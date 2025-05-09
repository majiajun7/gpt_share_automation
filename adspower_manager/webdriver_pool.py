import time
import threading
import queue
import logging
import json
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import platform
import os
import datetime
import pyotp
import uuid
import re  # Added for regex matching in helper methods

# 配置日志
logger = logging.getLogger(__name__)

# --- Constants ---
TARGET_DEVICE_PAGE = "https://app-global.adspower.net/personalSettings"
LOGIN_PAGE_URL = "https://app-global.adspower.net/login"
HEALTH_CHECK_URL = "https://app-global.adspower.net/"  # For basic login status check
INSTANCE_COUNT_PER_ACCOUNT = 3  # Target instances per account
MAX_FAIL_COUNT_CONFIG = 3  # Max retries for configuration/login
MAX_FAIL_COUNT_NAV = 3    # Max retries for navigation
MAX_FAIL_COUNT_INIT = 3   # Max retries for getting driver from pool
STUCK_IN_USE_TIMEOUT = 600  # Seconds before considering an instance stuck in 'in_use' state

# --- Instance States ---
STATE_INITIALIZING = "initializing"         # Trying to get raw driver from pool
STATE_NEEDS_CONFIG = "needs_config"         # Got raw driver, needs cookie load or login
STATE_CONFIGURING = "configuring"           # Actively loading cookies or logging in
STATE_NEEDS_NAVIGATION = "needs_navigation" # Logged in, needs navigation to target page
STATE_NAVIGATING = "navigating"             # Actively navigating and handling popups
STATE_READY = "ready"                       # Logged in, on target page, ready for use
STATE_IN_USE = "in_use"                     # Allocated for an API operation
STATE_UNHEALTHY = "unhealthy"               # Health check failed, needs replacement cycle
STATE_FAILED = "failed"                     # Non-recoverable failure, instance removed

# 添加账号专用WebDriver管理类
class AccountWebDriverManager:
    """
    为每个AdsPower账号维护一组（默认为2个）专用的、预热好的WebDriver实例。
    实例会尝试保持登录状态并停留在设备管理页面(/personalSettings)，随时准备处理API请求。
    """
    _instance = None
    _lock = threading.RLock()  # Main lock for singleton and critical sections

    @classmethod
    def get_instance(cls):
        """获取AccountWebDriverManager的单例实例"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = AccountWebDriverManager()
            return cls._instance

    def __init__(self, manage_interval=3):
        """初始化账号WebDriver管理器"""
        self.account_data = {}
        self._main_lock = threading.RLock()  # Protects the account_data dictionary itself
        self.running = False
        self.management_thread = None
        self.manage_interval = manage_interval  # How often the management thread runs its cycle

        logger.info(f"[Account Manager] 预热型账号WebDriver管理器已初始化 (管理间隔: {manage_interval}秒)")

    def start_management(self):
        """启动后台管理线程，开始监控和维护账号实例"""
        with self._lock:
            if self.running:
                logger.warning("[Account Manager] 管理线程已经在运行")
                return
            try:
                get_driver_pool()  # This will initialize the pool if needed
            except Exception as pool_init_e:
                logger.error(f"[Account Manager] 获取/初始化 WebDriverPool 失败，无法启动管理线程！错误: {pool_init_e}")
                return

            self.running = True
            self.management_thread = threading.Thread(
                target=self._manage_account_instances_loop, daemon=True
            )
            self.management_thread.start()
            logger.info(f"[Account Manager] 后台实例管理线程已启动 (检查间隔: {self.manage_interval}s)")

    def stop_management(self):
        """停止后台管理线程并清理所有资源"""
        with self._lock:
            if not self.running:
                logger.warning("[Account Manager] 管理线程已经停止")
                return
            logger.info("[Account Manager] 正在停止后台实例管理线程...")
            self.running = False

        if self.management_thread and self.management_thread.is_alive():
            try:
                logger.debug("[Account Manager] 正在等待管理线程退出...")
                self.management_thread.join(timeout=self.manage_interval + 5)
                if self.management_thread.is_alive():
                    logger.warning(
                        f"[Account Manager] 管理线程未能在超时 ({self.manage_interval + 5}s) 内正常停止"
                    )
                else:
                    logger.debug("[Account Manager] 管理线程未运行或已退出")
            except Exception as e:
                logger.error(f"[Account Manager] 等待管理线程停止时出错: {e}")

        logger.info("[Account Manager] 停止管理线程后，开始关闭所有账号的WebDriver实例...")
        self.close_all_drivers()
        logger.info("[Account Manager] 实例清理完成，管理器已停止")

    def add_managed_account(self, account_id, username, password, totp_secret, cookies):
        """
        注册一个需要主动管理实例的账号，或更新现有账号的凭据/Cookie。
        管理器将开始为此账号维护预热的实例。
        """
        account_id = str(account_id)
        log_prefix = f"[Account Manager Add/Update] 账号 {username} (ID: {account_id})"

        with self._main_lock:
            if account_id not in self.account_data:
                logger.info(f"{log_prefix} 已添加到管理器，将开始准备实例")
                self.account_data[account_id] = {
                    'instances': [],
                    'lock': threading.RLock(),
                    'email': username,
                    'credentials': {
                        'username': username,
                        'password': password,
                        'totp_secret': totp_secret
                    },
                    'cookies': cookies,
                    'next_driver_index': 0,
                    'is_managing': False
                }
            else:
                logger.info(f"{log_prefix} 已存在，检查并更新凭据和Cookie...")
                with self.account_data[account_id]['lock']:
                    account_info = self.account_data[account_id]
                    account_info['email'] = username
                    account_info['credentials'] = {
                        'username': username,
                        'password': password,
                        'totp_secret': totp_secret
                    }
                    if cookies is not None and account_info['cookies'] != cookies:
                        logger.info(f"{log_prefix} Cookie已更新，现有实例将重新配置")
                        account_info['cookies'] = cookies
                        for inst in account_info['instances']:
                            if inst['state'] in [
                                STATE_READY, STATE_NEEDS_NAVIGATION, STATE_NAVIGATING
                            ]:
                                logger.debug(
                                    f"{log_prefix} 实例 {inst['instance_id']} 状态 {inst['state']} -> NEEDS_CONFIG (因Cookie更新)"
                                )
                                # Pass username as account_email here
                                self._update_instance_state(
                                    inst, STATE_NEEDS_CONFIG, "凭据或Cookie已更新", username
                                )
                    else:
                        logger.debug(f"{log_prefix} 凭据已更新，但Cookie无变化或未提供新的Cookie")

    def remove_managed_account(self, account_id):
        """停止管理指定账号并关闭其所有当前实例"""
        account_id = str(account_id)
        account_info = None
        account_email = "未知邮箱"

        with self._main_lock:
            if account_id in self.account_data:
                account_info = self.account_data.pop(account_id)
                account_email = account_info.get('email', '未知邮箱') # Capture email before releasing lock
                log_prefix = f"[Account Manager Remove] 账号 {account_email} (ID: {account_id})"
                logger.info(f"{log_prefix} 已从管理器监控列表移除")
            else:
                log_prefix = f"[Account Manager Remove] 账号 ID: {account_id}"
                logger.warning(f"{log_prefix} 账号未在管理器中找到，无需移除")
                return

        if account_info:
            instances_to_close = []
            with account_info['lock']:
                instances_to_close = list(account_info['instances'])
                account_info['instances'] = []

            if instances_to_close:
                logger.info(
                    f"{log_prefix} 开始关闭该账号的 {len(instances_to_close)} 个残留实例..."
                )
                closed_count = 0
                for inst in instances_to_close:
                    instance_id = inst.get('instance_id', '未知')
                    try:
                        logger.debug(f"{log_prefix} 正在关闭实例 {instance_id}...")
                        # Pass the captured account_email
                        self._close_driver_instance(inst, account_email)
                        closed_count += 1
                    except Exception as e:
                        logger.error(f"{log_prefix} 关闭实例 {instance_id} 时出错: {e}")
                logger.info(
                    f"{log_prefix} 实例关闭完成 ({closed_count}/{len(instances_to_close)})"
                )
            else:
                logger.info(f"{log_prefix} 未找到需要关闭的关联实例")

    def _manage_account_instances_loop(self):
        """后台管理线程主循环，定期检查和维护所有已注册账号的实例"""
        logger.info("[Account Manager Thread] 管理循环已启动")

        # === RESTRUCTURED LOOP ===
        loop_count = 0
        while self.running:
            loop_count += 1
            cycle_start_time = time.time()
            logger.debug(f"[Account Manager Thread Loop #{loop_count}] 开始新一轮循环")
            account_tasks = [] # List of tuples: (account_id, account_info, account_lock, latest_cookies)
            cookies_to_update = {} # Dict: {account_id: new_cookies_str}

            # --- Phase 1: Acquire locks and gather data (briefly hold _main_lock) ---
            try:
                with self._main_lock:
                    managed_account_ids_snapshot = list(self.account_data.keys())
                    for account_id in managed_account_ids_snapshot:
                        if account_id in self.account_data: # Check if account still exists
                            account_info = self.account_data[account_id]
                            account_lock = account_info.get('lock')
                            # Try to acquire account lock non-blockingly WHILE holding main lock
                            # Also check the is_managing flag under main lock protection
                            if account_lock and not account_info.get('is_managing') and account_lock.acquire(blocking=False):
                                try:
                                    # Read cookies and mark as managing under lock
                                    latest_cookies = account_info.get('cookies')
                                    account_info['is_managing'] = True # Mark as managing
                                    account_tasks.append((account_id, account_info, account_lock, latest_cookies))
                                    logger.debug(f"[Account Manager Thread Loop #{loop_count}] 获取到账号 {account_id} 的锁和数据")
                                except Exception as inner_lock_err:
                                     logger.error(f"[Account Manager Thread Loop #{loop_count}] 标记账号 {account_id} 时出错: {inner_lock_err}", exc_info=True)
                                     # If marking failed, ensure lock is released
                                     account_lock.release() # Release account lock if marking failed
                            # else: Skip account if lock busy or managing flag set or lock doesn't exist
                logger.debug(f"[Account Manager Thread Loop #{loop_count}] 锁获取和数据收集完成，共准备处理 {len(account_tasks)} 个账号")
            except Exception as lock_gather_e:
                logger.error(f"[Account Manager Thread Loop #{loop_count}] 获取锁和数据阶段出错: {lock_gather_e}", exc_info=True)
                # Ensure any locks acquired in account_tasks are released if error occurred
                # This might be tricky if the error happened mid-loop. Releasing based on list might be incorrect.
                # Best effort: iterate tasks and release if owned.
                for _, _, lock, _ in account_tasks:
                    if lock and lock._is_owned():
                         try: lock.release()
                         except Exception: pass
                account_tasks = [] # Clear tasks to prevent processing potentially inconsistent state
            # --- _main_lock RELEASED --- 

            # --- Phase 2: Process accounts (hold only account_lock) ---
            processed_count = 0
            newly_obtained_cookies = {} # Store cookies obtained in this cycle {account_id: cookies_str}
            for account_id, account_info, account_lock, latest_cookies in account_tasks:
                if not self.running:
                    logger.debug(f"[Account Manager Thread Loop #{loop_count}] 在处理账号过程中检测到停止标志，退出循环")
                    # Ensure lock is released before breaking
                    try:
                         if account_lock._is_owned(): account_lock.release()
                    except Exception: pass
                    break

                new_cookies_for_account = None
                try:
                    logger.debug(f"[Account Manager Thread Loop #{loop_count}] 开始调用 _check_and_manage_single_account 处理账号 {account_id}")
                    # Pass the fetched latest_cookies. This function now returns new cookies if login occurred.
                    new_cookies_for_account = self._check_and_manage_single_account(account_id, account_info, account_lock, latest_cookies)
                    logger.debug(f"[Account Manager Thread Loop #{loop_count}] 完成对账号 {account_id} 的处理")
                    processed_count += 1
                    if new_cookies_for_account:
                         newly_obtained_cookies[account_id] = new_cookies_for_account
                except Exception as e:
                    account_email = account_info.get('email', '未知邮箱')
                    logger.error(f"[Account Manager Thread] 管理账号 {account_email} (ID: {account_id}) 时发生意外错误: {e}", exc_info=True)
                finally:
                    # Reset managing flag and release account_lock
                    try:
                         # Reset flag *before* releasing account lock (protected by it)
                         if account_info:
                             account_info['is_managing'] = False
                             logger.debug(f"[Account Manager Thread Loop #{loop_count}] 已重置账号 {account_id} 的 is_managing 标志")
                         # Release account lock
                         if account_lock._is_owned():
                             account_lock.release()
                             logger.debug(f"[Account Manager Thread Loop #{loop_count}] 已释放账号 {account_id} 的锁 (管理后)")
                    except Exception as final_release_err:
                         logger.error(f"[Account Manager Thread Loop #{loop_count}] 释放账号 {account_id} 锁或重置标志时出错: {final_release_err}", exc_info=True)

            # --- End of Processing Phase --- 
            logger.debug(f"[Account Manager Thread Loop #{loop_count}] 账号处理阶段完成，处理了 {processed_count} 个账号")

            # --- Phase 3: Write back updated cookies (briefly hold _main_lock) ---
            if newly_obtained_cookies:
                logger.debug(f"[Account Manager Thread Loop #{loop_count}] 检测到 {len(newly_obtained_cookies)} 个账号需要更新Cookie，开始回写...")
                try:
                    with self._main_lock:
                        for account_id, cookies_str in newly_obtained_cookies.items():
                            if account_id in self.account_data:
                                 # Compare with current cookies under lock to avoid unnecessary writes?
                                 # Or just write the latest obtained ones.
                                 self.account_data[account_id]['cookies'] = cookies_str
                                 account_email = self.account_data[account_id].get('email', '未知邮箱')
                                 logger.info(f"[Account Manager Thread Loop #{loop_count}] 已更新账号 {account_email} (ID: {account_id}) 的内存Cookie缓存")
                            # else: Account might have been removed between phases
                except Exception as cookie_write_e:
                    logger.error(f"[Account Manager Thread Loop #{loop_count}] 回写Cookie时出错: {cookie_write_e}", exc_info=True)
            # --- _main_lock RELEASED --- 

            # --- Loop End: Calculate sleep time ---
            cycle_duration = time.time() - cycle_start_time
            logger.debug(f"[Account Manager Thread Loop #{loop_count}] 本轮循环总耗时 {cycle_duration:.3f}s")
            elapsed = cycle_duration
            sleep_time = max(0.1, self.manage_interval - elapsed)
            if self.running:
                # logger.debug(f"[Account Manager Thread Loop #{loop_count}] 休眠 {sleep_time:.3f}s 后继续")
                time.sleep(sleep_time)

        logger.info("[Account Manager Thread] 管理循环已退出")

    def _check_and_manage_single_account(self, account_id, account_info, account_lock, latest_cookies):
        """(Core Logic) 检查并管理单个账号的实例状态和数量.
        Assumes account_lock is already acquired.
        Returns: str | None - New cookies string if login occurred, otherwise None.
        """
        account_email = account_info.get('email', '未知邮箱')
        log_prefix = f"[Account Manager Check] 账号 {account_email} (ID: {account_id})"
        logger.debug(f"{log_prefix} 函数调用开始")
        # new_cookies_str_obtained = None # Initialize here to prevent UnboundLocalError
        # === 新增：追踪在本轮检查中获取的新Cookie ===
        new_cookies_str_obtained_in_this_run = None
        # ========================================

        try:
            instances = account_info['instances']
            credentials = account_info['credentials']
            # Get email early is already done by caller passing account_email
            # account_email = account_info.get('email', '未知邮箱') # Redundant

            # 1. Prune dead/failed instances
            initial_instance_count = len(instances)
            logger.debug(f"{log_prefix} 准备清理失效/失败实例，初始实例数: {initial_instance_count}")
            instances_to_remove_indices = []
            for i, inst in enumerate(instances):
                if inst['state'] == STATE_FAILED:
                    logger.info(f"{log_prefix} 将要移除失败的实例: {inst['instance_id']} (状态: {inst['state']})")
                    try:
                        # Pass the account_email for closing
                        self._close_driver_instance(inst, account_email)
                    except Exception as close_err:
                        logger.error(f"{log_prefix} 清理实例 {inst['instance_id']} 时出错: {close_err}")
                    instances_to_remove_indices.append(i)

            if instances_to_remove_indices:
                for i in sorted(instances_to_remove_indices, reverse=True):
                    removed_inst = instances.pop(i)
                    logger.debug(f"{log_prefix} 已从实例列表移除: {removed_inst['instance_id']}")
                logger.info(
                    f"{log_prefix} 已清理 {len(instances_to_remove_indices)} 个失效/失败实例 (之前: {initial_instance_count}, 现在: {len(instances)})"
                )
            else:
                logger.debug(f"{log_prefix} 未发现需要移除的实例，清理完成。当前实例数: {len(instances)}")

            # 打印当前状态
            logger.debug(f"{log_prefix} 清理后实例状态: {[inst['instance_id'] + ':' + inst.get('state', 'UnknownState') for inst in instances]}")

            # 强制保持 <= INSTANCE_COUNT_PER_ACCOUNT
            overflow = len(instances) - INSTANCE_COUNT_PER_ACCOUNT
            logger.debug(f"{log_prefix} 检查是否超出目标上限，当前数量 {len(instances)}, 目标 {INSTANCE_COUNT_PER_ACCOUNT}, 超出 {overflow}")
            if overflow > 0:
                logger.warning(f"{log_prefix} 实例数量 {len(instances)} 超过上限 {INSTANCE_COUNT_PER_ACCOUNT}，需裁剪多余 {overflow} 个")

                removable_candidates = [
                    inst for inst in instances
                    if inst['state'] not in (STATE_READY, STATE_IN_USE)
                ]

                instances_to_remove = []
                take_from_candidates = min(len(removable_candidates), overflow)
                instances_to_remove.extend(removable_candidates[:take_from_candidates])
                remaining_overflow = overflow - take_from_candidates

                if remaining_overflow > 0:
                    remaining_instances = [inst for inst in instances if inst not in instances_to_remove]
                    sorted_remaining = sorted(
                        remaining_instances, key=lambda x: x.get('last_state_change', 0)
                    )
                    instances_to_remove.extend(sorted_remaining[:remaining_overflow])

                for inst_to_remove in instances_to_remove:
                    instance_id_to_remove_str = inst_to_remove.get('instance_id', '未知')
                    try:
                        logger.info(f"{log_prefix} 裁剪实例 {instance_id_to_remove_str} (状态: {inst_to_remove.get('state')})")
                        self._close_driver_instance(inst_to_remove)
                        original_list_len = len(instances)
                        instances[:] = [inst for inst in instances if inst is not inst_to_remove]
                        if len(instances) == original_list_len - 1:
                            logger.info(f"{log_prefix} 已成功移除多余实例 {instance_id_to_remove_str}")
                        else:
                            logger.warning(f"{log_prefix} 从列表移除实例 {instance_id_to_remove_str} 时，实例数未如预期减少")
                    except Exception as prune_overflow_err:
                        logger.error(f"{log_prefix} 裁剪实例 {instance_id_to_remove_str} 时出错: {prune_overflow_err}")
                logger.info(f"{log_prefix} 裁剪完成，当前实例数量: {len(instances)}")

            logger.debug(f"{log_prefix} 强制保持实例数量完成。当前 {len(instances)}, 目标 {INSTANCE_COUNT_PER_ACCOUNT}")

            # 2. Ensure target number of instance placeholders exist
            current_total_count = len(instances)
            logger.debug(f"{log_prefix} 占位检查：当前总数={current_total_count}, 目标={INSTANCE_COUNT_PER_ACCOUNT}")
            needed_now = max(0, INSTANCE_COUNT_PER_ACCOUNT - current_total_count)

            if needed_now > 0:
                logger.info(f"{log_prefix} 实例数量({current_total_count})不足目标({INSTANCE_COUNT_PER_ACCOUNT})，需要增加 {needed_now} 个占位实例")
                initial_add_count = len(instances)
                for _ in range(needed_now):
                    if len(instances) >= INSTANCE_COUNT_PER_ACCOUNT:
                        logger.warning(f"{log_prefix} 添加过程中已达到目标数量，提前结束")
                        break
                    new_instance_id = f"inst_{account_id}_{uuid.uuid4().hex[:8]}"
                    new_inst = {
                        'driver': None,
                        'pool_driver_id': None,
                        'instance_id': new_instance_id,
                        'state': STATE_INITIALIZING,
                        'last_state_change': time.time(),
                        'last_check_time': 0,
                        'fail_count': 0,
                        'error_message': None
                    }
                    instances.append(new_inst)
                    logger.info(f"{log_prefix} 已添加新的占位实例: {new_instance_id}")
                logger.info(f"{log_prefix} 已完成添加 {needed_now} 个占位实例，之前: {initial_add_count}, 现在: {len(instances)}")
            else:
                logger.debug(f"{log_prefix} 实例数量({current_total_count})已满足或超过目标，不需要添加占位实例")

            # 3. Process each instance according to its state machine
            logger.debug(f"{log_prefix} 开始处理 {len(instances)} 个实例")
            logger.debug(f"{log_prefix} 当前实例状态: {[inst['instance_id'] + ':' + inst.get('state', 'UnknownState') for inst in instances]}")
            pool = get_driver_pool()
            for inst in instances:
                if not self.running:
                    break

                instance_id = inst['instance_id']
                current_state = inst['state']
                now = time.time()
                inst_log_prefix = f"{log_prefix} Inst: {instance_id}"

                try:
                    if current_state == STATE_INITIALIZING:
                        logger.debug(f"{inst_log_prefix} 状态: {current_state}，尝试从池中获取驱动...")
                        pool_id, driver = pool.get_driver(timeout=10)
                        if driver and pool_id:
                            inst['driver'] = driver
                            inst['pool_driver_id'] = pool_id
                            inst['fail_count'] = 0
                            logger.info(f"{inst_log_prefix} 已成功从池 {pool_id} 获取原始WebDriver")
                            # Pass account_email
                            self._update_instance_state(inst, STATE_NEEDS_CONFIG, "已获取原始驱动", account_email)
                        else:
                            inst['fail_count'] += 1
                            logger.warning(f"{inst_log_prefix} 无法从池获取驱动 (尝试次数: {inst['fail_count']}/{MAX_FAIL_COUNT_INIT})")
                            if inst['fail_count'] >= MAX_FAIL_COUNT_INIT:
                                # Pass account_email
                                self._update_instance_state(
                                    inst,
                                    STATE_FAILED,
                                    f"多次尝试从池获取驱动失败({inst['fail_count']}次)",
                                    account_email
                                )

                    elif current_state == STATE_NEEDS_CONFIG:
                        logger.debug(f"{inst_log_prefix} 状态: {current_state}，开始配置/登录")
                        # Pass account_email
                        self._update_instance_state(inst, STATE_CONFIGURING, "开始配置", account_email)

                        # === 优化点：优先使用本轮检查中获取的新Cookie ===
                        cookies_to_try = new_cookies_str_obtained_in_this_run if new_cookies_str_obtained_in_this_run else latest_cookies
                        if new_cookies_str_obtained_in_this_run:
                            logger.info(f"{inst_log_prefix} 检测到本轮检查中已有新Cookie，将尝试使用它进行配置")
                        # ===========================================

                        # 调用 _configure_driver_login 时传递 cookies_to_try
                        # config_success is now a tuple: (bool, new_cookies_str | None)
                        login_result = self._configure_driver_login(
                            account_id, inst, credentials, account_email, cookies_to_try # 使用 cookies_to_try
                        )
                        config_success = login_result[0]
                        new_cookies_str = login_result[1] # 这个实例登录后获取的新Cookie(如果有)

                        if config_success:
                            # Pass account_email
                            self._update_instance_state(inst, STATE_NEEDS_NAVIGATION, "配置/登录成功", account_email)
                            if new_cookies_str:
                                # === 优化点：记录本实例获取的新Cookie，供后续实例使用 ===
                                new_cookies_str_obtained_in_this_run = new_cookies_str
                                logger.info(f"{inst_log_prefix} 登录成功并获取了新的Cookie。本轮后续实例将优先使用此Cookie。")
                                # ==================================================
                        else:
                            inst['fail_count'] += 1
                            logger.warning(f"{inst_log_prefix} 配置/登录失败 (尝试次数: {inst['fail_count']}/{MAX_FAIL_COUNT_CONFIG})")
                            # Pass account_email to _close_driver_instance
                            self._close_driver_instance(inst, account_email)
                            if inst['fail_count'] >= MAX_FAIL_COUNT_CONFIG:
                                logger.error(f"{inst_log_prefix} 配置/登录失败次数已达上限({inst['fail_count']}次)，将回退到INITIALIZING重新获取驱动: {inst['error_message']}")
                                # Pass account_email
                                self._update_instance_state(
                                    inst,
                                    STATE_INITIALIZING,
                                    f"多次配置失败({inst['fail_count']}次)，准备重新开始",
                                    account_email
                                )
                            else:
                                # Pass account_email
                                self._update_instance_state(
                                    inst,
                                    STATE_INITIALIZING,
                                    f"配置失败，重试({inst['fail_count']})",
                                    account_email
                                )

                    elif current_state == STATE_NEEDS_NAVIGATION:
                        logger.debug(f"{inst_log_prefix} 状态: {current_state}，开始导航到目标页面")
                        # Pass account_email
                        self._update_instance_state(inst, STATE_NAVIGATING, "开始导航", account_email)
                        # Pass account_email
                        nav_success = self._navigate_and_ready_instance(account_id, inst, account_email)
                        if nav_success:
                            # Pass account_email
                            self._update_instance_state(inst, STATE_READY, "导航成功，实例可用", account_email)
                        else:
                            inst['fail_count'] += 1
                            logger.warning(f"{inst_log_prefix} 导航失败 (尝试次数: {inst['fail_count']}/{MAX_FAIL_COUNT_NAV})")
                            # Pass account_email
                            self._close_driver_instance(inst, account_email)
                            if inst['fail_count'] >= MAX_FAIL_COUNT_NAV:
                                # Pass account_email
                                self._update_instance_state(
                                    inst,
                                    STATE_FAILED,
                                    f"多次导航失败({inst['fail_count']}次): {inst['error_message']}",
                                    account_email
                                )
                            else:
                                # Pass account_email
                                self._update_instance_state(
                                    inst,
                                    STATE_INITIALIZING,
                                    f"导航失败，重试({inst['fail_count']})",
                                    account_email
                                )

                    elif current_state == STATE_READY:
                        check_frequency = self.manage_interval * 4
                        if now - inst.get('last_check_time', 0) > check_frequency:
                            logger.debug(f"{inst_log_prefix} 状态: {current_state}，进行周期性健康检查...")
                            # Pass account_email
                            if not self._check_instance_health(account_id, inst, account_email):
                                logger.warning(f"{inst_log_prefix} READY状态的实例健康检查未通过")
                            else:
                                inst['last_check_time'] = now

                    elif current_state == STATE_IN_USE:
                        time_in_use = now - inst['last_state_change']
                        if time_in_use > STUCK_IN_USE_TIMEOUT:
                            logger.warning(
                                f"{inst_log_prefix} 实例已在 InUse 状态下运行了 {time_in_use:.0f} 秒 (超过 {STUCK_IN_USE_TIMEOUT}s)，可能存在泄漏！标记为不健康"
                            )
                            # Pass account_email
                            self._update_instance_state(
                                inst,
                                STATE_UNHEALTHY,
                                f"InUse 状态超过 {STUCK_IN_USE_TIMEOUT} 秒",
                                account_email
                            )

                    elif current_state == STATE_UNHEALTHY:
                        logger.warning(f"{inst_log_prefix} 状态: {current_state}，即将替换不健康实例")
                        # Pass account_email
                        self._close_driver_instance(inst, account_email)
                        # Pass account_email
                        self._update_instance_state(inst, STATE_INITIALIZING, "替换不健康实例", account_email)

                except Exception as inst_proc_e:
                    logger.error(f"{inst_log_prefix} 在处理实例(状态: {current_state})时发生内部错误: {inst_proc_e}", exc_info=True)
                    try:
                        self._save_error_screenshot(
                            inst.get('driver'),
                            account_id,
                            instance_id,
                            f"state_processing_error_{current_state}"
                        )
                        # Pass account_email
                        self._update_instance_state(
                            inst,
                            STATE_UNHEALTHY,
                            f"在状态 {current_state} 处理时出现错误: {inst_proc_e}",
                            account_email
                        )
                    except Exception as recovery_err:
                        logger.error(f"{inst_log_prefix} 在错误处理过程中再次遇到异常: {recovery_err}")

            logger.debug(f"{log_prefix} 完成实例处理流程")

        except Exception as outer_e:
            logger.error(f"{log_prefix} 在主要管理逻辑中出现异常: {outer_e}", exc_info=True)
        finally:
            logger.debug(f"{log_prefix} 函数 finally 块结束，锁释放由上层调用负责")
            # Return collected cookies string (or None)
            # === 优化点：返回本轮检查中最后获取到的新Cookie（如果发生过登录） ===
            # return new_cookies_str_obtained
            return new_cookies_str_obtained_in_this_run
            # ======================================================

    def _update_instance_state(self, instance_info, new_state, message=None, account_email=None):
        """(内部辅助方法) 更新实例状态，记录日志，并重置失败计数器"""
        old_state = instance_info.get('state')
        if old_state == new_state:
            return

        instance_id = instance_info['instance_id']
        # 不再通过 _get_account_email 获取，直接使用传入的参数
        email = account_email or "未知邮箱" # Use provided email or fallback
        account_id_match = re.match(r"inst_(\w+)_", instance_id)
        account_id_for_log = account_id_match.group(1) if account_id_match else "unknown_acc"

        # Use the provided/fallback email for logging
        log_prefix = f"[Account Manager State] 账号 {email} (ID: {account_id_for_log}) Inst: {instance_id}"
        log_level = logging.INFO
        if new_state in [STATE_FAILED, STATE_UNHEALTHY]:
            log_level = logging.WARNING
        logger.log(
            log_level,
            f"{log_prefix} 状态改变: {old_state} -> {new_state}" + (f" (原因: {message})" if message else "")
        )

        instance_info['state'] = new_state
        instance_info['last_state_change'] = time.time()
        if new_state in [STATE_FAILED, STATE_UNHEALTHY]:
            instance_info['error_message'] = message
        if new_state in [
            STATE_NEEDS_CONFIG, STATE_NEEDS_NAVIGATION, STATE_READY, STATE_INITIALIZING
        ]:
            if instance_info.get('fail_count', 0) > 0:
                instance_info['fail_count'] = 0

    def _configure_driver_login(self, account_id, instance_info, credentials, account_email, latest_cookies):
        """(内部方法) 配置WebDriver实例：尝试加载Cookie，如果失败则尝试使用凭据登录。
        Returns: tuple (bool: success, str | None: new_cookies_str)
        """
        driver = instance_info.get('driver')
        instance_id = instance_info['instance_id']
        # 使用传入的 account_email
        log_prefix = f"[Account Manager Config] 账号 {account_email} (ID: {account_id}, Inst: {instance_id})"

        if not driver:
            instance_info['error_message'] = "配置时缺少 driver 对象"
            logger.error(f"{log_prefix} 配置失败：driver 对象不存在")
            return False, None

        try:
            # --- Use the passed latest_cookies --- 
            # REMOVED: Internal acquisition of latest_cookies using _main_lock
            # ------------------------------------------

            # 1. Try loading cookies first (using passed latest_cookies)
            if latest_cookies:
                logger.info(f"{log_prefix} 尝试加载传入的内存缓存 Cookie...")
                # Pass account_email
                load_success = self._load_cookies(account_id, instance_id, driver, latest_cookies, account_email)
                if load_success:
                    logger.info(f"{log_prefix} Cookie 加载完成后检查登录状态...")
                    time.sleep(1)
                    if self._check_login_status_basic(driver):
                        logger.info(f"{log_prefix} 最新缓存 Cookie 有效，已确认处于登录状态")
                        instance_info['error_message'] = None
                        return True, None # Success, no new cookies from login
                    else:
                        logger.warning(f"{log_prefix} 加载最新缓存 Cookie 后仍然未登录(或URL不正确)，将尝试使用凭据登录")
                else:
                    logger.warning(f"{log_prefix} 最新缓存 Cookie 加载失败或格式有问题，尝试使用凭据登录")
            else:
                logger.info(f"{log_prefix} 内存缓存中无有效Cookie，尝试使用凭据登录")

            # 2. Try login with credentials
            username = credentials.get('username')
            password = credentials.get('password')
            totp_secret = credentials.get('totp_secret')
            new_cookies_str = None

            if username and password and totp_secret:
                logger.info(f"{log_prefix} 尝试使用用户名和密码进行登录...")
                # 传递 account_email
                login_success, msg, new_cookies_list = self._perform_login(
                    driver, username, password, totp_secret, account_id, instance_id, account_email
                )
                if login_success:
                    logger.info(f"{log_prefix} 凭据登录成功")
                    instance_info['error_message'] = None
                    if new_cookies_list:
                        try:
                            # 获取新cookie的JSON字符串
                            new_cookies_str = json.dumps(new_cookies_list)
                            # --- REMOVED: Direct update of self.account_data here --- 
                            logger.info(f"{log_prefix} 登录成功，获取到新的Cookie数据")
                        except Exception as json_e:
                            logger.error(f"{log_prefix} 将新 Cookie 序列化为 JSON 失败: {json_e}")
                    return True, new_cookies_str # Return success and potentially new cookies string
                else:
                    logger.error(f"{log_prefix} 凭据登录失败: {msg}")
                    instance_info['error_message'] = f"登录失败: {msg}"
                    return False, None
            else:
                logger.error(f"{log_prefix} 无有效 Cookie，且缺少登录凭据，无法继续")
                instance_info['error_message'] = "缺少有效 Cookie 或凭据，配置失败"
                return False, None

        except WebDriverException as wd_e:
            logger.error(f"{log_prefix} 配置实例时出现 WebDriverException: {wd_e}", exc_info=False)
            instance_info['error_message'] = f"WebDriverException during config: {type(wd_e).__name__}"
            self._save_error_screenshot(driver, account_id, instance_id, "config_wd_error")
            return False, None
        except Exception as e:
            logger.error(f"{log_prefix} 配置实例时发生未知异常: {e}", exc_info=True)
            instance_info['error_message'] = f"配置时发生异常: {e}"
            self._save_error_screenshot(driver, account_id, instance_id, "config_exception")
            return False, None

    def _perform_login(self, driver, username, password, totp_secret, account_id, instance_id, account_email):
        """
        (内部方法) 在给定的driver实例上执行登录操作。
        Returns:
            tuple: (bool: success, str: message, list | None: new_cookies)
        """
        # 使用传入的 account_email (或 username 作为备用)
        log_prefix = f"[Account Manager Login] 账号 {account_email or username} (ID: {account_id}, Inst: {instance_id})"
        try:
            logger.debug(f"{log_prefix} 导航到登录页: {LOGIN_PAGE_URL}")
            driver.get(LOGIN_PAGE_URL)
            wait = WebDriverWait(driver, 25)
            
            # 等待页面加载完成
            logger.debug(f"{log_prefix} 等待登录页面加载...")
            try:
                # 等待页面上任何一个输入框可见，表示页面已加载
                input_selector = "input.el-input__inner"
                wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, input_selector)))
                logger.debug(f"{log_prefix} 登录页已加载")
            except TimeoutException:
                logger.error(f"{log_prefix} 登录页加载超时")
                self._save_error_screenshot(driver, account_id, instance_id, "login_page_timeout")
                return False, "登录页未能加载", None
            
            # 使用纯JavaScript执行登录操作
            js_login_script = """
            function performLogin(username, password) {
                // 查找用户名输入框
                const usernameInputs = Array.from(document.querySelectorAll('input.el-input__inner[type="text"][maxlength="50"]'));
                const usernameInput = usernameInputs.find(input => 
                    input.placeholder && (
                        input.placeholder.includes('邮箱') || 
                        input.placeholder.includes('手机') || 
                        input.placeholder.includes('Email')
                    )
                );
                
                if (!usernameInput) {
                    return { success: false, message: "未找到用户名输入框" };
                }
                
                // 查找密码输入框
                const passwordInput = document.querySelector('input.el-input__inner[type="password"][maxlength="50"]');
                if (!passwordInput) {
                    return { success: false, message: "未找到密码输入框" };
                }
                
                // 填充用户名和密码
                usernameInput.value = username;
                passwordInput.value = password;
                
                // 触发输入事件
                usernameInput.dispatchEvent(new Event('input', { bubbles: true }));
                passwordInput.dispatchEvent(new Event('input', { bubbles: true }));
                
                // 查找登录按钮 - 尝试多种选择器
                let loginButton = document.querySelector('button._login_btn_1wru3_100');
                
                if (!loginButton) {
                    loginButton = Array.from(document.querySelectorAll('button')).find(
                        button => (button.textContent.includes('登录') || button.textContent.includes('Login')) &&
                                 (button.className.includes('login') || button.className.includes('btnWrapper'))
                    );
                }
                
                if (!loginButton) {
                    return { success: false, message: "未找到登录按钮" };
                }
                
                // 点击登录按钮
                loginButton.click();
                return { success: true, message: "登录操作已执行" };
            }
            
            return performLogin(arguments[0], arguments[1]);
            """
            
            # 执行登录脚本
            login_result = driver.execute_script(js_login_script, username, password)
            
            if not login_result.get('success'):
                logger.error(f"{log_prefix} JavaScript登录失败: {login_result.get('message')}")
                self._save_error_screenshot(driver, account_id, instance_id, "js_login_failed")
                return False, login_result.get('message', "JavaScript登录失败"), None
            
            logger.debug(f"{log_prefix} JavaScript登录操作执行成功，等待登录后跳转或TOTP弹窗...")
            
            # 等待登录成功（URL变化）或TOTP弹窗出现
            totp_dialog_selector = "div.el-overlay-dialog .el-dialog.ads-dialog.account-verify"
            login_success_url_condition = lambda d: "login" not in d.current_url.lower()
            totp_dialog_visible_condition = EC.visibility_of_element_located((By.CSS_SELECTOR, totp_dialog_selector))
            
            try:
                WebDriverWait(driver, 15).until(
                    lambda d: login_success_url_condition(d) or totp_dialog_visible_condition(d)
                )
                logger.debug(f"{log_prefix} 等待结束，当前URL: {driver.current_url}")
            except TimeoutException:
                logger.error(f"{log_prefix} 等待登录跳转或TOTP弹窗超时(15s)")
                self._save_error_screenshot(driver, account_id, instance_id, "login_post_click_timeout")
                error_msg = self._get_login_error_message(driver) or "登录后未见跳转或TOTP弹窗，超时"
                return False, error_msg, None
            
            # 检查是否登录成功
            if login_success_url_condition(driver):
                logger.info(f"{log_prefix} 登录成功 (URL 未包含 'login')")
                new_cookies = driver.get_cookies()
                return True, "登录成功 (URL 改变)", new_cookies
            
            # 处理TOTP验证
            logger.info(f"{log_prefix} 检测到 TOTP 安全验证弹窗")
            
            # 生成TOTP验证码
            totp = pyotp.TOTP(totp_secret)
            verification_code = totp.now()
            logger.debug(f"{log_prefix} 生成 TOTP 验证码: {verification_code[:3]}...")
            
            # 使用JavaScript填充验证码并点击确认按钮
            js_totp_script = """
            function submitTOTP(code) {
                // 查找验证码输入框
                let verifyInput = document.querySelector('.el-dialog.account-verify input.el-input__inner[maxlength="6"][type="text"]');
                
                if (!verifyInput) {
                    // 更通用的选择器
                    verifyInput = document.querySelector('div.el-dialog input.el-input__inner[maxlength="6"][type="text"]');
                }
                
                if (!verifyInput) {
                    return { success: false, message: "未找到验证码输入框" };
                }
                
                // 填充验证码
                verifyInput.value = code;
                verifyInput.dispatchEvent(new Event('input', { bubbles: true }));
                
                // 查找确认按钮
                let confirmButton = document.querySelector('div.dialog-footer button._btnWrapper_q26e2_45');
                
                if (!confirmButton) {
                    confirmButton = Array.from(document.querySelectorAll('div.dialog-footer button')).find(
                        button => button.textContent.includes('确定') || button.textContent.includes('Confirm')
                    );
                }
                
                if (!confirmButton) {
                    return { success: false, message: "未找到确认按钮" };
                }
                
                // 点击确认按钮
                confirmButton.click();
                return { success: true, message: "验证码已提交" };
            }
            
            return submitTOTP(arguments[0]);
            """
            
            totp_result = driver.execute_script(js_totp_script, verification_code)
            
            if not totp_result.get('success'):
                logger.error(f"{log_prefix} 提交TOTP验证码失败: {totp_result.get('message')}")
                self._save_error_screenshot(driver, account_id, instance_id, "js_totp_failed")
                return False, totp_result.get('message', "JavaScript提交TOTP失败"), None
            
            # 等待TOTP验证后登录成功
            logger.debug(f"{log_prefix} 等待 TOTP 验证完成后跳转...")
            try:
                WebDriverWait(driver, 10).until(login_success_url_condition)
                logger.info(f"{log_prefix} 输入 TOTP 后成功登录 (URL: {driver.current_url})")
                new_cookies = driver.get_cookies()
                return True, "TOTP 登录成功", new_cookies
            except TimeoutException:
                logger.error(f"{log_prefix} 输入 TOTP 后等待登录跳转超时(10s)")
                self._save_error_screenshot(driver, account_id, instance_id, "login_totp_timeout")
                error_msg = self._get_login_error_message(driver) or "提交 TOTP 后超时"
                return False, error_msg, None
            
        except WebDriverException as wd_e:
            logger.error(f"{log_prefix} 登录时出现 WebDriverException: {wd_e}", exc_info=False)
            self._save_error_screenshot(driver, account_id, instance_id, "login_wd_error")
            return False, f"登录过程出现 WebDriverException: {type(wd_e).__name__}", None
        except Exception as e:
            logger.error(f"{log_prefix} 登录过程中出现未知异常: {e}", exc_info=True)
            self._save_error_screenshot(driver, account_id, instance_id, "login_exception")
            return False, f"登录过程中出现异常: {e}", None

    def _get_login_error_message(self, driver):
        """(内部辅助方法) 尝试从页面提取常见的登录错误提示"""
        if not driver:
            return None
        error_message = None
        try:
            # 更新错误消息选择器以适应新的HTML结构
            error_selectors = [
                ".el-message--error .el-message__content", 
                ".el-form-item__error",
                "div.el-notification__content",
                "div[class*='error-message']",
                "div[class*='error']"
            ]
            for selector in error_selectors:
                try:
                    error_elem = WebDriverWait(driver, 0.5).until(
                        EC.visibility_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    if error_elem and error_elem.text:
                        error_message = error_elem.text.strip()
                        logger.debug(f"从选择器 '{selector}' 获取到登录错误提示: {error_message}")
                        break
                except TimeoutException:
                    continue
        except Exception as e:
            logger.warning(f"获取登录错误信息时出现异常: {e}")
        return error_message

    def _navigate_and_ready_instance(self, account_id, instance_info, account_email):
        """(内部方法) 导航实例到目标页面 (/personalSettings) 并处理已知弹窗"""
        driver = instance_info.get('driver')
        instance_id = instance_info['instance_id']
        # 使用传入的 account_email
        log_prefix = f"[Account Manager Nav] 账号 {account_email} (ID: {account_id}, Inst: {instance_id})"

        if not driver:
            instance_info['error_message'] = "导航失败：未找到WebDriver对象"
            logger.error(f"{log_prefix} 无driver，无法导航")
            return False

        try:
            logger.info(f"{log_prefix} 导航至目标页面: {TARGET_DEVICE_PAGE}")
            driver.get(TARGET_DEVICE_PAGE)
            wait = WebDriverWait(driver, 25)

            # target_element_selector = "div._session_control_em8gz_75"
            target_element_selector = "div[class^='_session_control_']"
            try:
                wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, target_element_selector)))
                logger.info(f"{log_prefix} 目标页面核心元素 {target_element_selector} 已成功加载")
            except TimeoutException:
                logger.error(f"{log_prefix} 导航后等待元素 {target_element_selector} 超时")
                instance_info['error_message'] = f"等待目标页面元素 {target_element_selector} 超时"
                self._save_error_screenshot(driver, account_id, instance_id, "nav_target_timeout")
                return False

            current_url = driver.current_url
            if "login" in current_url.lower():
                logger.error(f"{log_prefix} 导航后意外跳转至登录页! 当前URL: {current_url}")
                instance_info['error_message'] = "导航时被重定向到登录页"
                self._save_error_screenshot(driver, account_id, instance_id, "nav_login_redirect")
                return False
            elif TARGET_DEVICE_PAGE not in current_url:
                logger.warning(f"{log_prefix} 导航后当前URL({current_url}) 与期望({TARGET_DEVICE_PAGE})不一致")

            logger.debug(f"{log_prefix} 检查是否存在新手引导弹窗...")
            # 传递 account_email
            self._try_skip_new_user_guide(driver, log_prefix, account_email)

            logger.debug(f"{log_prefix} 处理完弹窗后，再次确认页面状态...")
            final_url = driver.current_url
            if TARGET_DEVICE_PAGE not in final_url:
                logger.error(f"{log_prefix} 处理弹窗后最终URL({final_url})仍然不符目标页面!")
                instance_info['error_message'] = f"跳过弹窗后最终URL错误: {final_url}"
                self._save_error_screenshot(driver, account_id, instance_id, "nav_final_url_mismatch")
                return False

            try:
                driver.find_element(By.CSS_SELECTOR, target_element_selector)
                logger.info(f"{log_prefix} 导航成功，已确认目标页面元素存在")
                instance_info['error_message'] = None
                return True
            except NoSuchElementException:
                logger.error(f"{log_prefix} 最终URL正确，但未找到目标元素 {target_element_selector}")
                instance_info['error_message'] = f"目标元素 {target_element_selector} 缺失"
                self._save_error_screenshot(driver, account_id, instance_id, "nav_final_element_missing")
                return False

        except WebDriverException as wd_e:
            logger.error(f"{log_prefix} 导航时出现 WebDriverException: {wd_e}", exc_info=False)
            instance_info['error_message'] = f"导航过程 WebDriverException: {type(wd_e).__name__}"
            self._save_error_screenshot(driver, account_id, instance_id, "nav_wd_error")
            return False
        except Exception as e:
            logger.error(f"{log_prefix} 导航过程中出现未知异常: {e}", exc_info=True)
            instance_info['error_message'] = f"导航未知异常: {e}"
            self._save_error_screenshot(driver, account_id, instance_id, "nav_exception")
            return False

    def _check_instance_health(self, account_id, instance_info, account_email):
        """
        (内部方法) 对处于READY状态的实例执行健康检查。
        """
        driver = instance_info.get('driver')
        instance_id = instance_info['instance_id']
        # 使用传入的 account_email
        log_prefix = f"[Account Manager Health] 账号 {account_email} (ID: {account_id}, Inst: {instance_id})"

        if not driver or not self.is_valid_driver(driver):
            logger.warning(f"{log_prefix} 健康检查失败：WebDriver已无效")
            # 传递 account_email
            self._update_instance_state(instance_info, STATE_UNHEALTHY, "WebDriver无效", account_email)
            return False

        is_healthy = False
        failure_reason = "未知健康检查失败原因"
        try:
            current_url = driver.current_url
            if "login" in current_url.lower():
                logger.warning(f"{log_prefix} 健康检查失败：页面跳转至登录页 ({current_url})")
                failure_reason = "页面跳转至登录页"
            elif TARGET_DEVICE_PAGE not in current_url:
                logger.warning(f"{log_prefix} 健康检查失败：未停留在目标页面 ({current_url})")
                failure_reason = f"不在目标页面 ({current_url})"
            else:
                try:
                    # target_element_selector = "div._session_control_em8gz_75"
                    target_element_selector = "div[class^='_session_control_']" 
                    
                    driver.find_element(By.CSS_SELECTOR, target_element_selector)
                    is_healthy = True
                except NoSuchElementException:
                    logger.warning(f"{log_prefix} 健康检查失败：目标元素 {target_element_selector} 不存在 (URL: {current_url})")
                    failure_reason = f"目标元素 {target_element_selector} 缺失"
                except WebDriverException as find_wd_e:
                    logger.warning(f"{log_prefix} 健康检查时查找元素出现 WebDriverException: {find_wd_e}")
                    failure_reason = f"查找元素时出现WebDriverException: {type(find_wd_e).__name__}"

        except WebDriverException as wd_e:
            logger.error(f"{log_prefix} 健康检查时出现 WebDriverException: {wd_e}")
            failure_reason = f"WebDriverException: {type(wd_e).__name__}"
            is_healthy = False
        except Exception as e:
            logger.error(f"{log_prefix} 健康检查时出现未知错误: {e}", exc_info=True)
            failure_reason = f"健康检查时出现未知错误: {e}"
            is_healthy = False

        if not is_healthy:
            # 传递 account_email
            self._update_instance_state(instance_info, STATE_UNHEALTHY, f"健康检查失败: {failure_reason}", account_email)
            self._save_error_screenshot(driver, account_id, instance_id, "health_check_failed")

        return is_healthy

    def get_driver(self, account_id, timeout=30):
        """
        获取指定账号的一个 'Ready' 状态的 WebDriver 实例。
        遵循严格的锁顺序: _main_lock -> account_lock
        """
        account_id = str(account_id)
        requested_time = time.time()
        instance_to_return = None
        instance_id_to_return = None

        while True:
            # --- Loop Entry: Check Timeout FIRST ---
            if time.time() - requested_time > timeout:
                email_for_log = "未知邮箱"
                try:
                    # Briefly acquire main lock ONLY to get email for logging
                    with self._main_lock:
                        if account_id in self.account_data:
                            email_for_log = self.account_data[account_id].get('email', '未知邮箱')
                except Exception:
                    pass # Ignore errors in getting email for timeout log
                logger.error(f"[Account Manager Get] 账号 {email_for_log} (ID: {account_id}) 获取可用实例超时 (等待超过 {timeout}s)")
                raise TimeoutError(f"获取账号 {account_id} ({email_for_log}) 的可用WebDriver超时({timeout}s)")

            account_lock = None
            account_email = "未知邮箱"
            found_ready_instance = False

            # --- Acquire locks in STRICT ORDER: _main_lock -> account_lock ---
            # acquire _main_lock
            self._main_lock.acquire()
            try:
                if account_id not in self.account_data:
                    logger.error(f"[Account Manager Get] 请求了未管理或已被移除的账号 ID: {account_id}")
                    # Release main lock before raising
                    self._main_lock.release()
                    raise ValueError(f"账号 {account_id} 未被管理或在获取实例期间被移除。")

                account_info = self.account_data[account_id]
                account_lock = account_info['lock']
                account_email = account_info.get('email', '未知邮箱') # Get email under main lock

                # acquire account_lock (blocking)
                account_lock.acquire()
                # --- BOTH LOCKS HELD ---
                log_prefix = f"[Account Manager Get] 账号 {account_email} (ID: {account_id})"
                try:
                    instances = account_info['instances']
                    ready_instances = [
                        inst for inst in instances if inst.get('state') == STATE_READY
                    ]
                    all_instance_states = {
                        inst.get('instance_id'): inst.get('state') for inst in instances
                    }

                    if not ready_instances:
                        logger.debug(f"{log_prefix} 当前无 READY 状态实例。所有实例状态: {all_instance_states}")
                    else:
                        num_ready = len(ready_instances)
                        # Use modulo for safety, though num_ready should be > 0 here
                        start_index = account_info.get('next_driver_index', 0) % num_ready if num_ready > 0 else 0
                        selected_instance = None

                        for i in range(num_ready):
                            check_index = (start_index + i) % num_ready
                            candidate_instance = ready_instances[check_index]
                            candidate_id = candidate_instance['instance_id']

                            logger.debug(f"{log_prefix} 尝试分配 READY 实例: {candidate_id}")
                            selected_instance = candidate_instance
                            account_info['next_driver_index'] = (check_index + 1) % num_ready
                            break # Found one

                        if selected_instance:
                            # Modify instance state under account lock
                            self._update_instance_state(selected_instance, STATE_IN_USE, "分配给操作使用", account_email) # Pass email
                            instance_to_return = selected_instance.get('driver')
                            instance_id_to_return = selected_instance.get('instance_id')

                            # Validate instance integrity before returning
                            if not instance_to_return:
                                logger.error(f"{log_prefix} 严重错误: 实例 {instance_id_to_return} 状态为 IN_USE，但无 driver 对象！标记为 FAILED")
                                self._update_instance_state( # Pass email
                                    selected_instance, STATE_FAILED, "分配后发现 driver 对象缺失", account_email
                                )
                                instance_to_return = None
                                instance_id_to_return = None
                            elif not instance_id_to_return:
                                logger.error(f"{log_prefix} 严重错误: 实例 ID 丢失！标记为 FAILED")
                                self._update_instance_state( # Pass email
                                    selected_instance, STATE_FAILED, "分配后发现 instance_id 缺失", account_email
                                )
                                instance_to_return = None
                                instance_id_to_return = None
                            else:
                                logger.info(f"{log_prefix} 已分配实例 {instance_id_to_return}")
                                found_ready_instance = True # Mark success for loop exit

                finally:
                    # Release account_lock FIRST (inner lock)
                    account_lock.release()
                    # --- account_lock RELEASED ---

            finally:
                # Release _main_lock SECOND (outer lock)
                self._main_lock.release()
                # --- _main_lock RELEASED ---

            if found_ready_instance:
                return instance_to_return, instance_id_to_return

            # If no instance found, sleep before next iteration
            time.sleep(0.5)

        # Fallback (should not be reached normally due to timeout check)
        # logger.error(f"[Account Manager Get] 账号 {account_email} (ID: {account_id}) get_driver 出现意外退出循环的问题")
        # raise RuntimeError(f"get_driver({account_id}) 在循环外意外退出")

    def release_driver(self, account_id, instance_id, success=True):
        """
        释放指定账号的 WebDriver 实例回管理器。
        如果 success=False，实例会被标记为不健康。
        遵循严格的锁顺序: _main_lock -> account_lock
        """
        account_id = str(account_id)
        account_lock = None
        account_email = "未知邮箱"

        # --- Acquire locks in STRICT ORDER: _main_lock -> account_lock ---
        self._main_lock.acquire()
        try:
            if account_id not in self.account_data:
                logger.warning(f"[Account Manager Release] 尝试释放一个未被管理的账号实例 (ID: {account_id}), 实例ID: {instance_id}")
                return # Exit early (finally block will release main lock)

            account_info = self.account_data[account_id]
            account_lock = account_info['lock']
            account_email = account_info.get('email', '未知邮箱') # Get email under main lock

            # acquire account_lock (blocking)
            account_lock.acquire()
            # --- BOTH LOCKS HELD ---
            log_prefix = f"[Account Manager Release] 账号 {account_email} (ID: {account_id}) Inst: {instance_id}"
            try:
                target_instance = None
                # Access account_info['instances'] safely under account_lock
                for inst in account_info['instances']:
                    if inst.get('instance_id') == instance_id:
                        target_instance = inst
                        break

                if not target_instance:
                    logger.warning(f"{log_prefix} 未找到对应实例")
                    return # Exit (finally blocks will release locks)

                current_state = target_instance.get('state')
                if current_state != STATE_IN_USE:
                    logger.warning(f"{log_prefix} 释放一个非 InUse 状态的实例 (当前状态: {current_state})，可能是重复释放，忽略")
                    return # Exit (finally blocks will release locks)

                logger.info(f"{log_prefix} 开始释放实例 (本次操作成功: {success}")
                next_state = STATE_UNHEALTHY # Default to unhealthy
                message = "已释放"

                if success:
                    logger.debug(f"{log_prefix} 操作成功，进行释放后健康检查...")
                    # Pass email to health check (safe to call under locks, reads instance/driver state)
                    if self._check_instance_health(account_id, target_instance, account_email):
                        logger.debug(f"{log_prefix} 释放后健康检查通过")
                        next_state = STATE_READY
                        message = "成功释放且通过健康检查"
                        # --- 集中更新 Cookie 逻辑 --- #
                        try:
                            driver = target_instance.get('driver')
                            if driver and self.is_valid_driver(driver):
                                # 从当前有效的 driver 获取最新的 cookies
                                current_cookies = driver.get_cookies()
                                if current_cookies: 
                                    new_cookies_str = json.dumps(current_cookies)
                                    # 获取内存中的旧 cookies
                                    old_cookies_str = self.account_data[account_id].get('cookies')
                                    
                                    # 比较新旧 cookies，且新 cookie 不为空字符串
                                    if new_cookies_str and new_cookies_str != old_cookies_str:
                                        logger.info(f"{log_prefix} 实例状态为 READY，检测到 Cookie 发生变化，准备更新内存和数据库...")
                                        # 1. 更新内存缓存
                                        self.account_data[account_id]['cookies'] = new_cookies_str
                                        logger.debug(f"{log_prefix} 内存 Cookie 缓存已更新。")
                                        
                                        # 2. 更新数据库
                                        try:
                                            from .models import AdspowerAccount, db # 局部导入避免循环依赖
                                            account_obj = db.session.get(AdspowerAccount, account_id)
                                            if account_obj:
                                                account_obj.cookies = new_cookies_str
                                                account_obj.last_check_time = int(time.time())
                                                db.session.add(account_obj)
                                                db.session.commit()
                                                logger.info(f"{log_prefix} 数据库中的 Cookie 已成功更新。")
                                            else:
                                                logger.warning(f"{log_prefix} 未在数据库中找到账号 {account_id}，无法更新 Cookie。")
                                        except Exception as db_err:
                                            logger.error(f"{log_prefix} 更新数据库 Cookie 时出错: {db_err}", exc_info=True)
                                            try:
                                                db.session.rollback()
                                            except Exception as rb_err:
                                                logger.error(f"{log_prefix} Cookie 数据库更新回滚失败: {rb_err}")
                                    else:
                                        logger.debug(f"{log_prefix} 实例状态为 READY，Cookie 未发生变化，无需更新。")
                            else:
                                logger.warning(f"{log_prefix} 实例状态为 READY 但 driver 无效，无法获取或更新 Cookie。")
                        except Exception as cookie_e:
                            logger.error(f"{log_prefix} 释放实例并更新 Cookie 时发生错误: {cookie_e}", exc_info=True)
                        # --- Cookie 更新逻辑结束 ---
                    else:
                        logger.warning(f"{log_prefix} 虽然操作成功，但释放后健康检查失败")
                        # next_state remains UNHEALTHY
                        message = f"操作成功，但健康检查失败: {target_instance.get('error_message', '未知原因')}"
                else:
                    logger.warning(f"{log_prefix} 本次操作失败，将实例标记为不健康")
                    # next_state remains UNHEALTHY
                    message = "操作失败"
                    # _save_error_screenshot is safe (doesn't acquire locks)
                    self._save_error_screenshot(
                        target_instance.get('driver'), account_id, instance_id, "release_op_failed"
                    )

                # Pass email to update state (safe, modifies instance dict under account_lock)
                self._update_instance_state(target_instance, next_state, message, account_email)

                # Cookie update logic (safe, accesses driver and modifies main dict under both locks)
                # ---
                # 移除旧的 cookie 处理逻辑块
                # ---
                # if next_state == STATE_READY:
                #     try:
                #         driver = target_instance.get('driver')
                #         if driver and self.is_valid_driver(driver):
                #             try:
                #                 current_cookies = driver.get_cookies()
                #                 if current_cookies:
                #                     cookies_str = json.dumps(current_cookies)
                #                     # Update self.account_data under _main_lock (already held)
                #                     if account_id in self.account_data: # Re-check needed? No, main lock held.
                #                         old_cookies = self.account_data[account_id].get('cookies')
                #                         if cookies_str != old_cookies:
                #                             self.account_data[account_id]['cookies'] = cookies_str
                #                             logger.info(f"{log_prefix} 实例状态更改为READY，已更新内存中的cookie缓存")
                #                         else:
                #                             logger.debug(f"{log_prefix} 实例状态更改为READY，但cookie无变化")
                #             except Exception as cookie_e:
                #                 logger.error(f"{log_prefix} 获取或更新cookie时出错: {cookie_e}", exc_info=True)
                #     except Exception as e:
                #          logger.error(f"{log_prefix} 状态变更为READY后更新cookie缓存时出错: {e}", exc_info=True)
                # elif next_state == STATE_UNHEALTHY:
                #     logger.warning(f"{log_prefix} 因实例释放失败或健康检查失败 (状态: {next_state})，清除账号 {account_id} 的内存Cookie缓存")
                #     # Update self.account_data under _main_lock (already held)
                #     if account_id in self.account_data: # Re-check needed? No, main lock held.
                #          if self.account_data[account_id].get('cookies') is not None:
                #              self.account_data[account_id]['cookies'] = None
                #              logger.info(f"{log_prefix} 已清除账号 {account_id} 的内存Cookie缓存")
                #          else:
                #              logger.debug(f"{log_prefix} 账号 {account_id} 的内存Cookie缓存已是None，无需清除")

            finally:
                # Release account_lock FIRST (inner lock)
                account_lock.release()
                # --- account_lock RELEASED ---

        finally:
            # Release _main_lock SECOND (outer lock)
            self._main_lock.release()
            # --- _main_lock RELEASED ---

        # Add a comment about the lock order rule globally if not already present
        # (Assuming it might be added near the class definition or __init__)

    # 修改方法签名，添加 notify_pool 参数，默认为 True
    def _close_driver_instance(self, instance_info, account_email, notify_pool=True):
        """(内部辅助方法) 安全关闭WebDriver，并根据需要通知WebDriverPool释放底层资源。"""
        driver = instance_info.get('driver')
        pool_driver_id = instance_info.get('pool_driver_id')
        instance_id = instance_info.get('instance_id', '未知实例')
        account_id_match = re.match(r"inst_(\w+)_", instance_id)
        account_id_for_log = account_id_match.group(1) if account_id_match else "unknown_acc"
        # 使用传入的 account_email
        email = account_email or "未知邮箱"

        log_prefix = f"[Account Manager Close] 账号 {email} (ID: {account_id_for_log}) Inst: {instance_id}"

        if driver:
            logger.info(f"{log_prefix} 正在关闭 WebDriver...")
            try:
                driver.quit()
                logger.info(f"{log_prefix} WebDriver 已关闭")
            except WebDriverException as q_wd_e:
                logger.warning(f"{log_prefix} 关闭 WebDriver 时出现 WebDriverException（可能已关闭）: {q_wd_e}")
            except Exception as e:
                logger.warning(f"{log_prefix} 关闭 WebDriver 时出现错误: {e}")

        # 只有在 notify_pool 为 True 时才通知池
        if notify_pool and pool_driver_id:
            logger.info(f"{log_prefix} 正在将池ID {pool_driver_id} 归还给通用池 (请求清理和替换)...") # 可以修改日志消息
            try:
                pool = get_driver_pool()
                if pool:
                    pool.release_driver(pool_driver_id, None)
                    logger.info(f"{log_prefix} 已通知通用池处理池ID {pool_driver_id}")
                else:
                    logger.warning(f"{log_prefix} WebDriverPool 未初始化或已关闭，无法归还池ID {pool_driver_id}")
            except Exception as e:
                logger.error(f"{log_prefix} 归还池ID {pool_driver_id} 时出现错误: {e}")
        elif pool_driver_id: # 如果有 ID 但不需要通知
             logger.debug(f"{log_prefix} 实例关闭，但配置为不通知通用池 (通常在全局关闭期间)")
        else:
             logger.warning(f"{log_prefix} 未找到关联的 pool_driver_id，无法通知通用池释放资源")

    def close_all_drivers(self):
        """关闭所有当前管理的账号的所有WebDriver实例，并清空管理器状态"""
        logger.info("[Account Manager] 请求关闭所有管理中的WebDriver实例...")
        accounts_to_close = {} # Store {account_id: {'email': email, 'instances': [...]}}

        with self._main_lock:
            managed_account_ids = list(self.account_data.keys())
            logger.info(f"[Account Manager] 找到 {len(managed_account_ids)} 个账号，准备清理其实例...")
            for account_id in managed_account_ids:
                account_info = self.account_data.pop(account_id)
                if account_info:
                    with account_info['lock']:
                        accounts_to_close[account_id] = {
                            'email': account_info.get('email', '未知邮箱'),
                            'instances': list(account_info['instances'])
                        }
                        account_info['instances'] = [] # Clear instances inside lock
            # self.account_data.clear() # Already cleared by popping
            logger.info("[Account Manager] 所有账号数据已从管理器移除")

        # --- Now process the snapshot outside the main lock ---
        total_instances_closed = 0
        total_instances_found = 0

        for account_id, data in accounts_to_close.items():
            email_for_close = data['email']
            instances_to_close = data['instances']
            total_instances_found += len(instances_to_close)
            log_prefix = f"[Account Manager CloseAll] 账号 {email_for_close} (ID: {account_id})"
            logger.info(f"{log_prefix} 开始关闭该账号的 {len(instances_to_close)} 个实例...")

            for inst_data in instances_to_close:
                instance_id = inst_data.get('instance_id', '未知')
                try:
                    # 调用 _close_driver_instance 时，传递 notify_pool=False
                    self._close_driver_instance(inst_data, email_for_close, notify_pool=False)
                    total_instances_closed += 1
                except Exception as e:
                    logger.error(f"{log_prefix} 关闭实例 {instance_id} 时出现错误: {e}")

        logger.info(f"[Account Manager] 实例关闭完成 (成功关闭 {total_instances_closed}/{total_instances_found})")

    def is_valid_driver(self, driver):
        """(内部辅助方法) 检查WebDriver实例底层是否仍然连接和响应"""
        if not driver:
            return False
        try:
            _ = driver.window_handles
            _ = driver.current_url
            return True
        except WebDriverException:
            return False
        except Exception:
            return False

    def _check_login_status_basic(self, driver):
        """(内部辅助方法) 快速检查是否登录(通过URL不含'login'判定)"""
        if not driver or not self.is_valid_driver(driver):
            return False
        try:
            current_url = driver.current_url
            return "login" not in current_url.lower()
        except WebDriverException:
            return False
        except Exception:
            logger.warning("_check_login_status_basic: 获取URL时出现异常")
            return False

    def _load_cookies(self, account_id, instance_id, driver, cookies, account_email):
        """(内部辅助方法) 加载Cookie到给定的WebDriver实例，处理域和属性"""
        # 使用传入的 account_email
        log_prefix = f"[Account Manager Cookie] 账号 {account_email} (ID: {account_id}, Inst: {instance_id})"

        if not cookies or not driver or not self.is_valid_driver(driver):
            logger.warning(f"{log_prefix} 加载Cookie失败：缺少Cookie或Driver无效")
            return False

        cookies_to_load = None
        if isinstance(cookies, str):
            try:
                cookies_to_load = json.loads(cookies)
            except json.JSONDecodeError as json_e:
                logger.error(f"{log_prefix} Cookie JSON解析失败: {json_e}")
                return False
        elif isinstance(cookies, list):
            cookies_to_load = cookies
        else:
            logger.error(f"{log_prefix} Cookie 格式不正确，既不是JSON字符串也不是列表")
            return False

        if not isinstance(cookies_to_load, list):
            logger.error(f"{log_prefix} 解析后的Cookie格式不正确 (非列表)")
            return False

        try:
            initial_url = driver.current_url
            if ".adspower.net" not in initial_url:
                logger.debug(f"{log_prefix} 当前URL({initial_url})不在 .adspower.net 域，先导航到 {HEALTH_CHECK_URL} 以正确加载Cookie上下文")
                try:
                    driver.set_page_load_timeout(15)
                    driver.get(HEALTH_CHECK_URL)
                    WebDriverWait(driver, 10).until(
                        lambda d: d.execute_script('return document.readyState') == 'complete'
                    )
                    logger.debug(f"{log_prefix} 导航完成，当前URL: {driver.current_url}")
                except TimeoutException:
                    logger.warning(f"{log_prefix} 导航到 {HEALTH_CHECK_URL} 设置Cookie上下文超时，仍继续尝试")
                except Exception as nav_e:
                    logger.warning(f"{log_prefix} 导航到 {HEALTH_CHECK_URL} 时出现异常: {nav_e}")
                finally:
                    try:
                        driver.set_page_load_timeout(300)
                    except:
                        pass

            logger.debug(f"{log_prefix} 删除当前域所有Cookie...")
            driver.delete_all_cookies()
            logger.debug(f"{log_prefix} 已删除当前域的全部Cookie")

            success_count = 0
            total_count = len(cookies_to_load)
            problematic_keys = {'expires', 'expiry'}

            for cookie in cookies_to_load:
                if not isinstance(cookie, dict) or 'name' not in cookie or 'value' not in cookie:
                    logger.warning(f"{log_prefix} 无效Cookie项(缺少 name/value 或非 dict): {str(cookie)[:100]}...")
                    continue

                selenium_cookie = {}
                for key, value in cookie.items():
                    if key in problematic_keys:
                        continue
                    selenium_cookie[key] = value

                expiry_value = cookie.get('expiry', cookie.get('expires'))
                if expiry_value is not None:
                    try:
                        selenium_cookie['expiry'] = int(float(expiry_value))
                    except (ValueError, TypeError):
                        logger.warning(f"{log_prefix} 无法转换Cookie '{cookie['name']}' 的 expiry 值: {expiry_value}")

                if 'sameSite' in selenium_cookie and selenium_cookie['sameSite'] not in ['Strict', 'Lax', 'None']:
                    logger.warning(f"{log_prefix} sameSite 值无效: {selenium_cookie['sameSite']}，已移除")
                    selenium_cookie.pop('sameSite')

                try:
                    driver.add_cookie(selenium_cookie)
                    success_count += 1
                except Exception as add_cookie_e:
                    logger.warning(f"{log_prefix} 添加Cookie '{cookie.get('name')}' 时出错: {add_cookie_e}")

            logger.info(f"{log_prefix} 共加载 {success_count}/{total_count} 个Cookie")

            if success_count > 0:
                logger.debug(f"{log_prefix} 刷新页面以应用新Cookie...")
                try:
                    driver.set_page_load_timeout(20)
                    driver.refresh()
                    WebDriverWait(driver, 15).until(
                        lambda d: d.execute_script('return document.readyState') == 'complete'
                    )
                    logger.debug(f"{log_prefix} 刷新完成，当前URL: {driver.current_url}")
                except TimeoutException:
                    logger.warning(f"{log_prefix} 刷新页面以应用Cookie时超时")
                except WebDriverException as refresh_wd_e:
                    logger.warning(f"{log_prefix} 刷新页面时出现 WebDriverException: {refresh_wd_e}")
                except Exception as refresh_e:
                    logger.warning(f"{log_prefix} 刷新页面时出现异常: {refresh_e}")
                finally:
                    try:
                        driver.set_page_load_timeout(300)
                    except:
                        pass
            else:
                logger.warning(f"{log_prefix} 未能成功添加任何Cookie")

            return success_count > 0

        except WebDriverException as wd_e:
            logger.error(f"{log_prefix} 加载Cookie时出现 WebDriverException: {wd_e}", exc_info=False)
            return False
        except Exception as e:
            logger.error(f"{log_prefix} 加载Cookie时出现未知异常: {e}", exc_info=True)
            return False

    def _try_skip_new_user_guide(self, driver, log_prefix, account_email):
        """(内部辅助) 检测并跳过可能出现的新手引导"""
        # log_prefix already contains email info passed from caller (_navigate_and_ready_instance)
        if not driver:
            return
        try:
            guide_wrapper_selector = "div.guide-wrapper"
            skip_button_xpath = (
                ".//div[contains(@class, 'guide-btn')]//span[contains(text(), '跳过') or contains(text(), 'Skip')]"
            )

            guide_wrapper = WebDriverWait(driver, 3).until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, guide_wrapper_selector))
            )
            # 使用反斜杠转义内部的双引号
            logger.info(f"{log_prefix} 检测到新手引导，尝试点击\"跳过\"按钮")
            skip_button = WebDriverWait(guide_wrapper, 5).until(
                EC.element_to_be_clickable((By.XPATH, skip_button_xpath))
            )
            driver.execute_script("arguments[0].click();", skip_button)
            # 使用反斜杠转义内部的双引号
            logger.info(f"{log_prefix} 已点击新手引导的\"跳过\"按钮")
            time.sleep(1)
        except TimeoutException:
            logger.debug(f"{log_prefix} 未检测到新手引导 (或检测超时)")
        except Exception as guide_err:
            logger.warning(f"{log_prefix} 跳过新手引导时出现异常: {guide_err}")

    def _save_error_screenshot(self, driver, account_id, instance_id, context):
        """(内部辅助方法) 当出现错误时保存浏览器截图。"""
        # This function doesn't need email itself, relies on context from caller log
        if not driver or not self.is_valid_driver(driver):
            logger.warning(f"[Screenshot] Driver 无效，无法为 {account_id}/{instance_id} (Context: {context}) 保存截图")
            return
        try:
            screenshot_dir = "error_screenshots"
            if not os.path.exists(screenshot_dir):
                try:
                    os.makedirs(screenshot_dir)
                except OSError as e:
                    logger.error(f"[Screenshot] 无法创建截图目录: {e}")
                    return

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            safe_account_id = re.sub(r'[\\/*?:"<>|]', "_", str(account_id))
            safe_instance_id = re.sub(r'[\\/*?:"<>|]', "_", str(instance_id))
            safe_context = re.sub(r'[\\/*?:"<>|]', "_", str(context))

            filename = f"{safe_context}_{safe_account_id}_{safe_instance_id}_{timestamp}.png"
            filepath = os.path.join(screenshot_dir, filename)

            if driver.save_screenshot(filepath):
                logger.info(f"[Screenshot] 错误截图已保存: {filepath} (Context: {context})")
            else:
                logger.warning(f"[Screenshot] save_screenshot 返回False，未成功保存 (Context: {context})")

        except WebDriverException as screen_wd_e:
            logger.error(f"[Screenshot] 保存截图时出现 WebDriverException (浏览器可能已关闭): {screen_wd_e} (Context: {context})")
        except Exception as screen_e:
            logger.error(f"[Screenshot] 保存截图时出现异常: {screen_e} (Context: {context})", exc_info=True)

    def get_account_cookies(self, account_id):
        """获取指定账号当前缓存的Cookie字符串 (JSON格式)"""
        account_id = str(account_id)
        account_email = self._get_account_email(account_id)
        log_prefix = f"[Account Manager Get Cookies] 账号 {account_email} (ID: {account_id})"

        with self._main_lock:
            account_info = self.account_data.get(account_id)
            if account_info:
                cookies_str = account_info.get('cookies')
                return cookies_str or None
            else:
                return None

    def get_managed_account_ids(self):
        """获取当前所有被管理的账号ID集合"""
        with self._main_lock:
            return set(self.account_data.keys())

    def sync_cookies_to_database(self, app_context=None):
        """将所有账号的内存缓存cookies同步到数据库
        
        Args:
            app_context: Flask应用上下文，用于在后台线程中操作数据库
            
        Returns:
            int: 成功同步的账号数量
        """
        if app_context is None and threading.current_thread().name != 'MainThread':
            logger.warning("同步cookies需要在主线程或提供应用上下文")
            return 0
            
        accounts_synced = 0
        
        # 如果在后台线程且有应用上下文，使用它
        if app_context:
            with app_context():
                accounts_synced = self._do_sync_cookies_to_database()
        else:
            # 在主线程中直接执行
            accounts_synced = self._do_sync_cookies_to_database()
            
        return accounts_synced
        
    def _do_sync_cookies_to_database(self):
        """实际执行同步操作的内部方法
        
        Returns:
            int: 成功同步的账号数量
        """
        from adspower_manager.models import AdspowerAccount, db # Keep import local

        accounts_synced = 0
        account_data_snapshot = {}
        # --- Acquire lock briefly to copy data needed ---
        with self._main_lock:
            account_ids = list(self.account_data.keys())
            for acc_id in account_ids:
                 if acc_id in self.account_data: # Re-check after potential context switch
                      account_info = self.account_data[acc_id]
                      account_data_snapshot[acc_id] = {
                          'cookies': account_info.get('cookies'),
                          'email': account_info.get('email', '未知邮箱')
                      }
        # --- Lock released ---

        # Now iterate over the snapshot without holding the lock
        for account_id, data in account_data_snapshot.items():
            try:
                memory_cookies = data.get('cookies')
                account_email = data.get('email')

                if not memory_cookies:
                    logger.debug(f"[Cookie同步] 账号 {account_email} (ID: {account_id}) 在内存中没有cookies，跳过")
                    continue

                # 获取数据库中的账号对象 (DB access outside main lock)
                account_obj = AdspowerAccount.query.get(account_id)
                if not account_obj:
                    logger.warning(f"[Cookie同步] 账号ID {account_id} 在数据库中不存在，跳过")
                    continue

                # 比较cookies，如果不同则更新 (DB access outside main lock)
                if memory_cookies != account_obj.cookies: # <-- 比较新的 cookies 字段
                    logger.info(f"[Cookie同步] 账号 {account_email} (ID: {account_id}) 的cookies需要更新")
                    account_obj.cookies = memory_cookies # <-- 写入新的 cookies 字段
                    # account_obj.last_check_time = int(time.time()) # 考虑是否还需要更新这个时间戳
                    db.session.add(account_obj)
                    db.session.commit()
                    accounts_synced += 1
                    logger.info(f"[Cookie同步] 账号 {account_email} (ID: {account_id}) 的cookies已成功更新到数据库")
                else:
                    logger.debug(f"[Cookie同步] 账号 {account_email} (ID: {account_id}) 的cookies无变化，无需更新")
            except Exception as e:
                logger.error(f"[Cookie同步] 账号 {account_id} ({account_email}) cookies同步到数据库时出错: {e}", exc_info=True)
                try:
                    db.session.rollback()
                except:
                    pass

        return accounts_synced

    def _get_account_email(self, account_id):
        """(内部辅助方法) 根据 account_id 安全地获取 email """
        account_id = str(account_id)
        try:
            # This method only needs the _main_lock, which is fine.
            with self._main_lock:
                account_info = self.account_data.get(account_id)
                if account_info:
                    return account_info.get('email', '未知邮箱')
        except Exception as e:
            logger.warning(f"获取账号 {account_id} 的邮箱时出错: {e}")
        return "未知邮箱"


# --- Global Instance and Accessor Functions ---
_account_driver_manager = None
_manager_lock = threading.Lock()

def get_account_driver_manager():
    """
    获取全局 AccountWebDriverManager 实例 (线程安全)。
    如果尚未初始化，则创建实例。
    """
    global _account_driver_manager
    if _account_driver_manager is None:
        with _manager_lock:
            if _account_driver_manager is None:
                logger.info("正在初始化全局 AccountWebDriverManager 实例...")
                _account_driver_manager = AccountWebDriverManager.get_instance()
                logger.info("全局 AccountWebDriverManager 初始化完毕 (管理线程需要手动启动)")
    return _account_driver_manager

def start_account_manager():
    """显式启动 AccountWebDriverManager 的后台管理线程。"""
    manager = get_account_driver_manager()
    manager.start_management()

def stop_account_manager():
    """显式停止 AccountWebDriverManager 的管理线程并清理所有实例。"""
    global _account_driver_manager
    with _manager_lock:
        if _account_driver_manager:
            logger.info("请求关闭 AccountWebDriverManager...")
            try:
                # 设置超时机制，防止在stop_management()中长时间阻塞
                stop_thread = threading.Thread(target=lambda: _account_driver_manager.stop_management())
                stop_thread.daemon = True
                stop_thread.start()
                stop_thread.join(timeout=10.0)
                
                if stop_thread.is_alive():
                    logger.warning("AccountWebDriverManager.stop_management() 超过10秒未完成，强制清除实例引用")
            except Exception as e:
                logger.error(f"关闭 AccountWebDriverManager 时出现错误: {e}")
            
            # 无论上面过程是否正常完成，都清除引用
            _account_driver_manager = None
            logger.info("AccountWebDriverManager 已关闭")
        else:
            logger.info("AccountWebDriverManager 已关闭或未初始化，无需停止")

# --- WebDriverPool Class ---
class WebDriverPool:
    """WebDriver池管理类，用于管理原始的、未配置的WebDriver实例的生命周期"""

    def __init__(self, pool_size=5, driver_timeout=1800, check_interval=30, browser_type='chrome'):
        """初始化WebDriver池"""
        if pool_size < 1:
            pool_size = 1
        self.pool_size = pool_size
        self.driver_timeout = driver_timeout
        self.check_interval = check_interval
        self.browser_type = browser_type.lower()

        self.driver_queue = queue.Queue()
        self.driver_status = {}
        self.lock = threading.RLock()
        self.running = False
        self.manager_thread = None

        logger.info(
            f"[WebDriverPool] 初始化 WebDriver 池: 目标大小={pool_size}, 超时时间={driver_timeout}s, 检查间隔={check_interval}s"
        )

    def start(self):
        """启动WebDriver池管理器"""
        with self.lock:
            if self.running:
                logger.warning("[WebDriverPool] 池管理器已在运行中")
                return
            self.running = True

            logger.info("[WebDriverPool] 开始初始化池中实例...")
            self._initialize_pool()
            logger.info(f"[WebDriverPool] 初始化完成 (队列大小: {self.driver_queue.qsize()}, 追踪数: {len(self.driver_status)})")

            self.manager_thread = threading.Thread(target=self._manage_pool, daemon=True)
            self.manager_thread.start()
            logger.info("[WebDriverPool] 池管理线程已启动")

    def stop(self):
        """停止WebDriver池管理器，并清理所有资源"""
        with self.lock:
            if not self.running:
                logger.warning("[WebDriverPool] 池管理器已经停止")
                return
            logger.info("[WebDriverPool] 正在停止 WebDriver 池...")
            self.running = False

        if self.manager_thread and self.manager_thread.is_alive():
            try:
                logger.debug("[WebDriverPool] 等待池管理线程退出...")
                # 将等待时间从self.check_interval + 5减少到更短的时间，避免长时间阻塞
                self.manager_thread.join(timeout=min(5.0, self.check_interval))
                if self.manager_thread.is_alive():
                    logger.warning("[WebDriverPool] 池管理线程未能在超时时间内停止，继续关闭资源")
            except Exception as e:
                logger.error(f"[WebDriverPool] 等待池管理线程停止时出现错误: {e}")

        logger.info("[WebDriverPool] 开始清理所有池资源...")
        with self.lock:
            drained_count = 0
            while not self.driver_queue.empty():
                try:
                    driver_info = self.driver_queue.get_nowait()
                    driver_id = driver_info.get('id', '未知ID')
                    logger.debug(f"[WebDriverPool Stop] 关闭队列中的实例: {driver_id}")
                    self._close_driver(driver_info)
                    drained_count += 1
                except queue.Empty:
                    break
                except Exception as q_e:
                    logger.error(f"[WebDriverPool Stop] 关闭队列实例时出现错误: {q_e}")
            logger.info(f"[WebDriverPool Stop] 已从队列清理并关闭 {drained_count} 个实例")

            closed_status_count = 0
            tracked_ids = list(self.driver_status.keys())
            logger.info(f"[WebDriverPool Stop] 开始清理 driver_status 中的 {len(tracked_ids)} 条记录...")
            for driver_id in tracked_ids:
                driver_info = self.driver_status.pop(driver_id, None)
                if driver_info:
                    instance_type = "临时" if driver_info.get('is_temporary') else "池内"
                    in_use_status = "使用中" if driver_info.get('in_use') else "空闲"
                    logger.debug(f"[WebDriverPool Stop] 关闭 {instance_type} 实例: {driver_id} (状态: {in_use_status})")
                    self._close_driver(driver_info)
                    closed_status_count += 1
            logger.info(f"[WebDriverPool Stop] 已从 driver_status 清理并关闭 {closed_status_count} 个实例")
            self.driver_status.clear()

        logger.info("[WebDriverPool] WebDriver池管理器已停止")

    def get_driver(self, timeout=10):
        """
        从池中获取一个可用的原始WebDriver实例。
        返回 (driver_id, driver) 或 (None, None)
        """
        get_start_time = time.time()
        driver_id = None
        driver = None
        driver_info = None

        try:
            logger.debug(f"[WebDriverPool Get] 正在尝试从队列获取可用驱动 (等待超时: {timeout}s)")
            driver_info = self.driver_queue.get(block=True, timeout=timeout)
            driver_id = driver_info.get('id')
            driver = driver_info.get('driver')
            logger.debug(f"[WebDriverPool Get] 已成功从队列获取到驱动 {driver_id}")
        except queue.Empty:
            logger.warning(f"[WebDriverPool Get] 在队列中等待 {timeout}s 仍然为空")
            with self.lock:
                if len(self.driver_status) < self.pool_size:
                    logger.warning(f"[WebDriverPool Get] 当前池中数量({len(self.driver_status)})小于目标({self.pool_size})，尝试创建新驱动...")
                    try:
                        driver_id, driver = self._add_new_driver(mark_in_use=True)
                        if driver_id and driver:
                            logger.info(f"[WebDriverPool Get] 已创建新的备用驱动 {driver_id}")
                        else:
                            logger.error("[WebDriverPool Get] 创建新驱动失败")
                    except Exception as add_err:
                        logger.error(f"[WebDriverPool Get] 创建新驱动时出现错误: {add_err}", exc_info=True)
                        driver_id = None
                        driver = None
                else:
                    logger.error(f"[WebDriverPool Get] 队列超时且池大小({len(self.driver_status)})已达目标({self.pool_size})，无法提供更多驱动")
                    driver_id = None
                    driver = None
        except Exception as e:
            logger.exception("[WebDriverPool Get] 在队列获取驱动时出现意外错误")
            driver_id = None
            driver = None

        if driver_id and driver:
            with self.lock:
                if driver_id in self.driver_status:
                    self.driver_status[driver_id]['last_used'] = time.time()
                    self.driver_status[driver_id]['in_use'] = True
                    logger.info(f"[WebDriverPool Get] 返回驱动 {driver_id} 给调用方 (已标记为 in_use)")
                    return driver_id, driver
                else:
                    logger.error(f"[WebDriverPool Get] 严重错误: 在状态跟踪中找不到 {driver_id}，将关闭此驱动以防泄漏")
                    self._close_driver({'id': driver_id, 'driver': driver})
                    return None, None
        else:
            logger.warning(f"[WebDriverPool Get] 获取驱动失败，耗时 {time.time() - get_start_time:.2f}s")
            return None, None

    def release_driver(self, driver_id, driver):
        """
        将 WebDriver 实例释放回池中
        """
        if not driver_id and not driver:
            logger.warning("[WebDriverPool Release] 未提供 driver_id 或 driver 对象，无法释放")
            return

        with self.lock:
            if not driver_id and driver:
                found_id = None
                for d_id, status in self.driver_status.items():
                    if status.get('driver') == driver:
                        found_id = d_id
                        break
                if found_id:
                    driver_id = found_id
                    logger.debug(f"[WebDriverPool Release] 通过 driver 对象匹配找到实例ID: {driver_id}")
                else:
                    logger.warning("[WebDriverPool Release] 无法通过 driver 对象定位到已追踪的实例，直接关闭该driver")
                    self._close_driver({'id': 'unknown_released', 'driver': driver})
                    return

            if driver_id not in self.driver_status:
                logger.warning(f"[WebDriverPool Release] 未知的 driver_id: {driver_id}，如果 driver 存在则尝试关闭")
                if driver:
                    self._close_driver({'id': driver_id, 'driver': driver})
                return

            status = self.driver_status[driver_id]
            is_temporary = status.get('is_temporary', False)

            # 添加开始释放的日志
            logger.debug(f"[WebDriverPool Release] 开始处理实例 {driver_id} (Temporary: {is_temporary})")

            if is_temporary:
                logger.debug(f"[WebDriverPool Release] 关闭临时 WebDriver {driver_id}")
                if driver:
                    self._close_driver({'id': driver_id, 'driver': driver})
                self.driver_status.pop(driver_id, None)
                logger.debug(f"[WebDriverPool Release] 已从 driver_status 中移除临时实例 {driver_id}")
                return

            # ---- 新增逻辑：处理 driver is None 的情况 (表示被通知关闭并替换) ----
            if not driver:
                logger.debug(f"[WebDriverPool Release] 接到实例 {driver_id} 的关闭替换信号 (driver is None).")
                # 不需要再次调用 self._close_driver，因为实例应该已被外部关闭
                # 关键：从状态跟踪中移除
                if driver_id in self.driver_status:
                    self.driver_status.pop(driver_id, None)
                    logger.info(f"[WebDriverPool Release] 已从状态跟踪中移除实例 {driver_id} 的记录.")
                else:
                     logger.warning(f"[WebDriverPool Release] 尝试移除 {driver_id} 时，在 driver_status 中未找到记录.")
                # 关键：尝试创建替换实例
                logger.info(f"[WebDriverPool Release] 正在尝试创建新的 WebDriver 实例以替换 {driver_id}...")
                self._add_new_driver() # 这里会记录创建成功或失败
                return # 处理完毕，直接返回
            # ---- 结束新增逻辑 ----

            # ---- 原有逻辑：处理 driver 存在的情况 (正常释放回池) ----
            if not status.get('in_use', True):
                logger.warning(f"[WebDriverPool Release] 释放一个并未标记使用中的实例: {driver_id}，可能是重复释放")
                # 即使重复释放，也检查下健康状况，万一有问题呢？
                # 但通常可以直接返回
                return

            status['in_use'] = False
            status['last_used'] = time.time()

            should_close = False
            reason_for_close = "N/A" # 初始化关闭原因
            if driver:
                logger.debug(f"[WebDriverPool Release] 检查实例 {driver_id} 的健康状况和年龄...")
                if not self._check_driver_health(driver):
                    logger.warning(f"[WebDriverPool Release] 实例 {driver_id} 健康检查失败，准备关闭并替换")
                    should_close = True
                    reason_for_close = "Health Check Failed" # 记录关闭原因
                    status['failed_checks'] = status.get('failed_checks', 0) + 1
                elif status.get('created') and (time.time() - status['created']) > self.driver_timeout:
                    age = time.time() - status['created']
                    logger.info(f"[WebDriverPool Release] 实例 {driver_id} 已运行 {age:.0f}s，超过 {self.driver_timeout}s，准备关闭并替换")
                    should_close = True
                    reason_for_close = f"Timeout ({age:.0f}s > {self.driver_timeout}s)" # 记录关闭原因
                else:
                     logger.debug(f"[WebDriverPool Release] 实例 {driver_id} 健康检查通过且未超时")


            if should_close:
                # 添加明确关闭原因的日志
                logger.info(f"[WebDriverPool Release] 关闭实例 {driver_id}，原因: {reason_for_close}")
                if driver:
                    self._close_driver({'id': driver_id, 'driver': driver})
                self.driver_status.pop(driver_id, None)
                logger.debug(f"[WebDriverPool Release] 已移除并关闭 {driver_id}，现在尝试添加新实例进行替换")
                self._add_new_driver()
                logger.info(f"[WebDriverPool Release] {driver_id} 已被新实例替换")
            else:
                if driver:
                    logger.info(f"[WebDriverPool Release] 实例 {driver_id} 健康，重新放回队列 (释放后队列大小: {self.driver_queue.qsize()})")
                    self.driver_queue.put({'id': driver_id, 'driver': driver})
                    logger.debug(f"[WebDriverPool Release] {driver_id} 已进入可用队列，当前队列大小: {self.driver_queue.qsize()}")
                else:
                    logger.debug(f"[WebDriverPool Release] 实例 {driver_id} 状态已更新，但未提供driver对象，无法重新入队")

    def _initialize_pool(self):
        """(内部辅助) 初始化WebDriver池"""
        with self.lock:
            for _ in range(self.pool_size):
                self._add_new_driver()

    def _add_new_driver(self, mark_in_use=False):
        """(内部辅助) 创建新的WebDriver实例"""
        driver_id = f"pool_{self.browser_type}_{uuid.uuid4().hex[:10]}"
        # 添加更详细的日志
        log_prefix = f"[WebDriverPool Add] ID: {driver_id}"
        logger.info(f"{log_prefix} 尝试创建新的WebDriver实例... (mark_in_use={mark_in_use})")
        driver = self._create_driver()

        if driver:
            # 记录创建成功
            logger.info(f"{log_prefix} WebDriver 实例创建成功")
            with self.lock:
                self.driver_status[driver_id] = {
                    'driver': driver,
                    'created': time.time(),
                    'last_used': time.time(),
                    'in_use': mark_in_use,
                    'health_checks': 0,
                    'failed_checks': 0,
                    'is_temporary': False
                }
                logger.info(f"{log_prefix} 已创建并登记到状态追踪，mark_in_use={mark_in_use}")
                if not mark_in_use:
                    self.driver_queue.put({'id': driver_id, 'driver': driver})
                    logger.debug(f"{log_prefix} 已加入可用队列 (队列大小: {self.driver_queue.qsize()})")
            return driver_id, driver
        else:
            # 记录创建失败
            logger.error(f"{log_prefix} 创建 WebDriver 实例失败 (driver is None)")
            return None, None

    def _create_driver(self):
        """(内部辅助) 创建一个新的原始WebDriver (Chrome)"""
        # 添加开始创建日志
        logger.debug(f"[_create_driver] 开始创建新的 {self.browser_type} WebDriver 实例...")
        if self.browser_type != 'chrome':
            logger.error(f"[_create_driver] 不支持的浏览器类型: {self.browser_type}")
            return None

        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless') # <-- 添加无头模式参数
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-popup-blocking')
            chrome_options.add_argument('--lang=zh-CN')
            
            # 设置语言偏好
            chrome_prefs = {
                "intl.accept_languages": "zh-CN,zh;q=0.9",
                "profile.default_content_setting_values.notifications": 2
            }
            chrome_options.add_experimental_option("prefs", chrome_prefs)
            
            chrome_options.add_argument(
                '--user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"'
            )
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_experimental_option(
                'excludeSwitches', ['enable-logging', 'enable-automation']
            )
            chrome_options.add_experimental_option('useAutomationExtension', False)
            chrome_options.add_argument('--log-level=3')
            chrome_options.add_argument('--silent')

            # --- 添加日志：打印最终使用的 Chrome Options --- 
            logger.debug(f"[WebDriverPool Create] 使用的 Chrome 参数: {chrome_options.arguments}")
            # Optional: 也可以打印实验性选项，但可能较长
            # logger.debug(f"[WebDriverPool Create] 使用的 Chrome 实验性选项: {chrome_options.experimental_options}")
            # ----------------------------------------------

            script_dir = os.path.dirname(os.path.abspath(__file__))
            local_driver_path = os.path.join(script_dir, "drivers", "chromedriver")
            if platform.system() == "Windows":
                local_driver_path += ".exe"

            # 记录使用的驱动路径
            logger.debug(f"[_create_driver] 检查本地 ChromeDriver 路径: {local_driver_path}")

            driver = None
            if os.path.exists(local_driver_path):
                logger.info(f"[_create_driver] 尝试使用本地 ChromeDriver: {local_driver_path}")
                try:
                    service = Service(executable_path=local_driver_path)
                    driver = webdriver.Chrome(service=service, options=chrome_options)
                    logger.info("成功使用本地 ChromeDriver 创建 WebDriver")
                except Exception as e:
                    logger.warning(f"使用本地 ChromeDriver ({local_driver_path}) 失败: {e}", exc_info=True)
                    return None
            else:
                logger.error(f"[_create_driver] 本地 ChromeDriver 不存在于路径: {local_driver_path}")
                logger.error(f"[_create_driver] 请确保兼容版本的 ChromeDriver 存放于 adspower_manager/drivers/ 下")
                return None

            if driver:
                driver.set_page_load_timeout(60)
                driver.implicitly_wait(5)
                driver.execute_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
                )
                logger.debug("WebDriver 实例创建成功")
            return driver

        except WebDriverException as wd_e:
            logger.error(f"[_create_driver] 创建 WebDriver 时遇到 WebDriverException: {wd_e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"[_create_driver] 创建 WebDriver 时发生未知错误: {e}", exc_info=True)
            return None

    def _close_driver(self, driver_info):
        """(内部辅助) 安全关闭 WebDriver"""
        driver = driver_info.get('driver')
        driver_id = driver_info.get('id', 'unknown')
        # 添加关闭开始日志
        log_prefix = f"[WebDriverPool Close] ID: {driver_id}"
        logger.debug(f"{log_prefix} 开始关闭 WebDriver 实例...")
        if driver:
            try:
                driver.quit()
                # 添加关闭成功日志
                logger.info(f"{log_prefix} WebDriver 实例已成功关闭 (quit)")
            except WebDriverException as q_wd_e:
                logger.warning(f"[WebDriverPool Close] 关闭实例 {driver_id} 时出现 WebDriverException (可能已关闭): {q_wd_e}")
            except Exception as e:
                logger.error(f"[WebDriverPool Close] 关闭实例 {driver_id} 时出现错误: {e}")

    def _check_driver_health(self, driver):
        """(内部辅助) 检查原始 WebDriver 实例是否仍能正常工作"""
        if not driver:
            return False
        try:
            # 添加健康检查日志
            logger.debug(f"[_check_driver_health] 正在检查 Driver...")
            _ = driver.title
            _ = driver.current_url
            logger.debug(f"[_check_driver_health] Driver 健康检查通过")
            return True
        except WebDriverException as wd_ex:
            # 记录健康检查失败原因
            logger.warning(f"[_check_driver_health] Driver 健康检查失败 (WebDriverException): {wd_ex}")
            return False
        except Exception as e:
            logger.warning(f"[WebDriverPool Health] 健康检查出现异常: {e}")
            return False

    def _manage_pool(self):
        """(内部线程) 管理WebDriver池，定期检查实例健康、超时，并维持池大小"""
        logger.info("[WebDriverPool Manager Thread] 池管理线程已启动")
        loop_count = 0 # 添加循环计数器
        while self.running:
            loop_count += 1
            start_time = time.time()
            # 添加循环开始日志
            logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 开始管理周期...")
            try:
                # 使用非阻塞锁尝试获取锁，避免长时间等待
                logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 尝试获取锁...")
                if not self.lock.acquire(blocking=False):
                    logger.debug("[WebDriverPool Manager Thread Loop #{loop_count}] 无法获取锁，本轮跳过")
                    # 短暂睡眠后再次检查running状态
                    time.sleep(0.1)
                    continue
                
                # 获取锁成功
                logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 已获取锁")
                try:
                    if not self.running:
                        logger.info("[WebDriverPool Manager Thread Loop #{loop_count}] 检测到停止标志，退出循环")
                        break
                        
                    current_time = time.time()
                    all_driver_ids = list(self.driver_status.keys())
                    queue_size = self.driver_queue.qsize()
                    tracked_count = len(all_driver_ids)
                    in_use_count = sum(
                        1 for status in self.driver_status.values() if status.get('in_use')
                    )

                    ids_to_replace = []
                    for driver_id in all_driver_ids:
                        if not self.running:
                            break
                        status = self.driver_status.get(driver_id)
                        if not status:
                            continue
                        # 增加日志，检查是否被标记为 in_use，如果是，通常不应在这里处理超时
                        if status.get('in_use'):
                             logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 实例 {driver_id} 正在使用中，跳过超时检查")
                             continue

                        created_ts = status.get('created')
                        if created_ts and (current_time - created_ts) > self.driver_timeout:
                            age = current_time - created_ts
                            logger.info(f"[WebDriverPool Manager Thread Loop #{loop_count}] 实例 {driver_id} (Not In Use) 已超时 ({age:.0f}s > {self.driver_timeout}s)，标记替换")
                            ids_to_replace.append(driver_id)

                    if not self.running:
                        break

                    if ids_to_replace and self.running:
                        logger.info(f"[WebDriverPool Manager Thread Loop #{loop_count}] 准备替换 {len(ids_to_replace)} 个超时实例...")
                        replaced_count = 0 # 记录替换计数
                        for driver_id_to_replace in ids_to_replace:
                            if not self.running:
                                break
                            logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 正在替换实例 {driver_id_to_replace}...")
                            old_info = self.driver_status.pop(driver_id_to_replace, None)
                            if old_info:
                                self._close_driver(old_info)
                                if self.running:
                                    # 记录尝试添加新实例替换
                                    logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 调用 _add_new_driver 替换 {driver_id_to_replace}")
                                    _, new_driver = self._add_new_driver()
                                    if new_driver:
                                        replaced_count += 1
                            else:
                                logger.warning(f"[WebDriverPool Manager Thread Loop #{loop_count}] 尝试替换 {driver_id_to_replace} 时，在 driver_status 中未找到")
                        logger.info(f"[WebDriverPool Manager Thread Loop #{loop_count}] 超时实例替换完成 (成功替换: {replaced_count}/{len(ids_to_replace)})")

                    if not self.running:
                        break

                    current_pool_drivers = sum(
                        1 for status in self.driver_status.values() if not status.get('is_temporary')
                    )
                    needed = self.pool_size - current_pool_drivers
                    if needed > 0 and self.running:
                        logger.info(f"[WebDriverPool Manager Thread Loop #{loop_count}] 池中实例数量({current_pool_drivers})不足目标({self.pool_size})，需要补充 {needed} 个实例...")
                        added_count = 0 # 记录补充计数
                        for i in range(needed):
                            if not self.running:
                                break
                            logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 调用 _add_new_driver 进行补充 (第 {i+1}/{needed} 个)")
                            _, new_driver = self._add_new_driver()
                            if new_driver:
                                added_count += 1
                        logger.info(f"[WebDriverPool Manager Thread Loop #{loop_count}] 实例补充完成 (成功添加: {added_count}/{needed})")
                    else:
                        logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 当前实例数量 ({current_pool_drivers}) 已满足或超过目标 ({self.pool_size})，无需补充")

                finally:
                    # 添加释放锁的日志
                    logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 准备释放锁...")
                    self.lock.release()
                    logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 已释放锁")
            except Exception as e:
                logger.error(f"[WebDriverPool Manager Thread Loop #{loop_count}] 池管理线程循环中出现错误: {e}", exc_info=True)
                # 确保锁被释放
                if self.lock._is_owned():
                    self.lock.release()

            # 记录循环耗时和休眠时间
            elapsed = time.time() - start_time
            remaining_sleep = max(0.1, self.check_interval - elapsed)
            logger.debug(f"[WebDriverPool Manager Thread Loop #{loop_count}] 本轮循环耗时 {elapsed:.3f}s, 计划休眠 {remaining_sleep:.3f}s (Check Interval: {self.check_interval}s)")
            
            # 避免长时间睡眠，分段睡眠以便更快响应停止信号
            sleep_step = 0.5
            while remaining_sleep > 0 and self.running:
                sleep_time = min(sleep_step, remaining_sleep)
                time.sleep(sleep_time)
                remaining_sleep -= sleep_time
                # 如果接收到停止信号，立即退出睡眠
                if not self.running:
                    break

        logger.info("[WebDriverPool Manager Thread] 池管理线程已退出")


# --- Global Pool Instance and Accessors ---
global_driver_pool = None
_pool_lock = threading.Lock()

def init_driver_pool(pool_size=5, driver_timeout=1800, check_interval=300):
    """
    显式初始化全局 WebDriverPool (线程安全)。
    """
    global global_driver_pool
    if global_driver_pool is None:
        with _pool_lock:
            if global_driver_pool is None:
                logger.info("正在初始化全局 WebDriverPool...")
                global_driver_pool = WebDriverPool(
                    pool_size=pool_size,
                    driver_timeout=driver_timeout,
                    check_interval=check_interval
                )
                global_driver_pool.start()
                logger.info("全局 WebDriverPool 初始化并启动完成")

def get_driver_pool(create_if_none=False):
    """
    获取全局 WebDriverPool 实例。
    如果尚未初始化且 create_if_none=False，则返回 None。
    """
    global global_driver_pool
    if global_driver_pool is None and create_if_none is False:
        logger.debug("get_driver_pool 调用时，Pool 不存在且 create_if_none=False，返回 None")
        return None
    return global_driver_pool

def shutdown_driver_pool():
    """关闭全局 WebDriverPool 并清理资源。"""
    global global_driver_pool
    with _pool_lock:
        if global_driver_pool is not None:
            logger.info("请求关闭全局 WebDriverPool...")
            try:
                # 设置5秒超时，防止在pool.stop()中长时间阻塞
                stop_thread = threading.Thread(target=lambda: global_driver_pool.stop())
                stop_thread.daemon = True
                stop_thread.start()
                stop_thread.join(timeout=5.0)
                
                if stop_thread.is_alive():
                    logger.warning("WebDriverPool.stop() 超过5秒未完成，强制清除实例引用")
            except Exception as e:
                logger.error(f"关闭 WebDriverPool 时出现错误: {e}")
            
            # 无论上面过程是否正常完成，都清除引用
            global_driver_pool = None
            logger.info("全局 WebDriverPool 已关闭")
        else:
            logger.info("全局 WebDriverPool 已关闭或未初始化，无需操作")