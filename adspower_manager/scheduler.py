import threading
import logging
import json
# Use relative imports for services and models within the same package
from .services import SubscriptionService # Keep only necessary service imports
from .models import AdspowerAccount, db, Device, LoginSession, Subscription, User # 添加Subscription和User的导入
from .adspower_api import get_adspower_api
# Import necessary config from the root config.py
from config import CHECK_EXPIRATION_INTERVAL, ADSPOWER_REFRESH_INTERVAL as REFRESH_INTERVAL # Use alias for clarity
# Removed unused sqlalchemy imports for engine/sessionmaker
from .webdriver_pool import get_account_driver_manager # Keep only manager access
from flask import current_app # Keep current_app for flask context
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit
import time # Keep time for logging/timestamps if needed
from sqlalchemy import and_
from datetime import datetime, timedelta

# Configuration for logger
logger = logging.getLogger(__name__)

scheduler = None # Global scheduler instance for APScheduler

def check_expired_subscriptions(app_context): # <-- Accept app_context
    """定时任务：检查过期订阅"""
    job_name = "Check Expired Subs"
    # Ensure operations run within the passed app context
    with app_context(): # <-- Use the passed context WITH parentheses
        logger.info(f"[{job_name}] 定时任务: 开始检查过期订阅...")
        count = 0
        try:
            logger.debug(f"[{job_name}] 调用订阅服务进行过期检查...")
            # Call the service method, assuming it handles db session correctly within context
            count = SubscriptionService.check_expired_subscriptions()
            logger.info(f"[{job_name}] 定时任务: 已处理 {count} 个过期订阅")
        except Exception as e:
            logger.error(f"[{job_name}] 定时任务: 检查过期订阅任务出错: {e}", exc_info=True)
            # Rollback is likely handled by Flask-SQLAlchemy or the service method on exception
            # Explicit rollback here might interfere if service uses its own session management
            # try:
            #     db.session.rollback()
            # except Exception as rb_err:
            #      logger.error(f"[{job_name}] 回滚检查过期订阅任务时出错: {rb_err}")
        logger.debug(f"[{job_name}] 定时任务: 过期订阅检查完成，处理了 {count} 个订阅")
        return count # Return count even on error? Or 0? Let's return actual count processed before error.

# 新增的自动退出过期订阅用户设备的任务
def logout_expired_subscription_devices(app_context):
    """定时任务：检查并退出所有订阅均已过期的用户的设备"""
    job_name = "Logout Devices"
    with app_context():
        logger.info(f"[{job_name}] 定时任务: 开始检查并退出所有订阅均已过期的用户的设备...")
        adspower_api = get_adspower_api()
        logger.debug(f"[{job_name}] 已获取AdsPower API实例")
        total_devices_logged_out = 0
        processed_users = 0

        try:
            # 获取所有用户
            all_users = User.query.all()
            logger.debug(f"[{job_name}] 找到 {len(all_users)} 个用户")

            for user in all_users:
                processed_users += 1
                user_log_prefix = f"用户 {user.email} (ID: {user.id})"
                logger.debug(f"[{job_name}] 开始处理第 {processed_users}/{len(all_users)} 个用户: {user_log_prefix}")

                # 检查用户是否有任何有效的订阅
                has_active_subscription = Subscription.query.filter(
                    Subscription.user_id == user.id,
                    Subscription.end_date > datetime.utcnow()
                ).first()

                if has_active_subscription:
                    logger.debug(f"[{job_name}] {user_log_prefix} 至少有一个有效订阅 (例如 ID: {has_active_subscription.id}, 计划: {has_active_subscription.plan}, 结束于: {has_active_subscription.end_date})，跳过设备退出")
                    continue
                
                # 如果执行到这里，说明用户没有有效订阅（要么没有订阅，要么所有订阅都过期了）
                logger.info(f"[{job_name}] {user_log_prefix} 没有找到有效订阅，准备检查并退出其设备")

                # 查找该用户的所有设备
                devices = Device.query.filter_by(user_id=user.id).all()
                if not devices:
                    logger.info(f"[{job_name}] {user_log_prefix} 没有关联设备，无需操作")
                    continue

                devices_count = len(devices)
                logger.info(f"[{job_name}] {user_log_prefix} 发现 {devices_count} 个关联设备，准备退出")

                # 尝试退出该用户的所有设备
                for device in devices:
                    device_log_prefix = f"{user_log_prefix} 设备 ID: {device.id}, 名称: {device.device_name}"
                    logger.debug(f"[{job_name}] 处理 {device_log_prefix}")
                    
                    if not device.adspower_account_id:
                        logger.warning(f"[{job_name}] {device_log_prefix} 没有关联的AdsPower账号，无法远程退出，尝试直接删除记录")
                        try:
                            db.session.delete(device)
                            db.session.commit()
                            logger.info(f"[{job_name}] {device_log_prefix} 本地记录已删除 (无关联账号)")
                        except Exception as del_err:
                            logger.error(f"[{job_name}] {device_log_prefix} 删除本地记录时出错: {del_err}", exc_info=True)
                            db.session.rollback()
                        continue

                    adspower_account = AdspowerAccount.query.get(device.adspower_account_id)
                    if not adspower_account:
                        logger.warning(f"[{job_name}] {device_log_prefix} 找不到关联的AdsPower账号 {device.adspower_account_id}，无法远程退出，尝试直接删除记录")
                        try:
                            db.session.delete(device)
                            db.session.commit()
                            logger.info(f"[{job_name}] {device_log_prefix} 本地记录已删除 (关联账号不存在)")
                        except Exception as del_err:
                            logger.error(f"[{job_name}] {device_log_prefix} 删除本地记录时出错: {del_err}", exc_info=True)
                            db.session.rollback()
                        continue

                    if not device.device_name or not device.device_type:
                        logger.warning(f"[{job_name}] {device_log_prefix} 缺少名称或类型信息，无法远程退出，尝试直接删除记录")
                        try:
                            db.session.delete(device)
                            db.session.commit()
                            logger.info(f"[{job_name}] {device_log_prefix} 本地记录已删除 (缺少设备名称/类型)")
                        except Exception as del_err:
                            logger.error(f"[{job_name}] {device_log_prefix} 删除本地记录时出错: {del_err}", exc_info=True)
                            db.session.rollback()
                        continue

                    logger.info(f"[{job_name}] {device_log_prefix} 尝试退出 (账号: {adspower_account.username}, 类型: {device.device_type})")
                    success, message = adspower_api.logout_device(adspower_account, device.device_name, device.device_type)

                    if success:
                        total_devices_logged_out += 1
                        logger.info(f"[{job_name}] {device_log_prefix} 成功退出: {message}")
                        # 退出成功后删除本地记录
                        try:
                            logger.debug(f"[{job_name}] 从数据库中删除设备 {device.id}...")
                            db.session.delete(device)
                            db.session.commit()
                            logger.info(f"[{job_name}] {device_log_prefix} 已从数据库中删除")
                        except Exception as del_err:
                            logger.error(f"[{job_name}] {device_log_prefix} 从数据库删除设备时出错: {del_err}", exc_info=True)
                            db.session.rollback()
                    else:
                        logger.warning(f"[{job_name}] {device_log_prefix} 退出失败: {message}")
                        # 退出失败也尝试删除本地记录，因为用户已无有效订阅
                        try:
                            logger.debug(f"[{job_name}] 远程退出失败，仍尝试从数据库中删除设备 {device.id}...")
                            db.session.delete(device)
                            db.session.commit()
                            logger.info(f"[{job_name}] {device_log_prefix} 远程退出失败，但本地记录已删除")
                        except Exception as del_err:
                            logger.error(f"[{job_name}] {device_log_prefix} 远程退出失败后，从数据库删除设备时出错: {del_err}", exc_info=True)
                            db.session.rollback()
            
            logger.info(f"[{job_name}] 定时任务: 用户设备退出检查完成，共退出 {total_devices_logged_out} 个设备")
            return total_devices_logged_out

        except Exception as e:
            logger.error(f"[{job_name}] 定时任务: 退出无有效订阅用户设备任务出错: {e}", exc_info=True)
            try:
                db.session.rollback()
            except Exception as rb_err:
                logger.error(f"[{job_name}] 定时任务: 回滚退出设备任务时出错: {rb_err}")
            return 0

# 新增的清理未知设备任务
def cleanup_unknown_devices(app_context):
    """定时任务：检查AdsPower账号中的设备，退出不在数据库中的设备"""
    job_name = "Cleanup Unknown Devices"
    with app_context():
        logger.info(f"[{job_name}] 定时任务: 开始检查并清理未知设备...")
        adspower_api = get_adspower_api()
        logger.debug(f"[{job_name}] 已获取AdsPower API实例")
        
        try:
            # 获取所有活跃的AdsPower账号
            logger.debug(f"[{job_name}] 查询所有活跃的AdsPower账号...")
            active_accounts = AdspowerAccount.query.filter_by(is_active=True).all()
            if not active_accounts:
                logger.info(f"[{job_name}] 定时任务: 没有活跃的AdsPower账号，跳过清理未知设备")
                return 0
                
            logger.debug(f"[{job_name}] 找到 {len(active_accounts)} 个活跃账号")
            # 用于统计退出的设备数量
            total_logged_out = 0
            
            # 获取当前处于登录过程中的会话（最近5分钟内创建的会话）
            logger.debug(f"[{job_name}] 查询最近5分钟内创建的会话...")
            five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
            pending_sessions = LoginSession.query.filter(
                LoginSession.login_time >= five_minutes_ago
            ).all()
            
            # 收集处于登录过程中的账号IDs
            accounts_in_login_process = set()
            for session in pending_sessions:
                if session.adspower_account_id:
                    accounts_in_login_process.add(session.adspower_account_id)
                    logger.info(f"[{job_name}] 定时任务: 账号 {session.adspower_account_id} (邮箱: {session.adspower_account.username if session.adspower_account else '未知'}) 正在登录过程中，不进行设备清理")
            
            logger.info(f"[{job_name}] 定时任务: 共有 {len(accounts_in_login_process)} 个账号正在登录过程中，将跳过处理")
            
            # 处理每个账号
            accounts_processed = 0
            for account in active_accounts:
                accounts_processed += 1
                account_log_prefix = f"账号 {account.username} (ID: {account.id})"
                logger.debug(f"[{job_name}] 处理第 {accounts_processed}/{len(active_accounts)} 个账号: {account_log_prefix}")
                # 如果账号正在登录过程中，跳过处理
                if account.id in accounts_in_login_process:
                    logger.info(f"[{job_name}] 定时任务: 跳过 {account_log_prefix}，因为它正在登录过程中")
                    continue
                
                try:
                    # 获取账号的设备信息
                    logger.debug(f"[{job_name}] 获取 {account_log_prefix} 的设备信息...")
                    devices_info = adspower_api.get_devices_info(account)
                    if devices_info is None:
                        logger.warning(f"[{job_name}] 定时任务: 无法获取 {account_log_prefix} 的设备信息，跳过")
                        continue
                    
                    if not devices_info:
                        logger.info(f"[{job_name}] 定时任务: {account_log_prefix} 没有已登录设备")
                        continue
                    
                    logger.debug(f"[{job_name}] {account_log_prefix} 有 {len(devices_info)} 个已登录设备")
                    
                    # 获取数据库中该账号的所有设备
                    db_devices = Device.query.filter_by(adspower_account_id=account.id).all()
                    db_device_names = {device.device_name.lower() for device in db_devices if device.device_name}
                    
                    logger.debug(f"[{job_name}] 定时任务: 数据库中 {account_log_prefix} 的设备名称: {db_device_names}")
                    
                    # 检查每个设备是否在数据库中
                    for device in devices_info:
                        device_name = device.get('name')
                        device_type = device.get('device_type')
                        
                        if device_name:
                            logger.debug(f"[{job_name}] 定时任务: 检查设备: {device_name} ({device_type})")
                            
                            # 不区分大小写比较设备名
                            if device_name.lower() not in db_device_names:
                                logger.info(f"[{job_name}] 定时任务: 发现未知设备: {device_name} (类型: {device_type})，尝试退出")
                                logger.debug(f"[{job_name}] 调用AdsPower API退出设备: {device_name}...")
                                success, message = adspower_api.logout_device(account, device_name, device_type)
                                if success:
                                    total_logged_out += 1
                                    logger.info(f"[{job_name}] 定时任务: 成功退出未知设备: {device_name} - {message}")
                                else:
                                    logger.warning(f"[{job_name}] 定时任务: 退出未知设备 {device_name} 失败: {message}")
                
                except Exception as account_e:
                    logger.error(f"[{job_name}] 定时任务: 处理 {account_log_prefix} 的设备时出错: {account_e}", exc_info=True)
                    continue
            
            logger.info(f"[{job_name}] 定时任务: 设备清理完成，共退出 {total_logged_out} 个未知设备")
            return total_logged_out
            
        except Exception as e:
            logger.error(f"[{job_name}] 定时任务: 清理未知设备任务出错: {e}", exc_info=True)
            try:
                db.session.rollback()
            except Exception as rb_err:
                logger.error(f"[{job_name}] 定时任务: 回滚清理未知设备任务时出错: {rb_err}")
            return 0

# 新增的同步cookies到数据库的任务
def sync_cookies_to_database_job(app_context):
    """定时任务：将所有AdsPower账号的内存缓存cookies同步到数据库"""
    job_name = "Sync Cookies"
    with app_context():
        logger.info(f"[{job_name}] 定时任务: 开始同步AdsPower账号cookies到数据库...")
        
        try:
            # 获取WebDriver管理器以执行同步操作
            driver_manager = get_account_driver_manager()
            if not driver_manager:
                logger.warning(f"[{job_name}] 定时任务: 无法获取AccountWebDriverManager实例，跳过cookies同步")
                return 0
            
            # 直接调用AccountWebDriverManager的同步方法    
            cookies_updated = driver_manager.sync_cookies_to_database(app_context)
            
            logger.info(f"[{job_name}] 定时任务: cookies同步完成，更新了 {cookies_updated} 个账号的cookies")
            return cookies_updated
        
        except Exception as e:
            logger.error(f"[{job_name}] 定时任务: cookies同步任务出错: {e}", exc_info=True)
            try:
                db.session.rollback()
            except Exception as rb_err:
                logger.error(f"[{job_name}] 定时任务: 回滚cookies同步任务时出错: {rb_err}")
            return 0

# 定时更新 AccountWebDriverManager 中的托管账号
def update_managed_accounts_job(app_context):
    """定期从数据库加载活跃账号并更新到 AccountWebDriverManager"""
    job_name = "Update Managed Accounts"
    logger.info(f"[{job_name}] 定时任务: 正在更新AccountWebDriverManager中的托管账号...")
    with app_context(): # 使用传入的应用上下文
        try:
            logger.debug(f"[{job_name}] 查询活跃的AdsPower账号...")
            accounts = AdspowerAccount.query.filter_by(is_active=True).all()
            if not accounts:
                logger.info(f"[{job_name}] 定时任务: 数据库中未找到活跃账号。")
                # 如果没有活跃账号，可能需要通知管理器移除所有现有账号？
                # 暂时保持不变，仅在有活跃账号时更新
                # return
            
            logger.debug(f"[{job_name}] 找到 {len(accounts)} 个活跃账号，获取账号管理器...")
            manager = get_account_driver_manager()
            if not manager:
                 logger.warning(f"[{job_name}] 定时任务: AccountWebDriverManager尚未初始化。跳过更新。")
                 return

            # 检查管理器是否仍在运行
            if not manager.running:
                logger.warning(f"[{job_name}] 定时任务: AccountWebDriverManager管理线程未运行。跳过更新。")
                return

            updated_count = 0
            error_count = 0
            removed_count = 0
            try:
                logger.debug(f"[{job_name}] 获取当前托管账号ID列表...")
                current_managed_ids = manager.get_managed_account_ids() # 获取当前托管的IDs
            except AttributeError:
                 logger.error(f"[{job_name}] 定时任务: AccountWebDriverManager实例缺少'get_managed_account_ids'方法。")
                 return # 无法继续
            except Exception as get_ids_err:
                 logger.error(f"[{job_name}] 定时任务: 获取托管账号ID时出错: {get_ids_err}", exc_info=True)
                 return # 无法安全继续

            # 添加/更新数据库中的活跃账号到管理器
            logger.debug(f"[{job_name}] 开始同步数据库账号到管理器...")
            db_active_ids = set()
            for acc in accounts:
                db_active_ids.add(str(acc.id)) # 收集数据库中活跃的ID
                try:
                    cookies = acc.cookies # 从 cookies 字段获取
                    logger.debug(f"[{job_name}] 添加/更新账号 {acc.username} (ID: {acc.id})...")
                    # 将账号信息添加到管理器
                    manager.add_managed_account(
                        account_id=str(acc.id),
                        username=acc.username,
                        password=acc.password, # 注意：频繁传递密码的安全性
                        totp_secret=acc.totp_secret, # 注意：安全性
                        cookies=cookies
                    )
                    updated_count += 1
                    logger.debug(f"[{job_name}] 成功更新/注册账号: {acc.username}")
                except AttributeError:
                     logger.error(f"[{job_name}] 定时任务: AccountWebDriverManager实例缺少'add_managed_account'方法。")
                     error_count += 1
                except Exception as add_err:
                    logger.error(f"[{job_name}] 定时任务: 添加/更新托管账号 {acc.username} (ID: {acc.id}) 时出错: {add_err}", exc_info=True)
                    error_count += 1

            # 从管理器中移除不再活跃的账号
            logger.debug(f"[{job_name}] 检查需要从管理器中移除的账号...")
            ids_to_remove = current_managed_ids - db_active_ids
            for acc_id_str in ids_to_remove:
                try:
                    logger.debug(f"[{job_name}] 从管理器中移除账号 ID: {acc_id_str}...")
                    manager.remove_managed_account(acc_id_str)
                    removed_count += 1
                    logger.info(f"[{job_name}] 定时任务: 已从管理器中移除不活跃账号 ID {acc_id_str}。")
                except AttributeError:
                     logger.error(f"[{job_name}] 定时任务: AccountWebDriverManager实例缺少'remove_managed_account'方法。")
                     error_count += 1
                except Exception as remove_err:
                    logger.error(f"[{job_name}] 定时任务: 移除托管账号 ID {acc_id_str} 时出错: {remove_err}", exc_info=True)
                    error_count += 1

            logger.info(f"[{job_name}] 定时任务: 托管账号同步完成。更新/添加: {updated_count}，移除: {removed_count}，错误: {error_count}")
        except Exception as job_err:
            logger.error(f"[{job_name}] 定时任务: 托管账号更新任务期间出错: {job_err}", exc_info=True)
            # 考虑是否需要回滚，但此任务通常不直接修改数据库状态
            # try: db.session.rollback() 
            # except: pass

# --- APScheduler based init function ---
def init_scheduler(app):
    """初始化 APScheduler 并添加任务"""
    global scheduler # Declare intent to modify the global scheduler variable
    logger.info("开始初始化调度器...")

    if scheduler is not None and scheduler.running:
        logger.warning("调度器已经在运行，跳过初始化。")
        return

    # --- Create the scheduler instance FIRST ---
    logger.info("正在初始化APScheduler后台调度器...")
    scheduler = BackgroundScheduler(daemon=True)
    logger.debug("BackgroundScheduler实例已创建")

    # --- Now add jobs ---
    logger.info("正在添加APScheduler任务...")
    # Job 1: Check expired subscriptions
    try:
        logger.debug(f"添加检查过期订阅任务，间隔：{CHECK_EXPIRATION_INTERVAL}秒...")
        scheduler.add_job(
            func=check_expired_subscriptions,
            trigger=IntervalTrigger(minutes=CHECK_EXPIRATION_INTERVAL),
            id='check_expired_subscriptions',
            name='检查过期订阅',
            args=[app.app_context],
            replace_existing=True
        )
        logger.info(f"已添加检查过期订阅任务，间隔：{CHECK_EXPIRATION_INTERVAL}分钟")
    except Exception as add_job_e:
        logger.error(f"添加检查过期订阅任务时出错: {add_job_e}")

    # Job 2: Logout expired subscription devices
    try:
        logger.debug("添加退出过期订阅设备任务，间隔：60秒...")
        scheduler.add_job(
            func=logout_expired_subscription_devices,
            trigger=IntervalTrigger(seconds=60),
            id='logout_expired_subscription_devices',
            name='退出过期订阅设备',
            args=[app.app_context],
            replace_existing=True
        )
        logger.info("已添加退出过期订阅设备任务，间隔：60秒")
    except Exception as add_job_e:
        logger.error(f"添加退出过期订阅设备任务时出错: {add_job_e}")
    
    # Job 3: Clean up unknown devices
    try:
        logger.debug("添加清理未知设备任务，间隔：60秒...")
        scheduler.add_job(
            func=cleanup_unknown_devices,
            trigger=IntervalTrigger(seconds=60),
            id='cleanup_unknown_devices',
            name='清理未知设备',
            args=[app.app_context],
            replace_existing=True
        )
        logger.info("已添加清理未知设备任务，间隔：60秒")
    except Exception as add_job_e:
        logger.error(f"添加清理未知设备任务时出错: {add_job_e}")
        
    # Job 4: Sync cookies to database
    # try:
    #     logger.debug("添加cookies同步任务，间隔：30秒...")
    #     scheduler.add_job(
    #         func=sync_cookies_to_database_job,
    #         trigger=IntervalTrigger(seconds=30),
    #         id='sync_cookies_to_database',
    #         name='同步Cookies到数据库',
    #         args=[app.app_context],
    #         replace_existing=True
    #     )
    #     logger.info("已添加cookies同步任务，间隔：30秒")
    # except Exception as add_job_e:
    #     logger.error(f"添加cookies同步任务时出错: {add_job_e}")
        
    # # Job 5: Update managed accounts (用户要求移除)
    # try:
    #     logger.debug(f"添加更新管理账号任务，间隔：{REFRESH_INTERVAL}秒...")
    #     logger.debug("添加更新托管账号任务，间隔：5分钟...")
    #     scheduler.add_job(
    #         func=update_managed_accounts_job,
    #         trigger=IntervalTrigger(minutes=5), # Runs every 5 minutes
    #         id='update_managed_accounts_job',
    #         name='更新托管账号',
    #         replace_existing=True,
    #         kwargs={'app_context': app.app_context} # Pass context to the job function itself
    #     )
    #     logger.info("已添加任务: 更新托管账号 (间隔: 5分钟)")
    # except Exception as e:
    #     logger.error(f"添加任务'更新托管账号'失败: {e}", exc_info=True)

    # --- Start the scheduler ---
    try:
        logger.info("正在启动调度器...")
        scheduler.start()
        logger.info("调度器启动成功。")
    except Exception as e:
        logger.error(f"启动调度器失败: {e}", exc_info=True)
        scheduler = None # Reset scheduler if start fails
        # Should we raise an error here to prevent app from running without scheduler?
        # raise RuntimeError("Failed to start APScheduler") from e
        return # Indicate failure

    # Register the shutdown function using atexit
    logger.info("正在使用atexit注册调度器关闭钩子。")
    atexit.register(shutdown_scheduler)
    logger.debug("调度器初始化完成")

# --- Simplified Shutdown Function for APScheduler ---
def shutdown_scheduler():
    """关闭 APScheduler"""
    global scheduler
    logger.info("正在尝试关闭调度器...")
    if scheduler and scheduler.running:
        try:
            logger.debug("调度器正在运行，执行关闭操作...")
            # wait=False might cause issues if jobs need to finish cleanly? Test carefully.
            # Let's try wait=True first for safety, unless atexit timeout is a concern.
            scheduler.shutdown(wait=True) # Wait for running jobs to complete
            logger.info("调度器成功关闭（等待任务完成）。")
        except Exception as e:
            logger.error(f"关闭调度器时出错: {e}", exc_info=True)
            # Should we try shutdown(wait=False) as fallback?
    else:
        logger.info("调度器未运行或未初始化。")
    # Clear the global reference after shutdown attempt
    scheduler = None
    logger.debug("调度器引用已清除")

# --- Ensure app.py calls cleanup correctly ---
# Note: The cleanup_resources function in app.py should handle calling
# stop_account_manager() and shutdown_driver_pool().
# This shutdown_scheduler only handles the APScheduler itself.
# Make sure atexit registration order is correct if dependencies exist. 

def background_scheduler_task(app):
    """后台调度任务"""
    try:
        # 检查过期的订阅 (现在由 SubscriptionService 处理，无需在此处重复)
        # logger.debug("Scheduler: 检查过期订阅...")
        # SubscriptionService.check_expired_subscriptions()
        # logger.debug("Scheduler: 过期订阅检查完成")
        
        # 检查并关闭长时间不活动的会话（如果需要的话）
        # ...

        # 检查AdsPower账号状态并同步Cookies到数据库
        account_manager = get_account_driver_manager(create_if_none=False)
        if account_manager:
            logger.debug("Scheduler: 开始同步账号Cookies到数据库...")
            try:
                # 使用 Flask 应用上下文执行数据库操作
                synced_count = account_manager.sync_cookies_to_database(app_context=app.app_context)
                logger.debug(f"Scheduler: 账号Cookies同步完成，更新了 {synced_count} 个账号")
            except Exception as sync_err:
                logger.error(f"Scheduler: 同步Cookies到数据库时出错: {sync_err}", exc_info=True)
        else:
            logger.warning("Scheduler: AccountWebDriverManager 未初始化，无法同步Cookies")
        
    except Exception as e:
        logger.error(f"执行后台调度任务时出错: {e}", exc_info=True)

# @scheduler.task('interval', id='check_expired_subs', seconds=3600, misfire_grace_time=900)
# def check_expired_subscriptions_job():
#     """定时任务：检查并标记过期订阅"""
#     logger.info("定时任务：开始检查过期订阅...")
#     with app.app_context():
#         try:
#             expired_subs = Subscription.query.filter(
#                 Subscription.end_date < datetime.utcnow(),
#                 Subscription.status == 'active',  # 仅检查标记为活跃但实际已过期的订阅
#             ).all()

#             count = 0
#             for sub in expired_subs:
#                 logger.info(f"定时任务：用户 {sub.user_id} 的订阅 {sub.id} 已过期，正在标记为 expired")
#                 sub.status = 'expired'
#                 db.session.add(sub)
#                 count += 1

#             if count > 0:
#                 db.session.commit()
#                 logger.info(f"定时任务：已处理 {count} 个过期订阅")
#             else:
#                 logger.info("定时任务：没有发现需要处理的过期订阅")

#         except Exception as e:
#             logger.error(f"定时任务执行检查过期订阅时出错: {e}", exc_info=True)
#             try:
#                 db.session.rollback()
#             except Exception as rb_err:
#                 logger.error(f"数据库回滚失败: {rb_err}")

# 可以添加更多定时任务，例如清理旧的登录会话、发送提醒邮件等
# ... 

def check_adspower_account_health(account_id, account_info):
    log_prefix = f"[健康检查 账号ID: {account_id}]"
    logger.info(f"{log_prefix} 开始检查账号 {account_info.get('username')}")

    acc = AdspowerAccount.query.get(account_id)
    if not acc:
        logger.error(f"{log_prefix} 数据库中未找到账号")
        return False

    cookies = acc.cookies # 从 cookies 字段获取
    if not cookies:
        logger.warning(f"{log_prefix} 账号没有保存 Cookies，无法执行健康检查")
        return False

    # 继续执行健康检查逻辑
    # ...

    return True # 假设检查通过

# 可以添加更多健康检查逻辑，例如检查账号的设备状态、订阅状态等
# ... 