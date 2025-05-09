import logging
import secrets
import json
from datetime import datetime, timedelta

from flask import url_for, request

from ..models import db, User, AdspowerAccount, LoginSession, Subscription, Device
from ..webdriver_pool import get_account_driver_manager, AccountWebDriverManager
from .auth_service import AuthService # Need AuthService to check subscriptions
from ..adspower_api import get_adspower_api

logger = logging.getLogger(__name__)

class DirectLoginService:
    """
    处理准备AdsPower账户直接登录会话的过程。
    职责包括：
    - 检查用户订阅状态。
    - 根据订阅查找合适的、可用的AdsPower账户。
    - 验证所选AdsPower账户实例的实时可用性。
    - 创建临时的LoginSession记录。
    """

    def __init__(self):
        self.auth_service = AuthService()
        self.driver_manager = get_account_driver_manager()

    def prepare_login(self, user_id):
        """
        为指定用户准备直接登录会话。

        Args:
            user_id (int): 请求登录的用户ID。

        Returns:
            dict: 包含结果的字典:
                  {
                      'success': bool,
                      'message': str,
                      'error_code': str | None,
                      'data': { ... 登录详情 ... } | None
                  }
        """
        logger.info(f"[直接登录服务] 正在为用户ID: {user_id} 准备登录会话")

        # 1. 检查用户订阅
        subscription = self.auth_service.get_user_subscription(user_id)
        if not subscription:
            logger.warning(f"[直接登录服务] 用户 {user_id} 无有效订阅.")
            return {
                'success': False,
                'message': '您没有有效的订阅',
                'error_code': 'no_subscription',
                'data': None
            }
        subscription_type = subscription.plan
        logger.info(f"[直接登录服务] 用户 {user_id} 拥有有效订阅: {subscription_type}")

        # 1.1 检查用户设备限制
        active_device_count = Device.query.filter_by(user_id=user_id).count()
        if active_device_count >= subscription.max_devices:
            logger.warning(f"[直接登录服务] 用户 {user_id} 已达到设备上限 ({active_device_count}/{subscription.max_devices}). 拒绝访问.")
            return {
                'success': False,
                'message': f'您已达到设备数量上限 ({subscription.max_devices}台)，请在"设备管理"中登出不再使用的设备。',
                'error_code': 'DEVICE_LIMIT_REACHED',
                'data': None
            }
        logger.info(f"[直接登录服务] 用户 {user_id} 设备数量检查通过 ({active_device_count}/{subscription.max_devices}). 继续操作...")

        # 2. 查找合适的AdsPower账户
        adspower_account = AdspowerAccount.query.filter(
            AdspowerAccount.subscription_type == subscription_type,
            AdspowerAccount.is_active == True,
        ).order_by(
            AdspowerAccount.last_login # 尝试最近使用过的
        ).first()

        if not adspower_account:
            logger.warning(f"[直接登录服务] 未找到订阅类型为 '{subscription_type}' 的可用AdsPower账户 (用户ID: {user_id})")
            return {
                'success': False,
                'message': f"暂时没有可用的 '{subscription_type}' 类型账号，请稍后再试",
                'error_code': 'no_account_available',
                'data': None
            }
        account_id_str = str(adspower_account.id)
        log_prefix = f"[直接登录服务] 用户ID: {user_id}, 尝试账户: {adspower_account.username} (ID: {account_id_str})"
        logger.info(f"{log_prefix} 已找到候选AdsPower账户.")

        # 3. 获取初始设备快照
        logger.info(f"{log_prefix} 正在尝试从AdsPower API获取初始设备快照...")
        adspower_api = get_adspower_api()
        initial_devices = None
        try:
            initial_devices = adspower_api.get_devices_info(adspower_account)

            if initial_devices is None:
                logger.error(f"{log_prefix} 从AdsPower API获取设备列表失败 (API返回None). 账户实例可能未就绪或发生错误.")
                return {
                    'success': False,
                    'message': f"所选账户 ({adspower_account.username}) 暂时无法准备就绪或获取状态失败，请稍后重试。",
                    'error_code': 'account_not_ready_or_failed',
                    'data': None
                }
            elif not initial_devices:
                logger.info(f"{log_prefix} 成功获取初始设备快照: 发现0个设备. 继续登录流程.")
                initial_devices_snapshot_json = json.dumps([])
            else:
                initial_devices_snapshot_json = json.dumps(initial_devices)
                logger.info(f"{log_prefix} 成功获取初始设备快照 (设备数量: {len(initial_devices)}).")

        except Exception as e:
            logger.error(f"{log_prefix} 获取初始设备快照时发生意外错误: {e}", exc_info=True)
            return {
                'success': False,
                'message': "获取初始设备快照时发生意外错误",
                'error_code': 'snapshot_processing_error',
                'data': None
            }

        # 4. Create LoginSession (Continue only if initial_devices was not None)
        logger.info(f"{log_prefix} 正在创建LoginSession...")
        try:
            login_token = secrets.token_urlsafe(32)
            client_ip = request.remote_addr if request else None
            user_agent_string = request.user_agent.string if request and request.user_agent else None
            expiration_time = datetime.utcnow() + timedelta(seconds=120)

            login_session = LoginSession(
                user_id=user_id,
                adspower_account_id=adspower_account.id,
                login_token=login_token,
                expiration_timestamp=expiration_time,
                ip_address=client_ip,
                user_agent=user_agent_string,
                known_devices_snapshot=initial_devices_snapshot_json
            )
            db.session.add(login_session)
            db.session.commit()
            logger.info(f"{log_prefix} LoginSession {login_session.id} created successfully.")

            # 5. Prepare response data (重新生成 login_url)
            login_page_url = None
            try:
                login_page_url = url_for(
                    'main.adspower_direct_login',
                    token=login_token,
                    username=adspower_account.username,
                    password=adspower_account.password,
                    account_id=adspower_account.id,
                    expires=expiration_time.isoformat() + "Z",
                    _external=True
                )
                logger.info(f"{log_prefix} 生成的登录URL (已移除TOTP密钥): {login_page_url}")
            except RuntimeError as url_e:
                logger.error(f"{log_prefix} Failed to generate login_url using url_for: {url_e}. Returning data without URL.")

            return {
                'success': True,
                'message': '获取登录信息成功',
                'error_code': None,
                'data': {
                    'login_token': login_token,
                    'username': adspower_account.username,
                    'password': adspower_account.password,
                    'account_id': adspower_account.id,
                    'expiration_timestamp_iso': expiration_time.isoformat() + "Z",
                    'login_url': login_page_url
                }
            }
        except Exception as e:
            logger.exception(f"{log_prefix} Error creating LoginSession or preparing response: {e}")
            try:
                db.session.rollback()
            except Exception as rb_err:
                logger.error(f"{log_prefix} Database rollback failed after LoginSession creation error: {rb_err}")
            return {
                'success': False,
                'message': "创建登录会话时发生内部错误",
                'error_code': 'session_creation_failed',
                'data': None
            }

# --- Helper to get the service instance ---
# (Consider using Flask app context patterns for better dependency management later)
_direct_login_service = None

def get_direct_login_service():
    global _direct_login_service
    if _direct_login_service is None:
        _direct_login_service = DirectLoginService()
    return _direct_login_service 