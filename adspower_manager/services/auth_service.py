import logging
import re
import random
import string
import pyotp
import jwt
from datetime import datetime, timedelta
from flask import current_app, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from ..models import db, User, ChatGPTAccount, AdspowerAccount, Device, Subscription, EmailVerification, LoginSession
from config import (
    JWT_SECRET_KEY, JWT_ACCESS_TOKEN_EXPIRES, JWT_REFRESH_TOKEN_EXPIRES,
    PASSWORD_MIN_LENGTH, PASSWORD_REQUIRE_SPECIAL_CHAR, PASSWORD_REQUIRE_NUMBER,
    TOTP_VERIFICATION_TIMEOUT, SECRET_KEY, REQUIRE_EMAIL_VERIFICATION
)
from .email_service import EmailService
import secrets
import json

# logger = logging.getLogger(__name__)
# 配置日志，使用中文
logger = logging.getLogger(__name__)
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class AuthService:
    """认证服务，处理用户注册、登录等认证相关功能"""
    
    def __init__(self, app=None):
        """初始化认证服务
        
        Args:
            app: Flask应用实例
        """
        self.app = app
        self.email_service = EmailService() # Instantiate EmailService here again
        self.secret_key = SECRET_KEY
        self.require_email_verification = REQUIRE_EMAIL_VERIFICATION
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """通过应用实例配置认证服务
        
        Args:
            app: Flask应用实例
        """
        self.secret_key = app.config.get('SECRET_KEY', SECRET_KEY)
        self.require_email_verification = app.config.get('REQUIRE_EMAIL_VERIFICATION', True)
        # Instantiate and initialize EmailService *here* when app context is available
        # self.email_service = EmailService() # Remove instantiation from here
        # Still call init_app on the instance created in __init__
        if self.email_service:
            self.email_service.init_app(app)
        
        logger.info("认证服务初始化完成") # Update log message
    
    def validate_password(self, password):
        """验证密码强度"""
        if len(password) < PASSWORD_MIN_LENGTH:
            return False, f"密码长度至少为{PASSWORD_MIN_LENGTH}个字符"
        
        if PASSWORD_REQUIRE_NUMBER and not re.search(r'\d', password):
            return False, "密码必须包含数字"
        
        if PASSWORD_REQUIRE_SPECIAL_CHAR and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "密码必须包含特殊字符"
        
        return True, "密码符合要求"
    
    def register_user(self, email, password, verification_code, is_admin=False):
        """注册新用户，并在注册时验证邮箱
        
        Args:
            email: 邮箱
            password: 密码
            verification_code: 用户提供的邮箱验证码
            is_admin: 是否为管理员
            
        Returns:
            (user, message): 用户对象和消息
        """
        # 检查邮箱是否已存在
        if User.query.filter_by(email=email).first():
            logger.warning(f"注册失败：邮箱 '{email}' 已存在")
            return None, "邮箱已存在"
        
        # 检查密码强度
        is_valid, msg = self.validate_password(password)
        if not is_valid:
            logger.warning(f"注册失败：邮箱 '{email}' 的密码强度不足: {msg}")
            return None, msg

        # 在创建用户前验证邮箱验证码
        # 使用 EmailService 的实例来调用 verify_code
        email_verify_success, email_verify_message = self.email_service.verify_code(email, verification_code, code_type="register")
        if not email_verify_success:
            logger.warning(f"注册失败：邮箱 '{email}' 验证码无效: {email_verify_message}")
            return None, email_verify_message # 返回具体的验证码错误信息

        # 验证码有效，继续创建用户
        user = User(
            email=email,
            is_admin=is_admin,
            is_active=True
        )
        user.set_password(password)
        
        # 注册时直接标记邮箱为已验证
        user.is_email_verified = True
        user.email_verified_at = datetime.utcnow() # 记录验证时间
        
        # 保存到数据库
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"用户注册成功并通过邮箱验证：'{user.email}'")
        
        # 移除内部再次发送验证邮件的逻辑
        # if self.require_email_verification:
        #     ...
        
        return user, "注册成功"
    
    def login_user(self, email, password, verification_code=None):
        """用户登录
        
        Args:
            email: 邮箱
            password: 密码
            verification_code: 邮箱验证码（如有）
            
        Returns:
            (user, token, message): 用户对象，JWT令牌和消息
        """
        # 查找用户
        user = User.query.filter_by(email=email).first()
        
        if not user:
            logger.warning(f"登录失败：邮箱不存在 '{email}'")
            return None, None, "邮箱不存在"
        
        # 检查密码
        if not user.check_password(password):
            logger.warning(f"登录失败：邮箱 '{email}' 密码错误")
            return None, None, "密码错误"
        
        # 检查账号状态
        if not user.is_active:
            logger.warning(f"登录失败：邮箱 '{email}' 账号已被禁用")
            return None, None, "账号已被禁用"
        
        # 更新最后登录时间
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # 生成JWT令牌
        token = self.generate_token(user)
        
        logger.info(f"用户登录成功：'{user.email}'")
        return user, token, "登录成功"
    
    def verify_email(self, email, code):
        """验证用户邮箱
        
        Args:
            email: 邮箱
            code: 验证码
            
        Returns:
            (success, message): 验证结果和消息
        """
        # 查找用户
        user = User.query.filter_by(email=email).first()
        if not user:
            logger.warning(f"邮箱验证失败：用户不存在 '{email}'")
            return False, "用户不存在"
        
        # 验证码验证
        success, message = self.email_service.verify_code(email, code, code_type="register")
        if not success:
            # Log the specific reason for code verification failure
            logger.warning(f"邮箱验证失败：用户 '{email}' 验证码错误或过期 ({message})")
            return False, message # Return the specific error message from verify_code
        
        # 更新用户邮箱验证状态
        user.verify_email()
        db.session.commit()
        
        logger.info(f"用户邮箱验证成功：'{email}'")
        return True, "邮箱验证成功"
    
    def generate_token(self, user):
        """为用户生成JWT令牌
        
        Args:
            user: 用户对象
            
        Returns:
            JWT令牌
        """
        payload = {
            'user_id': user.id,
            'username': user.email,
            'email': user.email,
            'is_admin': user.is_admin,
            'exp': datetime.utcnow() + timedelta(days=1)  # 令牌有效期1天
        }
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        return token
    
    def verify_token(self, token):
        """验证JWT令牌
        
        Args:
            token: JWT令牌
            
        Returns:
            (user, message): 用户对象和消息
        """
        try:
            # 解码令牌
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # 获取用户
            user_id = payload.get('user_id')
            user = User.query.get(user_id)
            
            if not user:
                logger.warning(f"令牌验证失败：用户ID '{user_id}' 不存在")
                return None, "令牌无效，用户不存在"
            
            if not user.is_active:
                logger.warning(f"令牌验证失败：用户ID '{user_id}' 账号已被禁用")
                return None, "账号已被禁用"
            
            # Optionally log success? Might be too verbose.
            # logger.info(f"令牌验证成功：用户ID '{user_id}'")
            return user, "令牌验证成功"
        except jwt.ExpiredSignatureError:
            logger.warning("令牌验证失败：令牌已过期")
            return None, "令牌已过期"
        except jwt.InvalidTokenError as e: # Catch specific invalid token errors
            logger.warning(f"令牌验证失败：令牌无效 ({e})")
            return None, "令牌无效"
        except Exception as e:
            logger.error(f"令牌验证时发生未知错误：{str(e)}", exc_info=True) # Use exc_info for full traceback
            return None, f"令牌验证失败：{str(e)}"
    
    def reset_password_request(self, email):
        """请求重置密码
        
        Args:
            email: 用户邮箱
            
        Returns:
            (success, message): 请求结果和消息
        """
        # 查找用户
        user = User.query.filter_by(email=email).first()
        if not user:
            logger.warning(f"密码重置请求失败：邮箱 '{email}' 对应的用户不存在")
            return False, "用户不存在"
        
        # 发送重置验证码
        success, message, _ = self.email_service.send_verification_email(email, code_type="reset")
        
        if success:
            logger.info(f"密码重置验证码已发送至：'{email}'")
        else:
            logger.warning(f"密码重置验证码发送失败：邮箱 '{email}' ({message})")
        
        return success, message # Return the message from email service
    
    def reset_password(self, email, code, new_password):
        """重置密码
        
        Args:
            email: 用户邮箱
            code: 验证码
            new_password: 新密码
            
        Returns:
            (success, message): 重置结果和消息
        """
        # 查找用户
        user = User.query.filter_by(email=email).first()
        if not user:
            logger.warning(f"密码重置失败：邮箱 '{email}' 对应的用户不存在")
            return False, "用户不存在"
        
        # 验证验证码
        success, message = self.email_service.verify_code(email, code, code_type="reset")
        if not success:
            logger.warning(f"密码重置失败：邮箱 '{email}' 验证码错误或过期 ({message})")
            return False, message # Return specific error
        
        # 更新密码
        user.set_password(new_password)
        user.last_login = datetime.utcnow()  # 更新最后登录时间
        
        # 如果用户邮箱未验证，同时标记为已验证
        if not user.is_email_verified:
            user.verify_email()
            logger.info(f"密码重置过程中，用户 '{email}' 的邮箱已同时被验证")
        
        db.session.commit()
        
        logger.info(f"用户密码重置成功：邮箱 '{email}'")
        return True, "密码重置成功"
    
    def get_user_subscription(self, user_id):
        """获取用户当前有效的订阅"""
        active_sub = Subscription.query.filter(
            Subscription.user_id == user_id,
            Subscription.end_date > datetime.utcnow()
        ).order_by(
            Subscription.end_date.desc()
        ).first()
        
        # Optionally log if subscription found or not
        # if subscription:
        #     logger.debug(f"用户 {user_id} 找到有效订阅，结束日期: {subscription.end_date}")
        # else:
        #     logger.debug(f"用户 {user_id} 未找到有效订阅")
        
        return active_sub

    def get_adspower_login_info(self, user_id):
        """获取AdsPower账号的登录信息 (已简化 - 不再执行实时验证和会话创建)
        
        主要职责是根据用户订阅查找一个合适的、活跃的账号记录。
        实时验证和会话创建由 DirectLoginService 处理。
        """
        try:
            user = User.query.get(user_id)
            if not user:
                logger.error(f"获取AdsPower登录信息失败：用户ID '{user_id}' 不存在")
                return {
                    'success': False,
                    'message': '用户不存在',
                    'error_code': 'user_not_found'
                }

            # 检查用户是否有有效订阅
            subscription = self.get_user_subscription(user_id)
            if not subscription:
                logger.warning(f"获取AdsPower登录信息失败：用户 '{user_id}' 没有有效订阅") # Changed log level to warning
                return {
                    'success': False,
                    'message': '您没有有效的订阅',
                    'error_code': 'no_subscription'
                }

            # 获取用户的订阅类型
            subscription_type = subscription.plan

            # --- 简化查找逻辑 --- 
            # 只查找数据库记录，不执行实时检查
            adspower_account = AdspowerAccount.query.filter(
                AdspowerAccount.subscription_type == subscription_type,
                AdspowerAccount.is_active == True
            ).order_by(
                AdspowerAccount.last_login # Or some other basic criteria
            ).first()

            if not adspower_account:
                logger.warning(f"查找账号记录失败：没有找到订阅类型为 '{subscription_type}' 的可用AdsPower账号记录")
                return {
                    'success': False,
                    'message': f"数据库中没有可用的 '{subscription_type}' 类型账号记录",
                    'error_code': 'no_account_record_available'
                }

            # --- 移除实时扫描和健康检查逻辑 --- 
            # initial_devices_count = 0
            # initial_devices_info_json = json.dumps([])
            # scan_success = False 
            # account_health_status = '未知' 
            # devices = None 
            # try:
            #     ...
            #     ads_api.get_devices_info(...)
            #     ...
            # except Exception as e:
            #     ...
            # --- 扫描与健康检查结束 ---
            
            # --- 移除会话创建逻辑 --- 
            # logger.info(f"...")
            # login_token = secrets.token_urlsafe(32)
            # ...
            # login_session = LoginSession(...)
            # db.session.add(login_session)
            # db.session.commit()
            # --- 会话创建结束 ---

            # --- 构造简化的返回信息 (仅账号凭据) ---
            # 不再生成 login_url 或 login_token 在这里
            logger.info(f"成功为用户 '{user_id}' 找到AdsPower账号记录 '{adspower_account.username}' (订阅类型: {subscription_type})")
            return {
                'success': True,
                'message': '找到账号登录信息记录', # Changed message
                'data': {
                    # 'login_token': None, # Removed
                    'username': adspower_account.username,
                    'password': adspower_account.password,
                    'totp_secret': adspower_account.totp_secret,
                    # 'login_url': None, # Removed
                    'account_id': adspower_account.id
                }
            }

        except Exception as e:
            logger.exception(f"查找AdsPower登录信息记录时发生错误：{str(e)}")
            # Database rollback might not be needed if only reads were performed
            # try: db.session.rollback()
            # except: pass
            return {
                'success': False,
                'message': "系统内部错误，请联系管理员",
                'error_code': 'system_error'
            }


class DeviceAuthService:
    """设备认证服务，处理设备登录验证和分配"""
    
    def __init__(self):
        self.auth_service = AuthService()
    
    def register_device(self, user_id, device_id, device_info):
        """注册新设备"""
        # 检查用户是否存在
        user = User.query.get(user_id)
        if not user:
            # Add logging
            logger.warning(f"设备注册失败：用户ID '{user_id}' 不存在")
            return False, None, "用户不存在"
        
        # 检查设备ID是否已存在
        existing_device = Device.query.filter_by(device_id=device_id).first()
        if existing_device:
            # 如果设备已存在且属于该用户，则直接返回
            if existing_device.user_id == user_id:
                # Add logging
                logger.info(f"设备 '{device_id}' 已由用户 '{user_id}' 注册，无需重复操作")
                return True, existing_device, "设备已注册"
            # 如果设备已被其他用户占用，拒绝
            # Add logging
            logger.warning(f"设备注册失败：设备ID '{device_id}' 已被其他用户 ({existing_device.user_id}) 使用")
            return False, None, "设备ID已被其他用户使用"
        
        # 检查用户是否有有效订阅
        subscription = self.auth_service.get_user_subscription(user_id)
        if not subscription:
            # Add logging
            logger.warning(f"设备注册失败：用户 '{user_id}' 没有有效订阅")
            return False, None, "用户没有有效订阅"
        
        # 检查用户设备数量是否已达上限
        device_count = Device.query.filter_by(user_id=user_id).count()
        # Use >= for comparison
        if device_count >= subscription.max_devices:
            # Add logging
            logger.warning(f"设备注册失败：用户 '{user_id}' 设备数量 ({device_count}) 已达订阅上限 ({subscription.max_devices})")
            return False, None, f"设备数量已达上限({subscription.max_devices}台)"
        
        # 获取用户的订阅类型
        subscription_type = subscription.plan  # 例如 'monthly', 'student'
        
        # 直接查询匹配订阅类型的可用账号
        adspower_account = AdspowerAccount.query.filter(
            AdspowerAccount.subscription_type == subscription_type,
            AdspowerAccount.is_active == True,
            AdspowerAccount.current_devices < AdspowerAccount.max_devices
        ).order_by(
            AdspowerAccount.current_devices  # 优先选择设备数较少的账号
        ).first()
        
        # 如果没有找到匹配订阅类型的账号，尝试获取任意可用账号
        if not adspower_account:
            logger.warning(f"设备注册失败：用户 '{user_id}' 无法找到订阅类型 '{subscription_type}' 的可用AdsPower账号")
            return False, None, f"没有可用的 '{subscription_type}' 类型账号"
        
        # 创建设备记录
        device = Device(
            user_id=user_id,
            adspower_account_id=adspower_account.id,
            device_id=device_id,
            device_name=device_info.get('name', f"设备_{device_id[:8]}"),
            device_ip=device_info.get('ip_address'),
            device_type=device_info.get('type', 'unknown'),
            last_login=datetime.utcnow(),
            created_at=datetime.utcnow()
        )
        
        # 更新ADSpower账号设备计数
        adspower_account.current_devices += 1
        
        db.session.add(device)
        # Add adspower_account to the session as well since we modified it
        db.session.add(adspower_account)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"设备注册时数据库提交失败：用户 '{user_id}', 设备 '{device_id}'. 错误: {e}", exc_info=True)
            return False, None, "设备注册时数据库错误"
        
        logger.info(f"用户 '{user_id}' 注册新设备 '{device_id}' 成功 (关联AdsPower账号: {adspower_account.username}, 订阅类型: {subscription_type})")
        return True, device, "设备注册成功"
    
    def verify_device(self, user_id, device_id):
        """验证设备是否属于用户且有效"""
        device = Device.query.filter_by(
            user_id=user_id,
            device_id=device_id
        ).first()
        
        if not device:
            # Add logging
            logger.warning(f"设备验证失败：设备 '{device_id}' 未注册或不属于用户 '{user_id}'")
            return False, None, "设备未注册"
        
        # 检查用户订阅是否有效
        subscription = self.auth_service.get_user_subscription(user_id)
        if not subscription:
            # Add logging
            logger.warning(f"设备验证失败：用户 '{user_id}' (设备 '{device_id}') 订阅无效或已过期")
            # Should we deactivate the device here?
            # device.status = 'inactive'
            # db.session.add(device)
            # db.session.commit()
            return False, None, "用户订阅已过期"
        
        # 更新设备活跃时间
        device.last_active = datetime.utcnow()
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            # Log commit error but proceed with verification success
            logger.error(f"更新设备 '{device_id}' (用户 '{user_id}') 活跃时间时数据库提交失败: {e}", exc_info=True)
        
        # Log successful verification
        # logger.info(f"设备验证成功：设备 '{device_id}' (用户 '{user_id}')")
        return True, device, "设备验证成功"
    
    def get_device_info(self, device_id):
        """获取设备详细信息，包括关联的账号"""
        device = Device.query.filter_by(device_id=device_id).first()
        if not device:
            logger.warning(f"获取设备信息失败：设备ID '{device_id}' 未注册")
            return False, None, "设备未注册"
        
        adspower_account = AdspowerAccount.query.get(device.adspower_account_id)
        if not adspower_account:
            # This indicates data inconsistency
            logger.error(f"获取设备信息失败：设备 '{device_id}' 关联的AdsPower账号ID '{device.adspower_account_id}' 不存在")
            return False, None, "关联的ADSpower账号不存在"
        
        result = {
            "device": {
                "id": device.id,
                "device_id": device.device_id,
                "device_name": device.device_name,
                "device_type": device.device_type,
                "last_login": device.last_login.isoformat() if device.last_login else None,
                "created_at": device.created_at.isoformat() if device.created_at else None
            },
            "adspower_account": {
                "id": adspower_account.id,
                "username": adspower_account.username,
                # "api_key": adspower_account.api_key # Consider if exposing API key is safe here
            }
        }
        
        logger.info(f"获取设备信息成功：设备ID '{device_id}' (用户: {device.user_id}, AdsPower账号: {adspower_account.username})")
        return True, result, "获取设备信息成功"


class TwoFactorAuthService:
    """二因素认证服务，处理TOTP验证码和备用码生成"""
    
    def generate_totp_secret(self):
        """生成TOTP密钥"""
        return pyotp.random_base32()
    
    def get_totp_uri(self, secret, account_name, issuer="ADSpower共享平台"):
        """获取TOTP URI，用于生成二维码"""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=account_name, issuer_name=issuer)
    
    def verify_totp(self, secret, code):
        """验证TOTP验证码"""
        totp = pyotp.TOTP(secret)
        # Add logging for verification attempt
        logger.debug(f"尝试验证TOTP代码：密钥 '{secret[:4]}...', 代码 '{code}'")
        verified = totp.verify(code, valid_window=TOTP_VERIFICATION_TIMEOUT // 30)  # 默认30秒一个窗口
        if verified:
            logger.info(f"TOTP验证成功：密钥 '{secret[:4]}...'")
        else:
            logger.warning(f"TOTP验证失败：密钥 '{secret[:4]}...', 代码 '{code}'")
        return verified
    
    def generate_backup_codes(self, count=10):
        """生成备用码"""
        codes = []
        for i in range(count):
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            codes.append(code)
        logger.info(f"已生成 {len(codes)} 个备用码")
        return codes

    @staticmethod
    def generate_2fa_code(secret):
        """生成2FA验证码
        
        Args:
            secret: TOTP密钥
            
        Returns:
            (code, expires_in): 验证码和有效期（秒）
        """
        if not secret:
            logger.warning("生成2FA验证码失败：未提供TOTP密钥")
            return None, 0
        
        try:
            totp = pyotp.TOTP(secret)
            code = totp.now()
            
            # 计算剩余有效期
            now = datetime.now()
            step = 30  # TOTP默认时间步长为30秒
            expires_in = step - (now.timestamp() % step)
            
            logger.debug(f"为密钥 '{secret[:4]}...' 生成2FA验证码 '{code}'，有效期剩余 {int(expires_in)} 秒")
            return code, int(expires_in)
        except Exception as e:
            logger.error(f"生成2FA验证码时发生异常：密钥 '{secret[:4]}...' ({e})")
            return None, 0 