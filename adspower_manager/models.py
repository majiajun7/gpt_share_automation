from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import json
from config import TRIAL_PERIOD_DAYS
import math
import logging
from sqlalchemy.types import Text # Import Text type

# 配置日志
logger = logging.getLogger(__name__)

# 初始化SQLAlchemy和Bcrypt
db = SQLAlchemy()
bcrypt = Bcrypt()

# 邮箱验证码模型
class EmailVerification(db.Model):
    """邮箱验证码模型"""
    
    __tablename__ = 'email_verifications'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    code_type = db.Column(db.String(20), nullable=False)  # register, login, reset
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    
    def is_expired(self):
        """检查验证码是否已过期"""
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f"<EmailVerification {self.email} {self.code_type}>"

class User(db.Model):
    """用户模型，存储用户基本信息"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # 邮箱验证状态
    is_email_verified = db.Column(db.Boolean, default=False)
    email_verified_at = db.Column(db.DateTime, nullable=True)
    
    subscriptions = db.relationship('Subscription', backref='user', lazy=True)
    devices = db.relationship('Device', lazy=True)
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def verify_email(self):
        self.is_email_verified = True
        self.email_verified_at = datetime.utcnow()
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    def __repr__(self):
        return f'<User {self.email}>'

class Subscription(db.Model):
    """订阅模型，管理用户订阅状态"""
    __tablename__ = 'subscriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    plan = db.Column(db.String(50), nullable=False)  # 订阅计划类型
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    payment_id = db.Column(db.String(100))  # 支付ID
    price = db.Column(db.Float)  # 价格
    max_devices = db.Column(db.Integer, default=1)  # 最大设备数
    chatgpt_account_id = db.Column(db.Integer, db.ForeignKey('chatgpt_accounts.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def is_expired(self):
        """检查订阅是否已过期"""
        return datetime.utcnow() > self.end_date
    
    def extend(self, days):
        """延长订阅天数
        
        Args:
            days: 要延长的天数
            
        Returns:
            新的到期日期
        """
        # 如果订阅已过期，从当前时间开始计算
        if self.is_expired():
            self.start_date = datetime.utcnow()
            self.end_date = self.start_date + timedelta(days=days)
        else:
            # 如果订阅未过期，从原到期日开始延长
            self.end_date = self.end_date + timedelta(days=days)
        
        return self.end_date
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'plan': self.plan,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'payment_id': self.payment_id,
            'price': self.price,
            'max_devices': self.max_devices,
            'chatgpt_account_id': self.chatgpt_account_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        status = "有效" if not self.is_expired() else "已过期"
        return f'<订阅 #{self.id} ({self.plan}) - {status}>'

class ChatGPTAccount(db.Model):
    """ChatGPT账号模型，存储ChatGPT账号信息"""
    __tablename__ = 'chatgpt_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), nullable=False, unique=True)
    username = db.Column(db.String(64))
    password = db.Column(db.String(128), nullable=False)
    totp_secret = db.Column(db.String(128))  # 2FA密钥
    is_active = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 分配给哪个用户
    assigned_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    max_users = db.Column(db.Integer, default=50)  # 最大用户数
    current_users = db.Column(db.Integer, default=0)  # 当前使用该账号的用户数
    
    def __repr__(self):
        return f'<ChatGPTAccount {self.email}>'
    
    def to_dict(self):
        """将对象转为字典"""
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'is_active': self.is_active,
            'user_id': self.user_id,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'max_users': self.max_users,
            'current_users': self.current_users
        }

class AdspowerAccount(db.Model):
    """ADSpower账号模型，存储ADSpower账号信息"""
    __tablename__ = 'adspower_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    totp_secret = db.Column(db.String(128))  # 2FA密钥
    api_key = db.Column(db.String(128))  # API密钥
    is_active = db.Column(db.Boolean, default=True)
    current_devices = db.Column(db.Integer, default=0)  # 当前使用该账号的设备数
    max_devices = db.Column(db.Integer, default=10)  # 最大设备数限制
    last_login = db.Column(db.DateTime)
    cookies = db.Column(db.Text, nullable=True) # 新增: 存储Cookies JSON字符串
    remarks = db.Column(db.Text) # 保留remarks字段
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关联的订阅类型
    subscription_type = db.Column(db.String(32))  # monthly, student, trial, basic等
    
    def __repr__(self):
        return f'<AdspowerAccount {self.username}>'

    def has_capacity(self):
        """检查是否还有设备容量"""
        return self.current_devices < self.max_devices

class Device(db.Model):
    """设备模型，存储用户的设备信息"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    adspower_account_id = db.Column(db.Integer, db.ForeignKey('adspower_accounts.id'), nullable=False)
    
    device_name = db.Column(db.String(100), nullable=True) # 设备名称 (例如 'John's Windows PC')
    device_ip = db.Column(db.String(50), nullable=True) # 设备注册时的IP
    device_type = db.Column(db.String(50), nullable=True) # 设备类型 (例如 'Windows', 'Mac', 'Android') - 根据 AdsPower 解析
    # status = db.Column(db.String(20), default='active', nullable=False) # 设备状态: active, inactive, expired
    last_login = db.Column(db.DateTime, default=datetime.utcnow) # 最后登录时间
    last_active = db.Column(db.DateTime, default=datetime.utcnow) # 最后活跃时间 (例如 API 调用)
    created_at = db.Column(db.DateTime, default=datetime.utcnow) # 创建时间
    # extra_info = db.Column(Text, nullable=True) # 存储JSON格式的额外信息
    
    user = db.relationship('User')
    adspower_account = db.relationship('AdspowerAccount', backref=db.backref('devices', lazy=True))
    
    def __repr__(self):
        return f'<Device {self.device_name or self.id} (User: {self.user_id})>'

    # def set_extra_info(self, info_dict):
    #     \"\"\"将字典序列化为JSON并存储\"\"\"
    #     try:
    #         self.extra_info = json.dumps(info_dict)
    #     except TypeError as e:
    #         logger.error(f"序列化设备额外信息失败 (Device ID: {self.device_id}): {e}")
    #         self.extra_info = "{}" # 存入空JSON对象以避免None

    # def get_extra_info(self):
    #     \"\"\"从JSON字符串反序列化为字典\"\"\"
    #     if not self.extra_info:
    #         return {}
    #     try:
    #         return json.loads(self.extra_info)
    #     except json.JSONDecodeError as e:
    #         logger.error(f"反序列化设备额外信息失败 (Device ID: {self.device_id}): {e}")
    #         return {} # 返回空字典以避免错误

class PaymentRecord(db.Model):
    """支付记录"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)  # 支付金额
    payment_method = db.Column(db.String(50))  # 支付方式：支付宝/微信等
    transaction_id = db.Column(db.String(128))  # 交易号
    payment_status = db.Column(db.String(20))  # 支付状态
    payment_time = db.Column(db.DateTime)  # 支付时间
    subscription_days = db.Column(db.Integer)  # 购买的订阅天数
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关联
    user = db.relationship('User', backref='payment_records')
    
    def __repr__(self):
        return f'<Payment {self.id} User:{self.user_id} Amount:{self.amount}>'

class LoginSession(db.Model):
    """登录会话记录"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    adspower_account_id = db.Column(db.Integer, db.ForeignKey('adspower_accounts.id'))
    login_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime)
    completed_time = db.Column(db.DateTime)  # 登录完成时间
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    login_status = db.Column(db.String(20))  # pending, active, completed, expired
    device_info = db.Column(db.Text)  # 设备信息，JSON格式
    session_duration_seconds = db.Column(db.Integer, default=120)  # 会话有效期（秒）
    initial_devices_count = db.Column(db.Integer, nullable=True)  # 初始设备数量，用于检测登录成功
    initial_devices_info = db.Column(db.Text, nullable=True)  # 存储初始设备信息的JSON字符串
    known_devices = db.Column(db.Text) # Storing list of known device IDs/hashes as JSON string
    expiration_timestamp = db.Column(db.DateTime, nullable=False)
    known_devices_snapshot = db.Column(db.Text, nullable=True) # <--- 添加此行: 存储本次登录 *开始时* 获取的设备列表 JSON 快照
    
    # 关联
    user = db.relationship('User', backref='login_sessions', lazy=True)
    adspower_account = db.relationship('AdspowerAccount', backref='login_sessions', lazy=True)
    
    def get_remaining_seconds(self):
        """获取会话剩余有效时间（秒）"""
        if self.login_status == 'completed' or self.login_status == 'expired':
            return 0
            
        elapsed = (datetime.utcnow() - self.login_time).total_seconds()
        remaining = self.session_duration_seconds - int(elapsed)
        
        # 如果会话已经过期但状态未更新
        if remaining <= 0:
            self.login_status = 'expired'
            return 0
            
        return remaining
    
    def __repr__(self):
        return f'<Session {self.id} User:{self.user_id}>'

class Payment(db.Model):
    """支付记录模型，存储用户的支付信息"""
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.String(64), nullable=False, unique=True)  # 支付ID
    order_id = db.Column(db.String(64), nullable=False, unique=True)  # 订单号（与payment_id相同）
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)  # 支付金额
    currency = db.Column(db.String(10), default='CNY')  # 货币类型
    payment_method = db.Column(db.String(32), nullable=False)  # 支付方式：alipay, wechat等
    status = db.Column(db.String(32), default='pending')  # pending, completed, cancelled, refunded, error
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscriptions.id'))  # 关联的订阅ID
    transaction_id = db.Column(db.String(128))  # 第三方支付交易号
    plan_id = db.Column(db.String(32))  # 购买的订阅计划ID
    subscription_days = db.Column(db.Integer, default=30)  # 购买的订阅天数
    remarks = db.Column(db.Text)
    
    # 与用户的关联
    user = db.relationship('User', backref='payments')
    
    def __repr__(self):
        return f'<Payment {self.payment_id} - {self.status}>'

class UserAdspowerAccount(db.Model):
    """用户-ADSpower账号关联表"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    adspower_account_id = db.Column(db.Integer, db.ForeignKey('adspower_accounts.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<UserAdspower User:{self.user_id} Account:{self.adspower_account_id}>'

class SubscriptionType(db.Model):
    """订阅类型模型，存储不同的订阅套餐信息"""
    __tablename__ = 'subscription_types'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)  # 类型代码，如monthly、student
    name = db.Column(db.String(64), nullable=False)  # 显示名称，如月付会员、学生会员
    max_devices = db.Column(db.Integer, default=1)  # 最大设备数量
    price = db.Column(db.Float, default=0)  # 价格
    discount = db.Column(db.Integer, default=100)  # 折扣百分比，例如90表示九折
    days = db.Column(db.Integer, default=30)  # 订阅有效期天数
    requirements = db.Column(db.Text)  # 适用条件，例如需要学生证
    is_public = db.Column(db.Boolean, default=True)  # 是否在购买页面公开显示
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<SubscriptionType {self.code}>'

# def extend_subscription(user_id, plan_code, payment_id, price):
#     """延长用户的订阅
#     
#     Args:
#         user_id: 用户ID
#         plan_code: 订阅计划代码
#         payment_id: 支付ID
#         price: 价格
#         
#     Returns:
#         活跃的Subscription对象或None
#     """
#     try:
#         # 获取当前活跃的订阅
#         active_sub = Subscription.query.filter(
#             Subscription.user_id == user_id,
#             Subscription.end_date > datetime.utcnow()
#         ).order_by(
#             Subscription.end_date.desc()  # 获取结束时间最晚的订阅
#         ).first()
# 
#         if active_sub:
#             # 如果已有相同类型的活跃订阅，则延长订阅
#             if active_sub.plan == plan_code:
#                 new_end_date = active_sub.extend(subscription_type.days)
#                 active_sub.payment_id = payment_id
#                 active_sub.price = price if price is not None else subscription_type.price
#                 db.session.commit()
# 
#                 logger.info(f"已延长用户 {user_id} 的订阅，新到期时间: {new_end_date}")
#                 return active_sub, "订阅已续期"
# 
#         # 创建新订阅
#         now = datetime.utcnow()
#         subscription = Subscription(
#             user_id=user_id,
#             plan=plan_code,
#             start_date=now,
#             end_date=now + timedelta(days=subscription_type.days),
#             payment_id=payment_id,
#             price=price if price is not None else subscription_type.price,
#             max_devices=subscription_type.max_devices,
#             chatgpt_account_id=subscription_type.id,
#             created_at=now,
#             updated_at=now
#         )
#         db.session.add(subscription)
#         db.session.commit()
# 
#         logger.info(f"新订阅创建成功，用户 {user_id} 的订阅计划: {plan_code}")
#         return subscription, "新订阅创建成功"
# 
#     except Exception as e:
#         logger.error(f"创建或延长订阅失败: {str(e)}")
#         db.session.rollback()
#         return None, f"创建或延长订阅失败: {str(e)}" 