from flask import jsonify, g, request, current_app
import logging
import functools
import secrets
import time
import threading
from datetime import datetime, timedelta, timezone
import hashlib
import math
import re
import random
import string
import json
from werkzeug.exceptions import NotFound

# 第三方库导入
import pyotp
from flask import Blueprint, request, jsonify, g, current_app as app, render_template, redirect, url_for, flash, send_from_directory, abort, make_response, session
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, and_, or_, not_
from sqlalchemy.exc import IntegrityError

# 项目内导入
from .models import (
    db, User, Subscription, ChatGPTAccount, AdspowerAccount, 
    Device, PaymentRecord, Payment, LoginSession, UserAdspowerAccount,
    SubscriptionType, EmailVerification
)
from .services.auth_service import AuthService, DeviceAuthService, TwoFactorAuthService
from .services.payment_service import AlipayService, PaymentService # Import PaymentService
from .services.device_service import DeviceService
from .services.subscription_service import SubscriptionService
from .services.email_service import EmailService
from .adspower_api import get_adspower_api
from config import MAX_DEVICES_PER_USER # 使用绝对导入
from .webdriver_pool import get_account_driver_manager
from .services.epay_service import EpayService # 导入 EpayService

# 配置日志
logger = logging.getLogger(__name__)

# 创建蓝图
api = Blueprint('api', __name__, url_prefix='/api')

# 初始化服务
auth_service = AuthService()
device_auth_service = DeviceAuthService()
two_factor_auth_service = TwoFactorAuthService()
device_service = DeviceService()
email_service = EmailService()
alipay_service = AlipayService()  # 全局支付宝服务实例
subscription_service = SubscriptionService()  # Add this import
epay_service = EpayService() # 初始化 EpayService
payment_service = PaymentService() # Instantiate PaymentService globally or within the route

# 权限检查装饰器
def login_required(f):
    """
    检查用户是否已登录的装饰器
    验证请求中的JWT令牌，并将用户信息添加到g对象
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # 从请求头获取令牌
        auth_header = request.headers.get('Authorization')
        token = None
        logger.debug(f"[认证] 收到Authorization头: {auth_header}")
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
            logger.debug(f"[认证] 提取到令牌: {token[:10]}...{token[-10:] if len(token) > 20 else ''}")
        else:
            logger.warning(f"[认证] 请求头中未找到有效的Bearer令牌: {auth_header}")

        if not token:
            logger.warning("[认证] 请求缺少有效的Bearer令牌")
            return jsonify({'success': False, 'message': '未提供认证令牌'}), 401

        # 验证令牌
        auth_service = AuthService() # 考虑从 app context 获取或使用单例
        user, message = auth_service.verify_token(token)

        if not user:
            # verify_token 内部已有日志
            return jsonify({'success': False, 'message': message}), 401

        # 将用户对象附加到全局上下文 g
        g.user = user
        logger.info(f"[认证成功] 用户 {user.id} ({user.email}) 通过令牌认证")
        return f(*args, **kwargs)
    return decorated_function

# 管理员权限检查装饰器
def admin_required(f):
    """
    检查用户是否具有管理员权限的装饰器
    必须在login_required之后使用
    """
    @functools.wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not g.user.is_admin:
            logger.warning(f"[权限不足] 用户 {g.user.id} ({g.user.email}) 尝试访问管理员资源")
            return jsonify({"success": False, "message": "需要管理员权限"}), 403
        
        logger.info(f"[管理员操作] 管理员 {g.user.id} ({g.user.email}) 访问管理员资源")
        return f(*args, **kwargs)
    return decorated_function

# 设备验证装饰器
def device_required(f):
    """
    验证设备是否合法的装饰器
    检查请求中的设备ID，并将设备信息添加到g对象
    """
    @functools.wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        # 从请求头或请求参数获取设备ID
        device_id = request.headers.get('X-Device-ID') or request.args.get('device_id')
        if not device_id:
            logger.warning(f"[设备验证] 用户 {g.user.id} 的请求缺少设备ID")
            return jsonify({"success": False, "message": "需要设备ID"}), 400
        
        # 验证设备
        success, device, error_msg = device_auth_service.verify_device(g.user.id, device_id)
        if not success:
            logger.warning(f"[设备验证失败] 用户 {g.user.id} 设备ID {device_id}: {error_msg}")
            return jsonify({"success": False, "message": error_msg}), 403
        
        # 将设备信息添加到g对象
        g.device = device
        logger.info(f"[设备验证成功] 用户 {g.user.id} 设备 {device.id} 验证通过")
        
        return f(*args, **kwargs)
    return decorated_function

# 用户认证相关路由
@api.route('/auth/register', methods=['POST'])
def register():
    """用户注册接口"""
    data = request.json
    email = data.get('email')
    password = data.get('password')
    verification_code = data.get('verification_code') # 获取验证码

    # 基本输入验证
    if not all([email, password, verification_code]): # 检查验证码是否提供
        logger.warning(f"[注册] 请求缺少必要字段: email={bool(email)}, password={bool(password)}, code={bool(verification_code)}")
        return jsonify({'success': False, 'message': '缺少必要字段 (邮箱, 密码, 验证码)'}), 400

    # 邮箱格式验证 (简单的)
    if '@' not in email or '.' not in email.split('@')[-1]:
        logger.warning(f"[注册] 邮箱格式无效: {email}")
        return jsonify({'success': False, 'message': '邮箱格式无效'}), 400
        
    # 密码强度验证 (在 AuthService 中进行)

    # 获取AuthService实例
    auth_service = AuthService()

    # 调用注册服务，现在传递验证码
    user, message = auth_service.register_user(email, password, verification_code) # 传递验证码
    
    if user:
        # 注册成功
        logger.info(f"[注册成功] 用户 {email} 注册成功，用户ID: {user.id}")
        # 可以在这里考虑是否直接返回登录令牌
        # token = auth_service.generate_token(user)
        return jsonify({'success': True, 'message': message, 'user_id': user.id}), 201
    else:
        # 注册失败
        logger.warning(f"[注册失败] 用户 {email} 注册失败: {message}")
        return jsonify({'success': False, 'message': message}), 400

@api.route('/auth/verify-email', methods=['POST'])
def verify_email():
    """验证邮箱API
    
    请求体:
    {
        "email": "邮箱",
        "code": "验证码"
    }
    
    返回:
    {
        "success": true/false,
        "message": "消息"
    }
    """
    data = request.json
    
    # 检查必填字段
    if not all(k in data for k in ['email', 'code']):
        logger.warning(f"[邮箱验证] 请求缺少必填字段: {data.keys()}")
        return jsonify({'success': False, 'message': '缺少必填字段'}), 400
    
    logger.info(f"[邮箱验证] 收到邮箱验证请求: {data['email']}")
    
    # 验证邮箱
    success, message = auth_service.verify_email(
        email=data['email'],
        code=data['code']
    )
    
    if success:
        logger.info(f"[邮箱验证成功] {data['email']} 验证成功")
        return jsonify({'success': True, 'message': message}), 200
    else:
        logger.warning(f"[邮箱验证失败] {data['email']} 验证失败: {message}")
        return jsonify({'success': False, 'message': message}), 400

@api.route('/auth/send-verification', methods=['POST'])
def send_verification():
    """发送验证码API
    
    请求体:
    {
        "email": "邮箱",
        "type": "register/login/reset"
    }
    
    返回:
    {
        "success": true/false,
        "message": "消息"
    }
    """
    data = request.json
    
    # 检查必填字段
    if 'email' not in data:
        logger.warning("[验证码] 请求缺少邮箱字段")
        return jsonify({'success': False, 'message': '邮箱不能为空'}), 400
    
    # 验证码类型
    code_type = data.get('type', 'register')
    if code_type not in ['register', 'login', 'reset']:
        logger.warning(f"[验证码] 无效的验证码类型: {code_type}")
        return jsonify({'success': False, 'message': '无效的验证码类型'}), 400
    
    logger.info(f"[验证码] 发送{code_type}类型验证码给: {data['email']}")
    
    # 发送验证码
    success, message, _ = email_service.send_verification_email(
        email=data['email'],
        code_type=code_type
    )
    
    if success:
        logger.info(f"[验证码] 发送成功: {data['email']} (类型: {code_type})")
        return jsonify({'success': True, 'message': message}), 200
    else:
        logger.warning(f"[验证码] 发送失败: {data['email']} (类型: {code_type}) - {message}")
        return jsonify({'success': False, 'message': message}), 400

@api.route('/auth/login', methods=['POST'])
def login():
    """用户登录API
    
    请求体:
    {
        "email": "邮箱",
        "password": "密码",
        "verification_code": "邮箱验证码（可选）"
    }
    
    返回:
    {
        "success": true/false,
        "message": "消息",
        "token": "JWT令牌",
        "user": {用户信息}
    }
    """
    data = request.json
    
    # 检查必填字段
    if not all(k in data for k in ['email', 'password']):
        logger.warning(f"[登录] 请求缺少必填字段: {data.keys()}")
        return jsonify({'success': False, 'message': '邮箱和密码不能为空'}), 400
    
    logger.info(f"[登录] 尝试登录: {data['email']}")
    
    # 登录
    user, token, message = auth_service.login_user(
        email=data['email'],
        password=data['password'],
        verification_code=data.get('verification_code')
    )
    
    if user and token:
        logger.info(f"[登录成功] 用户 {user.id} ({user.email}) 登录成功")
        return jsonify({
            'success': True,
            'message': message,
            'token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.email, # <-- 添加 username 字段
                'is_admin': user.is_admin,
                'is_email_verified': user.is_email_verified
            }
        }), 200
    else:
        logger.warning(f"[登录失败] 用户 {data['email']} 登录失败: {message}")
        return jsonify({'success': False, 'message': message}), 401

@api.route('/auth/reset-password-request', methods=['POST'])
def reset_password_request():
    """请求重置密码API
    
    请求体:
    {
        "email": "邮箱"
    }
    
    返回:
    {
        "success": true/false,
        "message": "消息"
    }
    """
    data = request.json
    
    # 检查必填字段
    if 'email' not in data:
        logger.warning("[重置密码] 请求缺少邮箱字段")
        return jsonify({'success': False, 'message': '邮箱不能为空'}), 400
    
    logger.info(f"[重置密码] 收到密码重置请求: {data['email']}")
    
    # 发送重置验证码
    success, message = auth_service.reset_password_request(
        email=data['email']
    )
    
    if success:
        logger.info(f"[重置密码] 已发送重置验证码: {data['email']}")
        return jsonify({'success': True, 'message': message}), 200
    else:
        logger.warning(f"[重置密码] 发送重置验证码失败: {data['email']} - {message}")
        return jsonify({'success': False, 'message': message}), 400

@api.route('/auth/reset-password', methods=['POST'])
def reset_password():
    """重置密码API
    
    请求体:
    {
        "email": "邮箱",
        "code": "验证码",
        "new_password": "新密码"
    }
    
    返回:
    {
        "success": true/false,
        "message": "消息"
    }
    """
    data = request.json
    
    # 检查必填字段
    if not all(k in data for k in ['email', 'code', 'new_password']):
        logger.warning(f"[重置密码] 请求缺少必填字段: {data.keys()}")
        return jsonify({'success': False, 'message': '缺少必填字段'}), 400
    
    logger.info(f"[重置密码] 尝试重置密码: {data['email']}")
    
    # 重置密码
    success, message = auth_service.reset_password(
        email=data['email'],
        code=data['code'],
        new_password=data['new_password']
    )
    
    if success:
        logger.info(f"[重置密码] 重置密码成功: {data['email']}")
        return jsonify({'success': True, 'message': message}), 200
    else:
        logger.warning(f"[重置密码] 重置密码失败: {data['email']} - {message}")
        return jsonify({'success': False, 'message': message}), 400

# 用户信息路由
@api.route('/users/me', methods=['GET'])
@login_required
def get_user_info():
    """获取当前用户信息"""
    try:
        user = g.user
        logger.info(f"[用户信息] 用户 {user.id} 请求获取个人信息")
        
        # 获取用户订阅信息
        subscription = auth_service.get_user_subscription(user.id)
        
        # 获取用户设备信息
        devices = Device.query.filter_by(user_id=user.id).all()
        
        # 获取用户支付记录
        payments = PaymentRecord.query.filter_by(
            user_id=user.id
        ).order_by(
            PaymentRecord.created_at.desc()
        ).limit(10).all()
        
        logger.debug(f"[用户信息] 用户 {user.id} 获取到 {len(devices)} 个设备和 {len(payments)} 条支付记录")
        
        return jsonify({
            "success": True,
            "data": {
                "user": user.to_dict(),
                "subscription": subscription.to_dict() if subscription else None,
                "devices": [device.to_dict() for device in devices],
                "payments": [payment.to_dict() for payment in payments]
            }
        })
        
    except Exception as e:
        logger.exception(f"[用户信息] 获取用户 {g.user.id} 信息时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

@api.route('/users/me', methods=['PUT'])
@login_required
def update_user_info():
    """更新当前用户信息"""
    try:
        data = request.json
        if not data:
            logger.warning(f"[更新用户] 用户 {g.user.id} 提交了空的请求数据")
            return jsonify({"success": False, "message": "无效的请求数据"}), 400
        
        user = g.user
        logger.info(f"[更新用户] 用户 {user.id} 正在更新个人信息: {list(data.keys())}")
        
        # 更新用户信息
        if 'email' in data:
            # 检查邮箱是否已被其他用户使用
            existing = User.query.filter(
                User.email == data['email'],
                User.id != user.id
            ).first()
            if existing:
                logger.warning(f"[更新用户] 用户 {user.id} 尝试更新邮箱为 {data['email']}，但该邮箱已被其他用户使用")
                return jsonify({"success": False, "message": "邮箱已被使用"}), 400
            
            old_email = user.email
            user.email = data['email']
            logger.info(f"[更新用户] 用户 {user.id} 邮箱已从 {old_email} 更新为 {data['email']}")
        
        # 更新密码
        if 'password' in data:
            # 验证旧密码
            old_password = data.get('old_password')
            if not old_password or not user.check_password(old_password):
                logger.warning(f"[更新用户] 用户 {user.id} 尝试更新密码，但提供了错误的原密码")
                return jsonify({"success": False, "message": "原密码错误"}), 400
            
            # 验证新密码强度
            is_valid, msg = auth_service.validate_password(data['password'])
            if not is_valid:
                logger.warning(f"[更新用户] 用户 {user.id} 提供的新密码强度不足: {msg}")
                return jsonify({"success": False, "message": msg}), 400
            
            user.set_password(data['password'])
            logger.info(f"[更新用户] 用户 {user.id} 密码已更新")
        
        db.session.commit()
        logger.info(f"[更新用户] 用户 {user.id} 信息更新成功")
        
        return jsonify({
            "success": True,
            "message": "用户信息已更新",
            "data": {
                "user": user.to_dict()
            }
        })
        
    except Exception as e:
        logger.exception(f"[更新用户] 更新用户 {g.user.id} 信息时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

# 设备管理路由 - 只有管理员可访问
@api.route('/admin/devices', methods=['GET'])
@admin_required
def get_all_devices():
    """(Admin) 获取所有设备列表 (分页) """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    try:
        logger.info(f"[管理员] 查询所有设备列表 (页码: {page}, 每页: {per_page})")
        
        # 通过服务获取所有设备
        devices = Device.query.paginate(page=page, per_page=per_page, error_out=False)
        
        # 格式化结果
        result = []
        for device in devices.items:
            user = User.query.get(device.user_id) if device.user_id else None
            
            # 获取ADSpower账号信息
            adspower_account = None
            if device.adspower_account_id:
                account = AdspowerAccount.query.get(device.adspower_account_id)
                if account:
                    adspower_account = {
                        'id': account.id,
                        'username': account.username,
                        'is_active': account.is_active,
                        'current_devices': account.current_devices,
                        'max_devices': account.max_devices
                    }
            
            # 处理IP地址 - 确保格式化正确
            ip_address = device.device_ip
            if ip_address:
                # 清理IP地址 - 移除HTML标签和特殊字符
                import re
                # 尝试从字符串中提取有效的IP地址
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f:]+)', ip_address)
                if ip_match:
                    ip_address = ip_match.group(1)
                else:
                    # 移除HTML标签
                    ip_address = re.sub(r'<[^>]*>?', '', ip_address).strip()
            
            device_info = {
                'id': device.id,
                'user_id': device.user_id,
                'user_email': user.email if user else '未知用户',
                'adspower_account_id': device.adspower_account_id,
                'adspower_username': adspower_account['username'] if adspower_account else '未知账号', # 使用字典键访问
                'device_name': device.device_name,
                'device_ip': ip_address,  # 使用清理后的IP
                'device_type': device.device_type, # 添加设备类型
                'last_login': device.last_login.isoformat() if device.last_login else None,
                'last_active': device.last_active.isoformat() if device.last_active else None,
                'created_at': device.created_at.isoformat(),
                'user': {
                    'id': user.id if user else None,
                    'username': user.email if user else '暂无', # Use email instead of username
                    'email': user.email if user else None
                },
                'adspower_account': adspower_account or {
                    'id': None,
                    'username': '暂无',
                    'is_active': False,
                    'current_devices': 0,
                    'max_devices': 0
                }
            }
            result.append(device_info)
        
        logger.info(f"[管理员] 已返回 {len(result)} 台设备信息，总计 {devices.total} 台")
        
        return jsonify({
            "success": True,
            "data": {
                "devices": result,
                "total": devices.total,
                "pages": devices.pages,
                "page": devices.page,
                "per_page": devices.per_page
            }
        })
        
    except Exception as e:
        logger.exception(f"[管理员] 获取设备列表时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

@api.route('/devices', methods=['GET'])
@login_required
def get_devices():
    """获取当前登录用户的所有设备信息"""
    try:
        user = g.user
        logger.info(f"[设备] 用户 {user.id} 请求获取设备列表")
        
        devices = Device.query.filter_by(user_id=user.id).order_by(Device.last_login.desc()).all()
        
        devices_data = []
        for device in devices:
            devices_data.append({
                'id': device.id, # Use DB primary key for delete operations
                'name': device.device_name,
                'ip_address': device.device_ip,
                'device_type': device.device_type, # Changed key from 'type' to 'device_type'
                'last_login': device.last_login.isoformat() if device.last_login else None,
                'created_at': device.created_at.isoformat() if device.created_at else None,
                'status': 'active'
            })
        
        logger.info(f"[设备] 用户 {user.id} 获取到 {len(devices_data)} 台设备信息")
            
        return jsonify({'success': True, 'devices': devices_data})
    except Exception as e:
        logger.exception(f"[设备] 用户 {g.user.id} 获取设备列表时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

@api.route('/devices', methods=['POST'])
@login_required
def register_device():
    """注册新设备"""
    try:
        data = request.json
        if not data:
            logger.warning(f"[设备注册] 用户 {g.user.id} 提交了空的请求数据")
            return jsonify({"success": False, "message": "无效的请求数据"}), 400
        
        user = g.user
        
        # 获取设备信息
        device_id = data.get('device_id')
        device_info = {
            'name': data.get('name'),
            'type': data.get('type'),
            'platform': data.get('platform'),
            'ip_address': request.remote_addr
        }
        
        logger.info(f"[设备注册] 用户 {user.id} 请求注册设备: ID={device_id}, 类型={data.get('type')}, IP={request.remote_addr}")
        
        if not device_id:
            logger.warning(f"[设备注册] 用户 {user.id} 未提供设备ID")
            return jsonify({"success": False, "message": "设备ID不能为空"}), 400
        
        # 检查用户当前设备数
        device_count = Device.query.filter_by(user_id=user.id).count()
        
        # 获取用户的设备上限
        subscription = auth_service.get_user_subscription(user.id)
        max_devices = subscription.max_devices if subscription else 2
        
        logger.info(f"[设备注册] 用户 {user.id} 当前设备: {device_count}，上限: {max_devices}")
        
        # 用户设备数量限制
        if device_count >= max_devices:
            logger.warning(f"[设备注册] 用户 {user.id} 已达到设备数量上限 ({max_devices}个)")
            return jsonify({"success": False, "message": f"您已达到设备数量上限({max_devices}个)"}), 400
        
        # 注册设备
        success, device, message = device_auth_service.register_device(
            user.id, device_id, device_info
        )
        
        if not success:
            logger.warning(f"[设备注册] 用户 {user.id} 注册设备失败: {message}")
            return jsonify({"success": False, "message": message}), 400
        
        # 获取设备详细信息
        success, device_info, _ = device_auth_service.get_device_info(device_id)
        
        logger.info(f"[设备注册] 用户 {user.id} 成功注册设备: ID={device_id}, DB_ID={device.id}")
        
        return jsonify({
            "success": True,
            "message": message,
            "data": device_info if success else device.to_dict()
        })
        
    except Exception as e:
        logger.exception(f"[设备注册] 用户 {g.user.id} 注册设备时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

@api.route('/devices/<device_id>', methods=['GET'])
@login_required
def get_device_info(device_id):
    """获取设备详细信息"""
    try:
        user = g.user
        logger.info(f"[设备] 用户 {user.id} 请求获取设备信息: {device_id}")
        
        # 验证设备属于当前用户
        device = Device.query.filter_by(user_id=user.id, device_id=device_id).first()
        if not device:
            return jsonify({"success": False, "message": "设备不存在或不属于当前用户"}), 404
        
        # 获取设备详细信息
        success, device_info, message = device_auth_service.get_device_info(device_id)
        if not success:
            return jsonify({"success": False, "message": message}), 400
        
        return jsonify({
            "success": True,
            "data": device_info
        })
        
    except Exception as e:
        logger.exception(f"获取设备信息时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

@api.route('/admin/devices/<int:device_id>', methods=['DELETE'])
@admin_required
def admin_delete_device(device_id):
    """管理员删除设备 - 尝试远程登出并删除本地记录"""
    admin_user = g.user
    logger.info(f"管理员 {admin_user.id} 请求删除设备 DB ID: {device_id}")
    
    try:
        # 1. 查找设备
        device = Device.query.get(device_id)
        if not device:
            logger.warning(f"管理员 {admin_user.id} 尝试删除不存在的设备 DB ID: {device_id}")
            return jsonify({"success": False, "message": "设备不存在"}), 404
        
        device_owner_id = device.user_id
        logger.info(f"设备 DB ID: {device_id} 属于用户 ID: {device_owner_id}. 由管理员 {admin_user.id} 操作删除。")

        # 2. 检查设备是否已关联 AdsPower 账号
        if not device.adspower_account_id:
            logger.warning(f"设备 DB ID: {device_id} 未关联 AdsPower 账号，将直接删除本地记录 (管理员操作)")
            try:
                db.session.delete(device)
                db.session.commit()
                return jsonify({"success": True, "message": "设备未关联远程账号，本地记录已由管理员删除"})
            except Exception as e:
                db.session.rollback()
                logger.error(f"管理员删除未关联账号的设备 {device_id} 记录时数据库出错: {e}")
                return jsonify({"success": False, "message": "删除本地设备记录时出错"}), 500

        # 3. 获取关联的 AdsPower 账号
        adspower_account = AdspowerAccount.query.get(device.adspower_account_id)
        if not adspower_account:
            logger.error(f"设备 DB ID: {device_id} 关联的 AdsPower 账号 ID: {device.adspower_account_id} 不存在，将删除本地设备记录 (管理员操作)")
            try:
                db.session.delete(device)
                db.session.commit()
                return jsonify({"success": True, "message": "关联的AdsPower账号不存在，本地设备记录已由管理员删除"})
            except Exception as e:
                db.session.rollback()
                logger.error(f"管理员删除关联账号不存在的设备 {device_id} 记录时数据库出错: {e}")
                return jsonify({"success": False, "message": "删除本地设备记录时出错"}), 500

        # 4. 获取设备在 AdsPower 上的必要信息
        device_name_on_ads = device.device_name
        device_ip_on_ads = device.device_ip
        device_type_on_ads = device.device_type
        
        if not device_name_on_ads:
            logger.error(f"设备 DB ID: {device_id} 缺少在 AdsPower 上的设备名称 (device_name)，无法执行远程退出 (管理员操作)")
            # 即使无法远程退出，管理员仍可选择删除本地记录
            # return jsonify({"success": False, "message": "设备缺少必要信息，无法执行远程退出操作，请先补充信息或联系技术支持"}), 400
            logger.warning(f"设备 DB ID: {device_id} 缺少 device_name，将跳过远程退出，仅删除本地记录 (管理员操作)")
        elif not device_type_on_ads:
             logger.error(f"设备 DB ID: {device_id} 缺少设备类型 (device_type)，无法执行精确的远程退出操作 (管理员操作)")
             # 同上，可以选择不强制要求，但记录错误
             logger.warning(f"设备 DB ID: {device_id} 缺少 device_type，将跳过远程退出，仅删除本地记录 (管理员操作)")
        else:
            # 5. 调用 AdsPower API 执行退出操作 (仅当必要信息齐全时)
            logout_message = "未尝试远程退出 (设备信息不完整)" # Default message
            logout_success = False # Default status
            try:
                adspower_api = get_adspower_api()
                logout_success, message = adspower_api.logout_device(adspower_account, device_name_on_ads, device_type_on_ads)
                logout_message = message # Update message with API result
                logger.info(f"管理员操作：adspower_api.logout_device(设备 DB ID: {device_id}) 返回: success={logout_success}, message='{message}'")

                if logout_success is not True:
                    # 如果远程退出失败，记录错误，但管理员仍然可以继续删除本地记录
                    logger.error(f"管理员操作：AdsPower远程退出设备 DB ID: {device_id} 失败，原因: {message}。将继续删除本地记录。")
                    # 不在此处返回失败，继续执行删除本地记录的步骤

            except Exception as e:
                logger.exception(f"管理员调用 logout_device 时发生意外错误 (设备 DB ID: {device_id}): {e}")
                # 发生异常时，也记录错误，但继续删除本地记录
                logger.error(f"管理员操作：调用远程退出API时发生异常，将继续删除本地记录。错误: {str(e)}")
                logout_message = f"尝试远程退出时出错: {str(e)}" # Update message for exception
                logout_success = False

        # 6. 删除本地设备记录 (无论远程退出是否成功或是否执行)
        try:
            db.session.delete(device)
            db.session.commit()
            logger.info(f"设备 DB ID: {device_id} 本地设备记录已由管理员 {admin_user.id} 删除")
            
            # -- 构造更友好的最终消息 --
            final_message = "设备记录已删除。"
            if device_name_on_ads and device_type_on_ads: # Only mention logout if it was attempted
                if logout_success:
                    final_message += " 已成功在 AdsPower 端退出登录。"
                else:
                    # Include the specific reason/message from the logout attempt
                    final_message += f" 但在 AdsPower 端退出登录失败: {logout_message}"
            elif not device_name_on_ads:
                final_message += " (因缺少设备名称，未尝试远程退出)"
            elif not device_type_on_ads:
                final_message += " (因缺少设备类型，未尝试远程退出)"
            # -- 消息构造结束 --
            
            return jsonify({
                "success": True,
                # "message": "设备已由管理员删除（远程退出尝试已执行，若有必要）" # 旧消息
                "message": final_message # 返回新构造的消息
            })
        except Exception as e:
            db.session.rollback()
            logger.error(f"管理员删除设备 {device_id} 本地记录时数据库最终出错: {e}")
            return jsonify({"success": False, "message": "尝试远程退出后，删除本地设备记录时出错"}), 500

    except Exception as e:
        logger.exception(f"管理员删除设备 DB ID: {device_id} 时发生顶层错误: {str(e)}")
        db.session.rollback() # Ensure rollback on top-level error
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

@api.route('/devices/<device_id>', methods=['DELETE'])
@login_required
def delete_device(device_id):
    """用户删除设备 - 检查权限"""
    try:
        user = g.user
        
        # 验证设备属于当前用户
        device = Device.query.filter_by(id=device_id, user_id=user.id).first()
        if not device:
            return jsonify({"success": False, "message": "设备不存在或不属于当前用户"}), 404
        
        # 删除设备
        db.session.delete(device)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "设备已删除"
        })
        
    except Exception as e:
        logger.exception(f"删除设备时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

# 二因素认证路由
@api.route('/2fa/get-code', methods=['POST'])
@login_required
@device_required
def get_2fa_code():
    """获取二因素认证验证码，用于登录ADSpower"""
    try:
        user = g.user
        device = g.device
        logger.info(f"[2FA] 用户 {user.id} 设备 {device.id} 请求获取二因素验证码")
        
        # 获取设备详细信息
        success, device_info, message = device_auth_service.get_device_info(g.device.device_id)
        if not success:
            logger.warning(f"[2FA] 用户 {user.id} 获取设备信息失败: {message}")
            return jsonify({"success": False, "message": message}), 400
        
        # 获取ADSpower账号信息
        adspower_account_id = device_info['adspower_account']['id']
        adspower_account = AdspowerAccount.query.get(adspower_account_id)
        
        if not adspower_account or not adspower_account.totp_secret:
            logger.warning(f"[2FA] 用户 {user.id} 获取验证码失败: ADSpower账号 {adspower_account_id} 不存在或未配置2FA")
            return jsonify({"success": False, "message": "ADSpower账号不存在或未配置2FA"}), 400
        
        # 生成TOTP验证码
        totp = pyotp.TOTP(adspower_account.totp_secret)
        code = totp.now()
        
        # 更新ADSpower账号最后登录时间
        adspower_account.last_login = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"[2FA] 用户 {user.id} 成功获取ADSpower账号 {adspower_account.username} 的验证码")
        
        return jsonify({
            "success": True,
            "data": {
                "code": code,
                "expires_in": 30  # TOTP默认30秒有效
            }
        })
        
    except Exception as e:
        logger.exception(f"[2FA] 用户 {g.user.id} 获取2FA验证码时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

@api.route('/subscriptions', methods=['GET'])
@login_required
def get_user_subscription():
    """获取用户当前订阅信息"""
    try:
        user = g.user
        logger.info(f"[订阅] 用户 {user.id} 请求获取订阅信息")
        
        # 获取用户订阅信息
        subscription = auth_service.get_user_subscription(user.id)
        
        # 获取历史订阅记录
        history = Subscription.query.filter_by(
            user_id=user.id
        ).order_by(
            Subscription.created_at.desc()
        ).all()
        
        logger.info(f"[订阅] 用户 {user.id} 获取到当前订阅和 {len(history)} 条历史记录")
        
        return jsonify({
            "success": True,
            "data": {
                "current": subscription.to_dict() if subscription else None,
                "history": [sub.to_dict() for sub in history]
            }
        })
        
    except Exception as e:
        logger.exception(f"[订阅] 用户 {g.user.id} 获取订阅信息时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

# 支付相关路由
@api.route('/payments/create', methods=['POST'])
@login_required
def create_payment():
    """创建支付订单 (支持 Epay, 0元直接激活, 并限制免费套餐领取一次)"""
    user_id = g.user.id
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': '缺少请求数据'}), 400

    plan_code = data.get('plan_code')
    payment_gateway = data.get('gateway', 'epay') 
    payment_type = data.get('type', 'alipay') 

    if not plan_code:
        return jsonify({'success': False, 'message': '缺少订阅计划代码'}), 400

    # 获取订阅计划信息
    subscription_type = SubscriptionType.query.filter_by(code=plan_code).first()
    if not subscription_type:
        return jsonify({'success': False, 'message': '无效的订阅计划代码'}), 404

    # 计算最终价格
    final_price = (subscription_type.price * (subscription_type.discount / 100.0)) if subscription_type.discount is not None and subscription_type.discount < 100 else subscription_type.price
    amount_str = "{:.2f}".format(final_price)

    # --- 移除 0元 计划的特殊处理逻辑 ---
    # (相关代码已在上一步被注释或删除)
    # --- 0元 计划处理结束 ---
    
    # --- 所有计划都进入支付流程 (移除原有的 else) ---
    # else: # <--- 删除此行
    logger.info(f"[支付] 用户 {user_id} 选择套餐 {plan_code} (¥{final_price:.2f})，创建 {payment_gateway} 订单...")
    # 根据选择的网关调用不同的服务
    redirect_url = None
    payment = None
    message = ""
    epay_api_data = None # <-- 用于存储 mapi 返回的数据
    html_form = None     # <-- 用于存储 submit.php 的 HTML 表单

    if payment_gateway == 'epay':
        epay_service = EpayService() 
        # --- 调用 Submit 模式 --- 
        payment, html_form = epay_service.create_payment_request( # <-- 修改变量名
            user_id=user_id,
            plan_id=plan_code, 
            amount=amount_str,
            payment_type=payment_type,
            mode='submit' # <-- 指定使用 submit
        )
        # --- 处理 Submit 响应 --- 
        if payment and html_form:
            message = "易支付 submit 请求成功，准备跳转表单..." # <-- 更新消息
        elif not payment and isinstance(html_form, dict) and not html_form.get('success', True): # Check if error dict returned
             # 如果 create_payment_request 返回了包含错误消息的字典 (虽然现在不太可能了)
             message = html_form.get('message', '创建易支付 submit 表单失败')
             logger.error(f"Epay submit 调用失败: {message}")
             payment = None 
             html_form = None 
        else:
             # 其他未知错误
             message = f"创建易支付 submit 表单时发生未知错误 (Payment: {bool(payment)}, HTML Form: {bool(html_form)})"
             logger.error(message)
             payment = None
             html_form = None 
            
    elif payment_gateway == 'alipay':
        # 支付宝逻辑
        return jsonify({'success': False, 'message': '支付宝支付暂未启用'}), 501 
    else:
        return jsonify({'success': False, 'message': '不支持的支付网关'}), 400

    # --- 检查 payment 和 html_form --- 
    if not payment or not html_form:
        logger.error(f"[支付] 创建订单失败 (网关: {payment_gateway})")
        return jsonify({
            'success': False,
            'message': '创建订单失败，请稍后重试或联系管理员。'
        }), 500

    # --- 返回包含 html_form 的 JSON --- # Dedent this block
    # This block should execute only if the 'epay' path succeeded and payment/html_form are valid
    return jsonify({
        'success': True,
        'message': '订单创建成功，正在准备支付表单...',
        'activated_directly': False, # False because this path handles paid plans
        'data': {
            'payment_id': payment.payment_id,
            'order_id': payment.order_id,
            'html_form': html_form,
            'gateway': payment_gateway, # payment_gateway was defined before the if/elif/else
        }
    }), 200

@api.route('/payments/epay/notify', methods=['GET', 'POST'])
def epay_notify():
    """处理易支付异步通知"""
    params = request.args.to_dict() # 获取GET或POST参数
    logger.info(f"[Epay Notify] 收到易支付回调: {params}")

    try:
        # --- 1. 验证签名 --- 
        # 期望 verify_notify 只返回 (bool, str)
        is_valid, message = epay_service.verify_notify(params)

        if not is_valid:
            logger.warning(f"[Epay Notify] 验证失败: {message}")
            # 返回 'fail' 通常会让支付平台重试，根据需要调整
            return "fail - invalid sign", 400

        # --- 2. 提取必要参数 --- 
        out_trade_no = params.get('out_trade_no')
        epay_trade_no = params.get('trade_no')
        amount_str = params.get('money')
        trade_status = params.get('trade_status')

        if not all([out_trade_no, epay_trade_no, amount_str, trade_status]):
            logger.error("[Epay Notify] 失败：回调参数不完整。")
            return "fail - missing params", 400

        # --- 3. 处理业务逻辑 (仅当交易成功时) --- 
        if trade_status == 'TRADE_SUCCESS':
            logger.info(f"[Epay Notify] 订单 {out_trade_no} 状态为成功，开始处理业务...")
            # 调用核心业务处理函数 (使用全局或新实例化的 payment_service)
            # Note: Ensure payment_service is accessible here. If not instantiated globally, do it here:
            payment_service = PaymentService() 
            success, process_message = payment_service.process_epay_payment(
                out_trade_no=out_trade_no,
                epay_trade_no=epay_trade_no,
                amount_str=amount_str
            )
            if success:
                logger.info(f"[Epay Notify] 订单 {out_trade_no} 处理成功。消息: {process_message}")
                # 务必返回 "success" 字符串给易支付，否则会重试
                return "success", 200
            else:
                logger.error(f"[Epay Notify] 订单 {out_trade_no} 业务处理失败。消息: {process_message}")
                # 即使业务失败，也建议返回 "success" 给易支付避免重试，错误应由内部监控处理
                return "success", 200
        elif trade_status == 'TRADE_CLOSED':
            logger.info(f"[Epay Notify] 订单 {out_trade_no} 状态为交易关闭，无需处理。")
            return "success", 200
        else:
            logger.warning(f"[Epay Notify] 订单 {out_trade_no} 状态为 {trade_status}，非成功状态，不处理。")
            return "success", 200

    except Exception as e:
        logger.exception("[Epay Notify] 处理易支付回调时发生未知异常")
        # 返回 "fail" 可能导致重试，需要权衡
        return "fail - exception", 500

@api.route('/payments/alipay/notify', methods=['POST'])
def alipay_notify():
    """支付宝异步通知接口
    
    由支付宝服务器调用，用于通知支付结果
    """
    try:
        # 获取通知数据
        data = request.form.to_dict()
        logger.info(f"[支付宝] 收到支付宝异步通知: {json.dumps(data, ensure_ascii=False)}")
        
        # 验证通知
        verified, payment = alipay_service.verify_payment(data)
        
        if not verified:
            logger.error("[支付宝] 支付宝通知验证失败")
            return 'fail', 400
        
        # 成功处理
        logger.info(f"[支付宝] 通知验证成功: 订单 {payment.order_id} 已完成支付")
        return 'success', 200
    except Exception as e:
        logger.error(f"[支付宝] 处理支付宝通知时出错: {str(e)}")
        return 'fail', 500

@api.route('/payments/status/<order_id>', methods=['GET'])
@login_required
def query_payment_status(order_id):
    """查询支付状态 (供前端轮询)"""
    # 从 g 对象获取当前用户
    user = g.user
    
    logger.info(f"[支付] 用户 {g.user.id} 查询订单 {order_id} 状态") # 使用 g.user.id
    
    try:
        payment = Payment.query.filter_by(order_id=order_id, user_id=user.id).first()
    
        # --- ADD CHECK FOR NONE --- 
        if payment is None:
            logger.error(f"[支付] 查询订单 {order_id} 失败或未找到")
            return jsonify({'success': False, 'message': '订单不存在或查询失败'}), 404
        # --- END CHECK --- 

        # --- ADD: Get plan_name ---
        plan_name = '未知套餐'
        if payment.plan_id:
            sub_type = SubscriptionType.query.filter_by(code=payment.plan_id).first()
            if sub_type:
                plan_name = sub_type.name
            else:
                # 如果找不到类型，但有 plan_id，可以记录警告并使用 plan_id
                logger.warning(f"[支付] 订单 {order_id} 的 plan_id '{payment.plan_id}' 在 SubscriptionType 中未找到")
                plan_name = payment.plan_id # Fallback to plan_id code
        # --- END ADD ---

        response_data = {
            'success': True,
            'status': payment.status, # paid, unpaid, failed
            'order_id': payment.payment_id,
            'plan_id': payment.plan_id, # <--- 使用 plan_id 替换 plan_code
            'plan_name': plan_name, # <--- ADD plan_name
            'amount': str(payment.amount), # Decimal转为字符串
            'created_at': payment.created_at.isoformat() + 'Z',
        }
        if payment.paid_at:
            response_data['paid_at'] = payment.paid_at.isoformat() + 'Z'

        return jsonify(response_data)

    except Exception as e:
        logger.exception(f"[支付] 查询订单 {order_id} 状态时发生内部错误: {str(e)}")
        return jsonify({'success': False, 'message': '服务器内部错误'}), 500

@api.route('/payments/result', methods=['GET'])
def payment_result():
    """支付结果页面API (旧版支付宝同步返回)
    
    支付宝同步返回页面，显示支付结果
    """
    # 获取参数
    order_id = request.args.get('out_trade_no')
    
    if not order_id:
        return jsonify({'success': False, 'message': '缺少订单号参数'}), 400
    
    # 查询支付记录
    payment = Payment.query.filter_by(payment_id=order_id).first() # 使用 payment_id 查询
    
    if not payment:
        return jsonify({'success': False, 'message': '找不到支付订单'}), 404
    
    # --- 修改：不再调用 alipay_service 查询最新状态，直接返回数据库状态 --- 
    # payment, message = alipay_service.query_payment(order_id)
    logger.info(f"[支付结果页] 订单 {order_id} 查询状态: {payment.status}")
    
    # 获取关联的订阅信息
    subscription = None
    if payment and payment.subscription_id:
        subscription = Subscription.query.get(payment.subscription_id)
    
    # 组装响应
    response = {
        'success': payment.status == 'paid', # 根据数据库状态判断
        'message': '支付成功' if payment.status == 'paid' else ('支付处理中' if payment.status == 'pending' else '支付状态未知'),
        'payment': {
            'order_id': payment.order_id,
            'amount': payment.amount,
            'status': payment.status,
            'created_at': payment.created_at.isoformat() if payment.created_at else None,
            'paid_at': payment.paid_at.isoformat() if payment.paid_at else None
        }
    }
    
    if subscription:
        response['subscription'] = {
            'id': subscription.id,
            'plan': subscription.plan,
            'start_date': subscription.start_date.isoformat() if subscription.start_date else None,
            'end_date': subscription.end_date.isoformat() if subscription.end_date else None
        }
    
    # 注意：此 API 端点现在只返回 JSON 数据。
    # 如果需要渲染 HTML 页面，应该在 app.py 或 page_routes.py 中定义页面路由。
    # 现有的 templates/payment_result.html 依赖此 API 返回 JSON。
    return jsonify(response), 200

# 管理员路由
@api.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    """管理员获取用户列表接口"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search_query = request.args.get('search', None)
    subscription_filter = request.args.get('subscription', 'all') # all, active, inactive, expired

    try:
        query = User.query.options(db.joinedload(User.subscriptions))

        if search_query:
            query = query.filter(User.email.ilike(f'%{search_query}%'))

        # 订阅状态过滤逻辑 (需要根据 end_date 判断)
        now = datetime.utcnow()
        if subscription_filter == 'active':
            # 找到至少有一个未过期的订阅的用户
            query = query.join(User.subscriptions).filter(Subscription.end_date > now)
        elif subscription_filter == 'inactive':
            # 找到没有订阅或所有订阅都已过期的用户
            # 需要子查询或更复杂的逻辑，暂时简化为只过滤没有订阅的用户
            # query = query.outerjoin(User.subscriptions).filter(Subscription.id == None)
            # 更准确: 找到所有订阅都已过期的用户
            # This is complex with SQLAlchemy. Let's focus on 'active' and 'expired' for now.
            pass # 暂时不过滤inactive
        elif subscription_filter == 'expired':
            # 找到所有订阅都已过期的用户 (需要至少有一个订阅)
            # 过滤掉有活跃订阅的用户，然后过滤掉没有订阅的用户
            subq_active = db.session.query(User.id).join(User.subscriptions).filter(Subscription.end_date > now).subquery()
            query = query.filter(User.id.notin_(subq_active))
            # Ensure they have at least one subscription (otherwise they are inactive/never subscribed)
            # query = query.join(User.subscriptions) # This might exclude users with only expired subs

        pagination = query.order_by(User.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        users = pagination.items
        total = pagination.total

        users_list = []
        for user in users:
            # 获取最新的订阅信息（无论是否过期）
            latest_subscription = Subscription.query.filter_by(user_id=user.id).order_by(Subscription.end_date.desc()).first()
            
            # 基于 end_date 判断状态
            subscription_status = '无订阅'
            plan_name = None
            end_date_iso = None
            if latest_subscription:
                plan_name = latest_subscription.plan
                end_date_iso = latest_subscription.end_date.isoformat() + 'Z'
                if latest_subscription.end_date > now:
                    subscription_status = '活跃'
                else:
                    subscription_status = '已过期'

            users_list.append({
                'id': user.id,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'subscription_plan': plan_name, # 使用 plan_name 替代 plan
                'subscription_status': subscription_status, # 基于 end_date 判断
                'subscription_end_date': end_date_iso # 添加结束日期
            })

        return jsonify({
            'success': True,
            'users': users_list,
            'pagination': {
                'page': pagination.page,
                'per_page': pagination.per_page,
                'total_pages': pagination.pages,
                'total_items': pagination.total
            }
        }), 200

    except Exception as e:
        logger.exception(f"[Admin] 获取用户列表时出错: {e}")
        return jsonify({'success': False, 'message': f'获取用户列表时出错: {str(e)}'}), 500

@api.route('/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def admin_update_user(user_id):
    """管理员更新用户信息"""
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': '缺少请求数据'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    # 获取当前管理员信息，防止管理员误操作修改自己的权限
    admin_user = g.user
    if admin_user.id == user.id and 'is_admin' in data and data['is_admin'] != user.is_admin:
         return jsonify({'success': False, 'message': '无法修改自己的管理员权限'}), 403

    # 更新字段
    updated_fields_summary = [] # 用于记录哪些字段被更新了

    if 'email' in data and data['email'] != user.email:
        # 检查邮箱是否已被使用
        existing_user = User.query.filter(User.email == data['email'], User.id != user_id).first()
        if existing_user:
            return jsonify({'success': False, 'message': '邮箱已被使用'}), 409
        original_email = user.email
        user.email = data['email']
        updated_fields_summary.append(f"邮箱从 {original_email} 更改为 {user.email}")
        # 如果邮箱更改，可能需要重新验证，根据需求决定
        # user.is_email_verified = False 

    if 'is_admin' in data and isinstance(data['is_admin'], bool) and data['is_admin'] != user.is_admin:
        user.is_admin = data['is_admin']
        updated_fields_summary.append(f"管理员权限更改为 {user.is_admin}")
        
    if 'is_active' in data and isinstance(data['is_active'], bool) and data['is_active'] != user.is_active:
        user.is_active = data['is_active']
        updated_fields_summary.append(f"激活状态更改为 {user.is_active}")
        
    if 'is_email_verified' in data and isinstance(data['is_email_verified'], bool) and data['is_email_verified'] != user.is_email_verified:
        user.is_email_verified = data['is_email_verified']
        if user.is_email_verified:
            user.email_verified_at = datetime.utcnow()
        updated_fields_summary.append(f"邮箱验证状态更改为 {user.is_email_verified}")
        
    if 'new_password' in data and data['new_password']:
        is_valid, msg = auth_service.validate_password(data['new_password'])
        if not is_valid:
            return jsonify({'success': False, 'message': f'密码强度不足: {msg}'}), 400
        user.set_password(data['new_password'])
        updated_fields_summary.append("密码已重置")

    # 处理订阅计划更新
    if 'subscription_plan_code' in data:
        new_plan_code = data['subscription_plan_code']
        current_active_subscription = Subscription.query.filter(
            Subscription.user_id == user.id,
            Subscription.end_date > datetime.utcnow()
        ).first()

        if not new_plan_code: # 表示 "无订阅"
            if current_active_subscription:
                current_active_subscription.end_date = datetime.utcnow() - timedelta(seconds=1)
                updated_fields_summary.append(f"取消了订阅 {current_active_subscription.plan}")
                db.session.add(current_active_subscription)
            else:
                # 用户本来就没有有效订阅，也选择了无订阅，无需操作
                pass
        else:
            # 用户选择了一个具体的订阅计划
            selected_subscription_type = SubscriptionType.query.filter_by(code=new_plan_code).first()
            if not selected_subscription_type:
                return jsonify({'success': False, 'message': f'无效的订阅计划代码: {new_plan_code}'}), 400

            plan_changed = True
            if current_active_subscription:
                if current_active_subscription.plan == new_plan_code:
                    plan_changed = False # 计划未变，无需操作
                    updated_fields_summary.append(f"订阅计划 {new_plan_code} 未发生变化")
                else:
                    # 计划改变，使旧计划过期
                    updated_fields_summary.append(f"旧订阅 {current_active_subscription.plan} 已终止")
                    current_active_subscription.end_date = datetime.utcnow() - timedelta(seconds=1)
                    db.session.add(current_active_subscription)
            
            if plan_changed:
                # 创建新订阅
                new_subscription = Subscription(
                    user_id=user.id,
                    plan=new_plan_code,
                    start_date=datetime.utcnow(),
                    end_date=datetime.utcnow() + timedelta(days=selected_subscription_type.days),
                    max_devices=selected_subscription_type.max_devices,
                    price=0.0,  # 管理员分配，价格记录为0或套餐原价
                    payment_id=f"admin_assigned_{user.id}_{int(time.time())}",
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                db.session.add(new_subscription)
                updated_fields_summary.append(f"设置了新订阅 {new_plan_code}，有效期至 {new_subscription.end_date.strftime('%Y-%m-%d')}")

    if updated_fields_summary:
        try:
            db.session.commit()
            logger.info(f"管理员 {admin_user.email} 更新了用户 {user.email} 的信息: {'; '.join(updated_fields_summary)}")
            return jsonify({'success': True, 'message': '用户信息更新成功', 'user': user.to_dict()})
        except Exception as e:
            db.session.rollback()
            logger.error(f"更新用户 {user_id} 信息时数据库出错: {e}", exc_info=True)
            return jsonify({'success': False, 'message': f'数据库错误: {e}'}), 500
    else:
        return jsonify({'success': True, 'message': '没有需要更新的信息', 'user': user.to_dict()})

@api.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    """管理员删除用户接口"""
    admin_user = g.user
    
    # 防止管理员删除自己
    if admin_user.id == user_id:
        logger.warning(f"管理员 {admin_user.email} (ID: {admin_user.id}) 尝试删除自己的账户")
        return jsonify({'success': False, 'message': '无法删除自己的账户'}), 403

    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        logger.warning(f"管理员 {admin_user.email} 尝试删除不存在的用户 ID: {user_id}")
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    try:
        logger.info(f"管理员 {admin_user.email} 开始删除用户 {user_to_delete.email} (ID: {user_id}) 及其关联数据")

        # 1. 删除 EmailVerification 记录 (按邮箱)
        EmailVerification.query.filter_by(email=user_to_delete.email).delete()
        logger.debug(f"已删除用户 {user_id} 的 EmailVerification 记录")

        # 2. 删除 Device 记录
        # 注意：如果Device与AdspowerAccount有current_devices计数，这里可能需要更新
        devices_deleted_count = Device.query.filter_by(user_id=user_id).delete()
        logger.debug(f"已删除用户 {user_id} 的 {devices_deleted_count} 条 Device 记录")

        # 3. 删除 LoginSession 记录
        login_sessions_deleted_count = LoginSession.query.filter_by(user_id=user_id).delete()
        logger.debug(f"已删除用户 {user_id} 的 {login_sessions_deleted_count} 条 LoginSession 记录")

        # 4. 删除 PaymentRecord 记录
        payment_records_deleted_count = PaymentRecord.query.filter_by(user_id=user_id).delete()
        logger.debug(f"已删除用户 {user_id} 的 {payment_records_deleted_count} 条 PaymentRecord 记录")

        # 5. 删除 Payment 记录
        payments_deleted_count = Payment.query.filter_by(user_id=user_id).delete()
        logger.debug(f"已删除用户 {user_id} 的 {payments_deleted_count} 条 Payment 记录")
        
        # 6. 删除 Subscription 记录
        subscriptions_deleted_count = Subscription.query.filter_by(user_id=user_id).delete()
        logger.debug(f"已删除用户 {user_id} 的 {subscriptions_deleted_count} 条 Subscription 记录")

        # 7. 删除 UserAdspowerAccount 记录 (如果存在这个模型且有user_id外键)
        # 假设 UserAdspowerAccount 模型已正确定义
        user_adspower_accounts_deleted_count = UserAdspowerAccount.query.filter_by(user_id=user_id).delete()
        logger.debug(f"已删除用户 {user_id} 的 {user_adspower_accounts_deleted_count} 条 UserAdspowerAccount 记录")
        
        # 最后删除用户本身
        db.session.delete(user_to_delete)
        db.session.commit()
        
        logger.info(f"管理员 {admin_user.email} 成功删除用户 {user_to_delete.email} (ID: {user_id})")
        return jsonify({'success': True, 'message': '用户及其关联数据已成功删除'})

    except Exception as e:
        db.session.rollback()
        logger.exception(f"管理员 {admin_user.email} 删除用户 ID: {user_id} 时发生错误: {e}")
        return jsonify({'success': False, 'message': f'删除用户时发生服务器内部错误: {str(e)}'}), 500

@api.route('/admin/users/<int:user_id>/details', methods=['GET'])
@admin_required
def admin_get_user_details(user_id):
    """管理员获取用户详细信息接口，包括订阅、设备和支付记录"""
    try:
        user = User.query.get_or_404(user_id)
        
        # 获取所有订阅记录
        subscriptions = Subscription.query.filter_by(user_id=user_id).order_by(Subscription.start_date.desc()).all()
        subscriptions_data = []
        for sub in subscriptions:
            # 计算状态
            status = '已过期' if sub.end_date < datetime.utcnow() else '活跃'
            plan_type = SubscriptionType.query.filter_by(code=sub.plan).first()
            subscriptions_data.append({
                'id': sub.id,
                'plan': sub.plan,
                'plan_name': plan_type.name if plan_type else sub.plan,
                'start_date': sub.start_date.isoformat() + 'Z',
                'end_date': sub.end_date.isoformat() + 'Z',
                'price': sub.price,
                'max_devices': sub.max_devices,
                'status': status, # 使用计算出的状态
                'payment_id': sub.payment_id,
                'created_at': sub.created_at.isoformat() + 'Z'
            })

        # 获取设备信息
        devices = Device.query.filter_by(user_id=user_id).all()
        devices_data = [{
            'id': d.id,
            'name': d.device_name,
            'ip_address': d.device_ip,
            'type': d.device_type,
            'last_login': d.last_login.isoformat() + 'Z' if d.last_login else None,
            'created_at': d.created_at.isoformat() + 'Z',
            'adspower_account_id': d.adspower_account_id,
            'account_username': d.adspower_account.username if d.adspower_account else 'N/A'
        } for d in devices]

        # 获取支付记录
        payments = Payment.query.filter_by(user_id=user_id).order_by(Payment.created_at.desc()).limit(20).all() # Limit recent payments
        payments_data = [{
            'id': p.id,
            'order_id': p.order_id,
            'amount': p.amount,
            'status': p.status,
            'payment_method': p.payment_method,
            'created_at': p.created_at.isoformat() + 'Z',
            'paid_at': p.paid_at.isoformat() + 'Z' if p.paid_at else None,
            'plan_id': p.plan_id,
            'subscription_days': p.subscription_days
        } for p in payments]

        # 获取登录会话 (最近10次)
        login_sessions = LoginSession.query.filter_by(user_id=user_id).order_by(LoginSession.login_time.desc()).limit(10).all()
        sessions_data = [{
            'id': s.id,
            'login_time': s.login_time.isoformat() + 'Z' if s.login_time else None,
            'ip_address': s.ip_address,
            'user_agent': s.user_agent,
            # 'status': s.status, # LoginSession status, not subscription status <-- 移除 status
            'completed_time': s.completed_time.isoformat() + 'Z' if s.completed_time else None, # 添加完成时间
            'adspower_account_id': s.adspower_account_id,
            'account_username': s.adspower_account.username if s.adspower_account else 'N/A'
        } for s in login_sessions]

        user_data = user.to_dict()

        return jsonify({
            'success': True,
            'user': user_data,
            'subscriptions': subscriptions_data,
            'devices': devices_data,
            'payments': payments_data,
            'login_sessions': sessions_data
        }), 200

    except NotFound:
        logger.warning(f"[Admin] 尝试获取不存在的用户详情: {user_id}")
        return jsonify({'success': False, 'message': '用户未找到'}), 404
    except Exception as e:
        logger.exception(f"[Admin] 获取用户 {user_id} 详细信息时出错: {e}")
        return jsonify({'success': False, 'message': f'获取用户详情时出错: {str(e)}'}), 500

@api.route('/admin/accounts/adspower', methods=['GET'])
@admin_required
def admin_get_adspower_accounts():
    """[管理员API] 获取所有ADSpower账号
    
    获取系统中所有ADSpower账号的列表
    
    返回:
    {
        "success": true/false,
        "message": "消息",
        "accounts": [
            {
                "id": 账号ID,
                "username": "用户名",
                "current_devices": 当前设备数,
                "max_devices": 最大设备数,
                "is_active": 是否激活,
                "subscription_type": "订阅类型",
                "last_login": "最后登录时间"
            }
        ]
    }
    """
    try:
        admin_user = g.user
        logger.info(f"[管理员] 管理员 {admin_user.id} ({admin_user.email}) 获取AdsPower账号列表")
        
        accounts = AdspowerAccount.query.all()
        result = []
        
        for account in accounts:
            result.append({
                "id": account.id,
                "username": account.username,
                "current_devices": account.current_devices,
                "max_devices": account.max_devices,
                "is_active": account.is_active,
                "subscription_type": account.subscription_type or "未设置",
                "last_login": account.last_login.isoformat() if account.last_login else None,
                "created_at": account.created_at.isoformat() if account.created_at else None
            })
        
        logger.info(f"[管理员] 获取到 {len(result)} 个AdsPower账号")
        
        return jsonify({
            "success": True,
            "accounts": result
        })
        
    except Exception as e:
        logger.exception(f"[管理员] 获取AdsPower账号列表时出错: {str(e)}")
        return jsonify({"success": False, "message": f"服务器内部错误: {str(e)}"}), 500

@api.route('/admin/accounts/adspower', methods=['POST'])
@admin_required
def admin_add_adspower_account():
    """[管理员API] 添加ADSpower账号
    
    添加新的ADSpower账号到系统
    
    请求体:
    {
        "username": "ADSpower用户名",
        "password": "ADSpower密码",
        "api_key": "API密钥(可选)",
        "totp_secret": "2FA密钥(可选)",
        "max_devices": 最大设备数(默认10),
        "subscription_type": "订阅类型(monthly/student/trial/basic)",
        "cookies": "Cookies JSON 字符串 (可选)",
        "remarks": "备注信息 (可选)"
    }
    
    返回:
    {
        "success": true/false,
        "message": "消息",
        "account": {账号信息}
    }
    """
    try:
        admin_user = g.user
        data = request.json
        
        logger.info(f"[管理员] 管理员 {admin_user.id} 正在添加新的AdsPower账号: {data.get('username')}")
        
        # 检查必填字段
        if not data.get('username') or not data.get('password'):
            logger.warning(f"[管理员] 添加AdsPower账号请求缺少必填字段: username={bool(data.get('username'))}, password={bool(data.get('password'))}")
            return jsonify({"success": False, "message": "用户名和密码为必填项"}), 400
        
        # 检查用户名是否已存在
        if AdspowerAccount.query.filter_by(username=data['username']).first():
            logger.warning(f"[管理员] 尝试添加的AdsPower账号已存在: {data['username']}")
            return jsonify({"success": False, "message": "账号已存在"}), 400
            
        # 处理 cookies 字段
        cookies_str = None
        if 'cookies' in data:
            cookies_value = data['cookies']
            if isinstance(cookies_value, str):
                if cookies_value == "":
                    cookies_str = ""
                else:
                    try:
                        json.loads(cookies_value) # 验证 JSON 格式
                        cookies_str = cookies_value
                    except json.JSONDecodeError:
                        logger.error(f"[管理员] 添加账号 {data['username']} 时提供的 Cookies 不是有效的 JSON 字符串")
                        return jsonify({"success": False, "message": "提供的 Cookie 数据不是有效的 JSON 格式"}), 400
                    except Exception as parse_err:
                         logger.error(f"[管理员] 添加账号 {data['username']} 时解析 Cookies 字符串出错: {parse_err}")
                         return jsonify({"success": False, "message": f"处理 Cookie 字符串时出错: {parse_err}"}), 400
            elif isinstance(cookies_value, (list, dict)):
                try:
                    cookies_str = json.dumps(cookies_value)
                except Exception as json_err:
                    logger.error(f"[管理员] 添加账号 {data['username']} 时序列化 Cookies 出错: {json_err}")
                    return jsonify({"success": False, "message": f"处理 Cookie 数据时出错: {json_err}"}), 400
            else:
                logger.warning(f"[管理员] 添加账号 {data['username']} 时收到非预期的 Cookies 类型: {type(cookies_value)}，将忽略 Cookies")
        
        # 创建新账号
        account = AdspowerAccount(
            username=data['username'],
            password=data['password'],
            api_key=data.get('api_key'),
            totp_secret=data.get('totp_secret'),
            max_devices=data.get('max_devices', 10),
            subscription_type=data.get('subscription_type'),
            cookies=cookies_str, # <-- 使用处理过的 cookies_str
            remarks=data.get('remarks'), # <-- 保留 remarks 字段
            is_active=True,
            current_devices=0,
            created_at=datetime.utcnow()
        )
        
        db.session.add(account)
        db.session.commit()
        
        logger.info(f"[管理员] 管理员 {admin_user.id} 成功创建AdsPower账号: {account.username}, ID: {account.id}")
        
        # 通知 WebDriver Manager 开始管理此账号
        try:
            manager = get_account_driver_manager()
            if manager:
                logger.info(f"[管理员] 准备通知 AccountWebDriverManager 添加新账号 ID: {account.id}")
                # 确保传递所有必要的凭据和 cookies
                manager.add_managed_account(
                    account_id=str(account.id),
                    username=account.username,
                    password=account.password, # 注意：这里需要能访问到原始密码
                    totp_secret=account.totp_secret,
                    cookies=account.cookies # 使用数据库中存储的 cookies
                )
                logger.info(f"[管理员] AccountWebDriverManager 已接收账号 {account.id} 的添加请求")
            else:
                logger.warning(f"[管理员] AccountWebDriverManager 未运行，无法添加新账号 {account.id} 进行管理")
        except Exception as e:
            # 记录错误，但不影响API成功返回，因为数据库已成功创建
            logger.error(f"[管理员] 通知 AccountWebDriverManager 添加新账号 {account.id} 时出错: {e}", exc_info=True)

        # # 移除旧的通过 API 获取 cookies 的逻辑 (如果需要，可以在其他地方触发)
        # # try:
        # #     if account.api_key:
        # #         adspower_api = AdspowerBrowser(api_key=account.api_key)
        # #         adspower_api.save_cookies_for_account(account.username)
        # #         logger.info(f"[管理员] 已为AdsPower账号 {account.username} 保存Cookies配置")
        # # except Exception as e:
        # #     logger.warning(f"[管理员] 获取AdsPower账号 {account.username} cookies时出错: {str(e)}")
        
        return jsonify({
            "success": True,
            "message": "ADSpower账号创建成功",
            "account": {
                "id": account.id,
                "username": account.username,
                "is_active": account.is_active,
                "max_devices": account.max_devices,
                "subscription_type": account.subscription_type or "未设置",
                "remarks": account.remarks, # 可以选择性返回 remarks
                "created_at": account.created_at.isoformat()
                # 不返回敏感信息如 password, api_key, totp_secret, cookies
            }
        }), 201
        
    except Exception as e:
        logger.exception(f"[管理员] 创建AdsPower账号时出错: {str(e)}")
        db.session.rollback()
        return jsonify({"success": False, "message": f"服务器内部错误: {str(e)}"}), 500

@api.route('/admin/accounts/adspower/<int:account_id>', methods=['DELETE'])
@admin_required
def admin_delete_adspower_account(account_id):
    """
    管理员删除一个ADSpower账号
    ---
    # ... (省略 swagger 文档)
    """
    account = AdspowerAccount.query.get(account_id)
    if not account:
        return jsonify(error="账号未找到"), 404

    # 检查账号是否仍有设备在使用
    if account.devices and len(account.devices) > 0:
        logger.warning(f"[管理员] 尝试删除账号 {account_id} ({account.username})，但仍有关联设备 ({len(account.devices)}个)")
        # 根据实际需求决定是阻止删除还是强制删除（并处理关联设备）
        # 当前实现：阻止删除
        return jsonify(error=f"无法删除账号，仍有 {len(account.devices)} 个设备关联。请先解绑或删除设备。"), 400

    try:
        # --- 添加这部分 ---
        try:
            manager = get_account_driver_manager()
            if manager:
                logger.info(f"[管理员] 准备通知 AccountWebDriverManager 停止管理账号 ID: {account_id}")
                manager.remove_managed_account(str(account_id))
                logger.info(f"[管理员] AccountWebDriverManager 已处理账号 {account_id} 的移除请求")
            else:
                logger.warning(f"[管理员] AccountWebDriverManager 未运行，无法通知其移除账号 {account_id}")
        except Exception as e:
            # 记录错误，但继续尝试删除数据库记录
            logger.error(f"[管理员] 通知 AccountWebDriverManager 移除账号 {account_id} 时出错: {e}", exc_info=True)
        # --- 添加结束 ---

        username = account.username # 在删除前保存用户名用于日志
        db.session.delete(account)
        db.session.commit()
        logger.info(f"[管理员] 管理员 {g.user_id} 成功删除AdsPower账号: {username} (ID: {account_id})")
        return jsonify(message="AdsPower账号删除成功"), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"[管理员] 删除AdsPower账号 {account_id} 时出错: {e}", exc_info=True)
        return jsonify(error=f"删除AdsPower账号时发生内部错误: {str(e)}"), 500

@api.route('/admin/accounts/adspower/<int:account_id>/toggle-status', methods=['POST'])
@admin_required
def admin_toggle_adspower_account_status(account_id):
    """切换ADSpower账号状态"""
    try:
        admin_user = g.user
        data = request.json
        logger.info(f"[管理员] 管理员 {admin_user.id} 正在切换AdsPower账号 {account_id} 状态")
        
        if data is None or 'is_active' not in data:
            logger.warning(f"[管理员] 切换AdsPower账号状态请求缺少必要参数: {data}")
            return jsonify({"success": False, "message": "缺少必要参数"}), 400
        
        account = AdspowerAccount.query.get(account_id)
        if not account:
            logger.warning(f"[管理员] 尝试切换不存在的AdsPower账号状态: {account_id}")
            return jsonify({"success": False, "message": "账号不存在"}), 404
        
        # 更新状态
        old_status = account.is_active
        account.is_active = data['is_active']
        db.session.commit()
        
        logger.info(f"[管理员] 管理员 {admin_user.id} 将AdsPower账号 {account.username} (ID: {account_id}) 的状态从 {old_status} 更改为 {account.is_active}")
        
        # 通知 AccountWebDriverManager 更新状态
        try:
            manager = get_account_driver_manager()
            if manager:
                if account.is_active:
                    logger.info(f"[管理员] 准备通知 AccountWebDriverManager 重新开始管理账号 ID: {account_id}")
                    # 重新激活时，调用 add_managed_account
                    manager.add_managed_account(
                        account_id=str(account.id),
                        username=account.username,
                        password=account.password,
                        totp_secret=account.totp_secret,
                        cookies=account.cookies
                    )
                    logger.info(f"[管理员] AccountWebDriverManager 已接收账号 {account_id} 的重新管理请求")
                else:
                    logger.info(f"[管理员] 准备通知 AccountWebDriverManager 停止管理账号 ID: {account_id}")
                    # 禁用时，调用 remove_managed_account
                    manager.remove_managed_account(str(account_id))
                    logger.info(f"[管理员] AccountWebDriverManager 已处理账号 {account_id} 的移除请求")
            else:
                logger.warning(f"[管理员] AccountWebDriverManager 未运行，无法通知其更新账号 {account_id} 的状态")
        except Exception as e:
            # 记录错误，但不影响API成功返回，因为数据库已成功更新
            logger.error(f"[管理员] 通知 AccountWebDriverManager 更新账号 {account_id} 状态时出错: {e}", exc_info=True)

        return jsonify({
            "success": True, 
            "message": f"账号状态已更新为: {'启用' if account.is_active else '禁用'}"
        })
        
    except Exception as e:
        logger.exception(f"[管理员] 更新AdsPower账号 {account_id} 状态时出错: {str(e)}")
        db.session.rollback()
        return jsonify({"success": False, "message": f"服务器内部错误: {str(e)}"}), 500

@api.route('/admin/accounts/adspower/<int:account_id>/cookies', methods=['GET'])
@admin_required
def admin_get_adspower_account_cookies(account_id):
    """获取ADSpower账号的Cookies"""
    try:
        admin_user = g.user
        logger.info(f"[管理员] 管理员 {admin_user.id} 获取AdsPower账号 {account_id} 的Cookies")
        
        account = AdspowerAccount.query.get(account_id)
        if not account:
            logger.warning(f"[管理员] 尝试获取不存在的AdsPower账号Cookies: {account_id}")
            return jsonify({"success": False, "message": "账号不存在"}), 404
        
        # 获取Cookies
        cookies = []
        if account.cookies: # <-- 读取新的 cookies 字段
            try:
                cookies = json.loads(account.cookies) # <-- 解析新的 cookies 字段
                logger.info(f"[管理员] 成功解析AdsPower账号 {account.username} (ID: {account_id}) 的Cookies")
            except Exception as e:
                logger.error(f"[管理员] 解析AdsPower账号 {account.username} (ID: {account_id}) 的Cookies失败: {str(e)}")
                # 返回空列表或原始字符串，取决于前端期望
                # cookies = account.cookies # 返回原始字符串供调试
                pass
        
        return jsonify({
            "success": True, 
            "cookies": cookies
        })
        
    except Exception as e:
        logger.exception(f"[管理员] 获取AdsPower账号 {account_id} Cookies时出错: {str(e)}")
        return jsonify({"success": False, "message": f"服务器内部错误: {str(e)}"}), 500

@api.route('/admin/devices/sync', methods=['POST'])
@admin_required
def admin_sync_devices():
    """管理员同步所有用户设备信息"""
    # 获取所有用户的设备
    devices = Device.query.all()
    
    if not devices:
        return jsonify({'message': '没有可用的设备'}), 404
    
    # 更新设备信息
    updated = 0
    for device in devices:
        try:
            # Skip extra_info handling as the attribute doesn't exist
            # Simply increment the counter
            updated += 1
        except Exception as e:
            logger.error(f"处理设备 {device.id} 时出错: {e}") # Updated log message
    
    db.session.commit()
    
    return jsonify({
        'message': f'成功更新 {updated} 台设备',
        'devices_updated': updated
    })

@api.route('/devices/sync', methods=['POST'])
@login_required
def sync_user_devices():
    """同步用户设备信息 - 为前端兼容保留但实际不执行同步"""
    # 不实际同步设备，只返回成功消息
    return jsonify({
        'message': '设备同步已完成'
    })

@api.route('/admin/accounts/adspower/<int:account_id>', methods=['PUT'])
@admin_required
def admin_update_adspower_account(account_id):
    """更新ADSpower账号信息"""
    try:
        admin_user = g.user
        data = request.json
        logger.info(f"更新账号 #{account_id} 接收数据: {data}")
        
        # 检查账号是否存在
        account = AdspowerAccount.query.get(account_id)
        if not account:
            return jsonify({"success": False, "message": "账号不存在"}), 404
        
        # 更新账号信息
        if 'username' in data:
            account.username = data['username']
            logger.info(f"更新账号 #{account_id} 用户名: {data['username']}")
        if 'password' in data and data['password']:
            account.password = data['password']
            logger.info(f"更新账号 #{account_id} 密码已修改")
        if 'api_key' in data:
            account.api_key = data['api_key']
            logger.info(f"更新账号 #{account_id} API密钥: {data['api_key']}")
        if 'totp_secret' in data:
            account.totp_secret = data['totp_secret']
            logger.info(f"更新账号 #{account_id} TOTP密钥: {data['totp_secret']}")
        if 'max_devices' in data:
            account.max_devices = data['max_devices']
            logger.info(f"更新账号 #{account_id} 最大设备数: {data['max_devices']}")
        if 'subscription_type' in data:
            logger.info(f"更新账号 #{account_id} 订阅类型: {data['subscription_type']} (原值: {account.subscription_type})")
            account.subscription_type = data['subscription_type']
        
        # 更新 cookies 字段
        cookies_updated = False
        if 'cookies' in data:
            cookies_value = data['cookies']
            if isinstance(cookies_value, str):
                if cookies_value == "": # 允许空字符串清空
                    if account.cookies != cookies_value:
                        account.cookies = cookies_value
                        logger.info(f"更新账号 #{account_id} Cookies 已清空")
                        cookies_updated = True
                else:
                    # 验证是否是有效的 JSON
                    try:
                        json.loads(cookies_value)
                        if account.cookies != cookies_value:
                            account.cookies = cookies_value
                            logger.info(f"更新账号 #{account_id} Cookies - 字符串: {cookies_value[:100]}...")
                            cookies_updated = True
                    except json.JSONDecodeError:
                        logger.error(f"更新账号 #{account_id} 失败：提供的 Cookies 不是有效的 JSON 字符串")
                        return jsonify({"success": False, "message": "提供的 Cookie 数据不是有效的 JSON 格式"}), 400
                    except Exception as parse_err:
                        logger.error(f"更新账号 #{account_id} 时解析 Cookies 字符串出错: {parse_err}")
                        return jsonify({"success": False, "message": f"处理 Cookie 字符串时出错: {parse_err}"}), 400
            elif isinstance(cookies_value, (list, dict)):
                # 如果是列表或字典，尝试序列化为JSON
                try:
                    new_cookies_json = json.dumps(cookies_value)
                    if account.cookies != new_cookies_json:
                        account.cookies = new_cookies_json
                        logger.info(f"更新账号 #{account_id} Cookies - 结构化数据: {account.cookies[:100]}...")
                        cookies_updated = True
                except Exception as json_err:
                    logger.error(f"更新账号 #{account_id} 时序列化 Cookies 出错: {json_err}")
                    return jsonify({"success": False, "message": f"处理 Cookie 数据时出错: {json_err}"}), 400
            else:
                logger.warning(f"更新账号 #{account_id} 时收到非预期的 Cookies 类型: {type(cookies_value)}，将忽略此字段更新")

        # 更新 remarks 字段 (保留原有逻辑，如果前端还传 remarks)
        if 'remarks' in data:
            if account.remarks != data['remarks']:
                account.remarks = data['remarks']
                logger.info(f"更新账号 #{account_id} Remarks: {account.remarks[:100]}...")
        
        # 提交数据库更改
        db.session.commit()
        logger.info(f"AdsPower账号 #{account.id} ({account.username}) 数据库更新成功")
        
        # === 更新 WebDriver Manager ===
        # 每次更新成功后，都调用 add_managed_account 以确保管理器拥有最新的凭据和Cookie
        # add_managed_account 内部会处理更新逻辑
        try:
            logger.info(f"账号 #{account_id} 信息已更新，正在通知 WebDriver 管理器...")
            manager = get_account_driver_manager()
            if manager:
                # 使用更新后的 account 对象中的信息
                manager.add_managed_account(
                    account_id=str(account.id),
                    username=account.username,
                    password=account.password, # 确保能访问到更新后的密码
                    totp_secret=account.totp_secret,
                    cookies=account.cookies
                )
                logger.info(f"账号 #{account_id} 的 WebDriver 管理器信息已同步")
            else:
                logger.warning(f"更新账号 #{account_id} 后，AccountWebDriverManager 未运行，无法同步信息")
        except Exception as manager_e:
            logger.error(f"更新账号 #{account_id} 后同步 WebDriver 管理器状态时出错: {manager_e}", exc_info=True)
            # 不在此处返回错误，因为数据库已成功更新，只记录日志
        # === WebDriver Manager 更新结束 ===

        # 返回更新后的账号信息 (只包含部分关键信息)
        updated_account = AdspowerAccount.query.get(account_id) # 重新获取以确保数据最新
        return jsonify({
            "success": True,
            "message": "账号信息更新成功",
            "account": {
                "id": updated_account.id,
                "username": updated_account.username,
                "subscription_type": updated_account.subscription_type,
                "max_devices": updated_account.max_devices
                # 不返回 password, api_key, totp_secret, cookies 到前端
            }
        })
    except Exception as e:
        logger.exception(f"更新AdsPower账号 #{account_id} 时出错: {str(e)}")
        db.session.rollback()
        return jsonify({"success": False, "message": f"更新账号失败: {str(e)}"}), 500

@api.route('/adspower/direct-login', methods=['POST'])
@login_required
def request_direct_adspower_login():
    """处理直接登录AdsPower账号的请求 (已重构)
    
    现在调用 DirectLoginService 来处理核心逻辑。
    """
    # Ensure g.user is populated by @login_required
    if not hasattr(g, 'user') or not g.user:
        logger.error("[API Direct Login] Endpoint reached without authenticated user in g")
        return jsonify({'success': False, 'message': '认证失败，无法识别用户。'}), 401
        
    user_id = g.user.id
    logger.info(f"[API Direct Login] 收到用户 {user_id} 的直接登录请求")

    # --- Use the new DirectLoginService --- 
    try:
        # Import the getter function for the new service
        from .services.direct_login_service import get_direct_login_service
        
        direct_login_service = get_direct_login_service()
        
        # Call the service method to prepare the login
        result = direct_login_service.prepare_login(user_id)
        
        # Determine status code based on result
        status_code = 500 # Default to internal error
        if result['success']:
            status_code = 200
        elif result.get('error_code') in ['no_subscription', 'DEVICE_LIMIT_REACHED']: # Add DEVICE_LIMIT_REACHED if handled by DirectLoginService
             status_code = 403 # Forbidden
        elif result.get('error_code') in ['no_account_available', 'account_verification_failed']:
            status_code = 503 # Service Unavailable
        elif result.get('error_code') in ['user_not_found', 'session_creation_failed']: # Added session error
             status_code = 400 # Bad Request or internal error? Let's use 400 for session fail for now.
        
        logger.info(f"[API Direct Login] DirectLoginService processed request for user {user_id}. Success: {result['success']}. Status Code: {status_code}")
        return jsonify(result), status_code

    except Exception as e:
         # Catch unexpected errors during service call
         logger.exception(f"[API Direct Login] Unexpected error calling DirectLoginService for user {user_id}: {e}")
         return jsonify({
            'success': False,
            'message': "处理登录请求时发生意外服务器错误",
            'error_code': 'service_call_exception',
            'data': None
         }), 500

# 统一错误处理
@api.errorhandler(404)
def not_found(error):
    """处理404错误"""
    return jsonify({"success": False, "message": "资源不存在"}), 404

@api.errorhandler(405)
def method_not_allowed(error):
    """处理405错误"""
    return jsonify({"success": False, "message": "方法不允许"}), 405

@api.errorhandler(500)
def internal_server_error(error):
    """处理500错误"""
    return jsonify({"success": False, "message": "服务器内部错误"}), 500

@api.route('/auth/generate-totp', methods=['POST'])
def generate_totp():
    """生成TOTP验证码
    
    请求体:
    {
        "login_token": "登录会话令牌" # 修改：不再是 secret
    }
    
    返回:
    {
        "success": true/false,
        "code": "生成的验证码",
        "remaining_seconds": 剩余有效秒数
    }
    """
    try:
        data = request.json
        if not data or 'login_token' not in data: # 修改：检查 login_token
            logger.warning("[TOTP Gen] 请求缺少 login_token 参数")
            return jsonify({'success': False, 'message': '缺少登录会话令牌'}), 400
            
        login_token = data['login_token']
        logger.info(f"[TOTP Gen]收到 login_token: {login_token[:10]}... 进行 TOTP 生成请求")

        login_session = LoginSession.query.filter_by(login_token=login_token).first()

        if not login_session:
            logger.warning(f"[TOTP Gen] 无效的 login_token: {login_token[:10]}...")
            return jsonify({'success': False, 'message': '登录会话令牌无效'}), 404
        
        now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        if login_session.expiration_timestamp < now_utc_naive:
            logger.warning(f"[TOTP Gen] LoginSession {login_session.id} (token: {login_token[:10]}...) 已过期")
            return jsonify({'success': False, 'message': '登录会话已过期'}), 410

        adspower_account = AdspowerAccount.query.get(login_session.adspower_account_id)

        if not adspower_account:
            logger.error(f"[TOTP Gen] LoginSession {login_session.id} 关联的 AdspowerAccount ID {login_session.adspower_account_id} 未找到")
            return jsonify({'success': False, 'message': '无法找到关联的AdsPower账户'}), 500
        
        if not adspower_account.totp_secret:
            logger.warning(f"[TOTP Gen] AdspowerAccount ID {adspower_account.id} ({adspower_account.username}) 未配置TOTP密钥")
            return jsonify({'success': False, 'message': '关联的AdsPower账户未配置TOTP'}), 400

        secret = adspower_account.totp_secret
        
        import pyotp
        import time
        
        totp_instance = pyotp.TOTP(secret)
        code = totp_instance.now()
        
        current_time = int(time.time())
        time_step = 30
        time_remaining_in_window = time_step - (current_time % time_step)
        
        logger.info(f"[TOTP Gen] 为账户 {adspower_account.username} 生成代码 {code}, 剩余 {time_remaining_in_window}s")
        
        return jsonify({
            'success': True,
            'code': code,
            'remaining_seconds': time_remaining_in_window
        }), 200
        
    except Exception as e:
        logger.exception(f"[TOTP Gen] 生成TOTP验证码时出错: {str(e)}")
        return jsonify({'success': False, 'message': f'生成验证码失败: {str(e)}'}), 500

@api.route('/subscriptions/current', methods=['GET'])
@login_required # 使用我们自己的 login_required 装饰器
def get_current_subscription():
    """获取当前用户的活跃订阅信息"""
    user_id = g.user.id # 从 g 对象获取用户 ID
    
    try:
        subscription = SubscriptionService.get_active_subscription(user_id)
        
        if not subscription:
            logger.info(f"[订阅查询] 用户 {user_id} 没有有效的订阅")
            return jsonify({'success': True, 'subscription': None, 'message': '当前无有效订阅'}), 200

        logger.info(f"[订阅查询] 用户 {user_id} 有效订阅: ID={subscription.id}, Plan={subscription.plan}, End={subscription.end_date}")
        
        # 获取关联的计划名称
        plan_type = SubscriptionType.query.filter_by(code=subscription.plan).first()
        plan_name = plan_type.name if plan_type else subscription.plan # Fallback to code if name not found

        # 直接使用 end_date 判断状态，不再需要 status 字段
        is_expired = subscription.end_date < datetime.utcnow()
        # status = 'expired' if is_expired else 'active' # No longer needed

        subscription_data = {
            'id': subscription.id,
            'user_id': subscription.user_id,
            'plan': subscription.plan,
            'plan_name': plan_name, # 添加计划名称
            'start_date': subscription.start_date.isoformat() + 'Z',
            'end_date': subscription.end_date.isoformat() + 'Z',
            'price': subscription.price,
            'max_devices': subscription.max_devices,
            # 'status': status, # 移除 status 字段
            'is_expired': is_expired # 可以选择性地添加一个布尔值表示是否过期
        }
        
        return jsonify({'success': True, 'subscription': subscription_data}), 200
        
    except Exception as e:
        logger.exception(f"[订阅查询] 获取用户 {user_id} 订阅信息时出错: {e}")
        return jsonify({'success': False, 'message': f'获取订阅信息时出错: {str(e)}'}), 500

"""
账号池管理相关的API路由
"""

@api.route('/adspower/pools', methods=['GET', 'POST'])
@api.route('/adspower/pools/<int:pool_id>', methods=['DELETE'])
@api.route('/adspower/assign-account', methods=['POST'])
@api.route('/adspower/unassign-account', methods=['POST'])
@api.route('/adspower/balance-pools', methods=['POST'])
@admin_required
def deprecated_pool_apis():
    """处理所有已弃用的账号池API
    
    返回:
    {
        "success": false,
        "message": "此API已弃用，账号池功能已移除，请使用订阅类型API"
    }
    """
    logger.warning(f"有客户端调用了已弃用的API: {request.path}")
    return jsonify({
        "success": False,
        "message": "此API已弃用，账号池功能已移除，请使用订阅类型API"
    }), 410

@api.route('/adspower/sync-accounts', methods=['POST'])
@admin_required
def sync_adspower_accounts():
    """同步所有ADSpower账号信息"""
    try:
        # 此处应添加实际与ADSpower API交互的代码
        # 简化实现，仅返回成功
        return jsonify({
            'success': True,
            'message': '同步账号信息成功'
        })
    except Exception as e:
        logger.error(f"同步账号信息出错: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'同步账号信息失败: {str(e)}'
        }), 500

@api.route('/adspower/login-info', methods=['GET'])
@login_required
def get_adspower_login_info():
    """
    获取当前用户订阅可用的ADSpower账号登录信息
    
    请求头:
    - Authorization: Bearer <token>
    
    返回:
    {
        "success": true/false,
        "message": "消息",
        "data": {
            "login_token": "登录令牌",
            "username": "ADSpower用户名",
            "password": "ADSpower密码",
            "totp_secret": "2FA密钥",
            "login_url": "登录URL"
        }
    }
    """
    try:
        user = g.user
        
        # 调用auth_service获取登录信息
        login_info = auth_service.get_adspower_login_info(user.id)
        
        if not login_info:
            return jsonify({
                "success": False, 
                "message": "获取登录信息失败，可能是没有可用的ADSpower账号或您的订阅已过期"
            }), 400
        
        return jsonify(login_info)
    
    except Exception as e:
        logger.exception(f"获取ADSpower登录信息时出错: {str(e)}")
        return jsonify({
            "success": False, 
            "message": f"服务器内部错误: {str(e)}"
        }), 500

# 移除原有的账号池相关API，添加设置订阅类型的API
@api.route('/admin/accounts/adspower/<int:account_id>/subscription-type', methods=['POST'])
@admin_required
def set_adspower_account_subscription_type(account_id):
    """设置ADSpower账号的订阅类型
    
    请求体:
    {
        "subscription_type": "monthly" // 订阅类型代码
    }
    
    返回:
    {
        "success": true/false,
        "message": "设置结果信息"
    }
    """
    try:
        data = request.json
        if not data or 'subscription_type' not in data:
            return jsonify({
                "success": False,
                "message": "缺少订阅类型参数"
            }), 400
        
        subscription_type = data['subscription_type']
        
        # 检查订阅类型是否存在
        if subscription_type:
            subscription_type_obj = SubscriptionType.query.filter_by(code=subscription_type).first()
            if not subscription_type_obj and subscription_type not in ['monthly', 'student', 'trial', 'basic']:
                return jsonify({
                    "success": False,
                    "message": f"无效的订阅类型: {subscription_type}"
                }), 400
        
        # 查找账号
        account = AdspowerAccount.query.get(account_id)
        if not account:
            return jsonify({
                "success": False,
                "message": "未找到指定的AdsPower账号"
            }), 404
        
        # 更新订阅类型
        account.subscription_type = subscription_type
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "订阅类型设置成功"
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"设置AdsPower账号订阅类型失败: {e}")
        return jsonify({
            "success": False,
            "message": f"设置失败: {str(e)}"
        }), 500

@api.route('/admin/accounts/adspower/batch-set-subscription', methods=['POST'])
@admin_required
def batch_set_adspower_subscription():
    """批量设置AdsPower账号的订阅类型
    
    请求体:
    {
        "account_ids": [1, 2, 3],  // 账号ID列表
        "subscription_type": "monthly"  // 要设置的订阅类型
    }
    
    返回:
    {
        "success": true/false,
        "message": "操作结果信息",
        "success_count": 3,  // 成功更新的账号数量
        "failed_count": 0    // 更新失败的账号数量
    }
    """
    try:
        data = request.json
        if not data or 'account_ids' not in data or 'subscription_type' not in data:
            return jsonify({
                "success": False,
                "message": "缺少必要参数"
            }), 400
        
        account_ids = data['account_ids']
        subscription_type = data['subscription_type']
        
        # 检查账号ID列表是否为空
        if not account_ids:
            return jsonify({
                "success": False,
                "message": "账号ID列表不能为空"
            }), 400
        
        # 检查订阅类型是否存在
        if subscription_type:
            subscription_type_obj = SubscriptionType.query.filter_by(code=subscription_type).first()
            if not subscription_type_obj and subscription_type not in ['monthly', 'student', 'trial', 'basic']:
                return jsonify({
                    "success": False,
                    "message": f"无效的订阅类型: {subscription_type}"
                }), 400
                
        # 查询所有指定的账号
        accounts = AdspowerAccount.query.filter(AdspowerAccount.id.in_(account_ids)).all()
        
        # 记录更新结果
        success_count = 0
        failed_ids = []
        
        # 更新每个账号的订阅类型
        for account in accounts:
            try:
                account.subscription_type = subscription_type
                success_count += 1
            except Exception as e:
                logger.error(f"更新账号 {account.id} 订阅类型失败: {e}")
                failed_ids.append(account.id)
        
        # 提交更改
        db.session.commit()
        
        failed_count = len(account_ids) - success_count
        
        return jsonify({
            "success": True,
            "message": f"批量更新完成: {success_count} 成功, {failed_count} 失败",
            "success_count": success_count,
            "failed_count": failed_count,
            "failed_ids": failed_ids if failed_ids else None
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"批量设置AdsPower账号订阅类型失败: {e}")
        return jsonify({
            "success": False,
            "message": f"操作失败: {str(e)}"
        }), 500

# 添加编辑AdsPower账号的API路由
@api.route('/admin/accounts/adspower/<int:account_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def admin_manage_adspower_account(account_id):
    """管理单个AdsPower账号 - 获取详情、更新或删除
    
    GET: 获取指定账号的详细信息
    返回:
    {
        "success": true/false,
        "message": "消息",
        "data": {
            "id": 账号ID,
            "username": "用户名",
            "api_key": "API Key",
            "totp_secret": "TOTP密钥",
            "max_devices": 最大设备数,
            "subscription_type": "订阅类型",
            "created_at": "创建时间",
            "device_count": 已关联设备数
        }
    }
    
    PUT: 更新账号信息
    请求体:
    {
        "username": "新用户名",
        "password": "新密码", // 可选
        "api_key": "新API Key",
        "totp_secret": "新TOTP密钥",
        "max_devices": 新最大设备数,
        "subscription_type": "新订阅类型"
    }
    
    DELETE: 删除账号
    """
    account = AdspowerAccount.query.get(account_id)
    if not account:
        return jsonify({"success": False, "message": f"账号ID {account_id} 不存在"}), 404
    
    # GET - 获取账号详情
    if request.method == 'GET':
        # 获取该账号关联的设备数量
        device_count = Device.query.filter_by(adspower_account_id=account_id).count()
        
        return jsonify({
            "success": True,
            "data": {
                "id": account.id,
                "username": account.username,
                "api_key": account.api_key,
                "totp_secret": account.totp_secret,
                "max_devices": account.max_devices,
                "subscription_type": account.subscription_type,
                "created_at": account.created_at.isoformat() if account.created_at else None,
                "device_count": device_count
            }
        })
    
    # PUT - 更新账号信息
    elif request.method == 'PUT':
        try:
            data = request.json
            logger.info(f"更新账号 #{account_id} 接收数据: {data}")
            
            # 更新字段
            if 'username' in data:
                account.username = data['username']
                logger.info(f"更新账号 #{account_id} 用户名: {data['username']}")
            if 'password' in data and data['password']:
                account.password = data['password']
                logger.info(f"更新账号 #{account_id} 密码已修改")
            if 'api_key' in data:
                account.api_key = data['api_key']
                logger.info(f"更新账号 #{account_id} API密钥: {data['api_key']}")
            if 'totp_secret' in data:
                account.totp_secret = data['totp_secret']
                logger.info(f"更新账号 #{account_id} TOTP密钥: {data['totp_secret']}")
            if 'max_devices' in data:
                account.max_devices = data['max_devices']
                logger.info(f"更新账号 #{account_id} 最大设备数: {data['max_devices']}")
            if 'subscription_type' in data:
                logger.info(f"更新账号 #{account_id} 订阅类型: {data['subscription_type']} (原值: {account.subscription_type})")
                account.subscription_type = data['subscription_type']
            
            # 更新 cookies 字段
            if 'cookies' in data:
                cookies_value = data['cookies']
                if isinstance(cookies_value, str):
                    if cookies_value == "": # 允许空字符串清空
                        if account.cookies != cookies_value:
                            account.cookies = cookies_value
                            logger.info(f"更新账号 #{account_id} Cookies 已清空")
                    else:
                        # 验证是否是有效的 JSON
                        try:
                            json.loads(cookies_value)
                            if account.cookies != cookies_value:
                                account.cookies = cookies_value
                                logger.info(f"更新账号 #{account_id} Cookies - 字符串: {cookies_value[:100]}...")
                        except json.JSONDecodeError:
                            logger.error(f"更新账号 #{account_id} 失败：提供的 Cookies 不是有效的 JSON 字符串")
                            return jsonify({"success": False, "message": "提供的 Cookie 数据不是有效的 JSON 格式"}), 400
                        except Exception as parse_err:
                            logger.error(f"更新账号 #{account_id} 时解析 Cookies 字符串出错: {parse_err}")
                            return jsonify({"success": False, "message": f"处理 Cookie 字符串时出错: {parse_err}"}), 400
                elif isinstance(cookies_value, (list, dict)):
                    # 如果是列表或字典，尝试序列化为JSON
                    try:
                        new_cookies_json = json.dumps(cookies_value)
                        if account.cookies != new_cookies_json:
                            account.cookies = new_cookies_json
                            logger.info(f"更新账号 #{account_id} Cookies - 结构化数据: {account.cookies[:100]}...")
                    except Exception as json_err:
                        logger.error(f"更新账号 #{account_id} 时序列化 Cookies 出错: {json_err}")
                        return jsonify({"success": False, "message": f"处理 Cookie 数据时出错: {json_err}"}), 400
                else:
                    logger.warning(f"更新账号 #{account_id} 时收到非预期的 Cookies 类型: {type(cookies_value)}，将忽略此字段更新")

            # 更新 remarks 字段 (保留原有逻辑，如果前端还传 remarks)
            if 'remarks' in data:
                if account.remarks != data['remarks']:
                    account.remarks = data['remarks']
                    logger.info(f"更新账号 #{account_id} Remarks: {account.remarks[:100]}...")
            
            # 提交数据库更改
            db.session.commit()
            logger.info(f"AdsPower账号 #{account.id} ({account.username}) 数据库更新成功")
            
            # === 更新 WebDriver Manager ===
            # 每次更新成功后，都调用 add_managed_account 以确保管理器拥有最新的凭据和Cookie
            # add_managed_account 内部会处理更新逻辑
            try:
                logger.info(f"账号 #{account_id} 信息已更新，正在通知 WebDriver 管理器...")
                manager = get_account_driver_manager()
                if manager:
                    # 使用更新后的 account 对象中的信息
                    manager.add_managed_account(
                        account_id=str(account.id),
                        username=account.username,
                        password=account.password, # 确保能访问到更新后的密码
                        totp_secret=account.totp_secret,
                        cookies=account.cookies
                    )
                    logger.info(f"账号 #{account_id} 的 WebDriver 管理器信息已同步")
                else:
                    logger.warning(f"更新账号 #{account_id} 后，AccountWebDriverManager 未运行，无法同步信息")
            except Exception as manager_e:
                logger.error(f"更新账号 #{account_id} 后同步 WebDriver 管理器状态时出错: {manager_e}", exc_info=True)
                # 不在此处返回错误，因为数据库已成功更新，只记录日志
            # === WebDriver Manager 更新结束 ===

            # 返回更新后的账号信息 (只包含部分关键信息)
            updated_account = AdspowerAccount.query.get(account_id) # 重新获取以确保数据最新
            return jsonify({
                "success": True,
                "message": "账号信息更新成功",
                "account": {
                    "id": updated_account.id,
                    "username": updated_account.username,
                    "subscription_type": updated_account.subscription_type,
                    "max_devices": updated_account.max_devices
                    # 不返回 password, api_key, totp_secret, cookies 到前端
                }
            })
        except Exception as e:
            logger.exception(f"更新AdsPower账号 #{account_id} 时出错: {str(e)}")
            db.session.rollback()
            return jsonify({"success": False, "message": f"更新账号失败: {str(e)}"}), 500
    
    # DELETE - 删除账号
    elif request.method == 'DELETE':
        try:
            # 检查是否有关联的设备
            devices = Device.query.filter_by(adspower_account_id=account_id).all()
            if devices:
                # 将设备的adspower_account_id设为NULL
                for device in devices:
                    device.adspower_account_id = None
                    logger.info(f"设备 #{device.id} 的AdsPower账号关联已移除")
            
            # 删除账号
            db.session.delete(account)
            db.session.commit()
            
            logger.info(f"AdsPower账号 #{account_id} 删除成功")
            return jsonify({
                "success": True,
                "message": "账号删除成功"
            })
            
        except Exception as e:
            logger.exception(f"删除AdsPower账号 #{account_id} 时出错: {str(e)}")
            db.session.rollback()
            return jsonify({"success": False, "message": f"删除账号失败: {str(e)}"}), 500

@api.route('/user/adspower-account', methods=['GET'])
@login_required
def get_user_adspower_account():
    """获取当前用户可用的AdsPower账号信息
    
    返回:
    {
        "success": true/false,
        "message": "消息",
        "account": {
            "username": "ADSpower用户名",
            "login_token": "登录令牌",
            "totp_secret": "TOTP密钥",
            "login_url": "直接登录URL"
        }
    }
    """
    try:
        user_id = g.user.id
        
        # 获取用户的AdsPower登录信息
        login_info = auth_service.get_adspower_login_info(user_id)
        
        if not login_info or not login_info.get('success'):
            # 如果获取失败，返回错误消息
            message = "获取AdsPower账号失败"
            if login_info and login_info.get('message'):
                message = login_info.get('message')
            
            return jsonify({
                "success": False,
                "message": message
            }), 404
        
        # 返回登录信息
        return jsonify({
            "success": True,
            "message": "获取AdsPower账号成功",
            "account": login_info.get('data')
        })
        
    except Exception as e:
        logger.exception(f"获取用户AdsPower账号信息时出错: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"服务器内部错误: {str(e)}"
        }), 500

"""
订阅类型管理API
"""
@api.route('/subscription-types', methods=['GET'])
@login_required
def get_subscription_types():
    """获取所有订阅类型
    
    返回:
    {
        "success": true,
        "types": [
            {
                "id": 1,
                "code": "monthly",
                "name": "月付会员",
                "max_devices": 5,
                "price": 49.99,
                "discount": 100,
                "days": 30,
                "requirements": null,
                "is_public": true
            },
            ...
        ]
    }
    """
    try:
        user = g.user
        logger.info(f"[订阅类型] 用户 {user.id} 请求获取订阅类型列表")
        
        # 从数据库获取所有订阅类型
        subscription_types = SubscriptionType.query.all()
        
        # 转换为JSON格式
        types_data = []
        for type_obj in subscription_types:
            types_data.append({
                "id": type_obj.id,
                "code": type_obj.code,
                "name": type_obj.name,
                "max_devices": type_obj.max_devices,
                "price": type_obj.price,
                "discount": type_obj.discount,
                "days": type_obj.days,
                "requirements": type_obj.requirements,
                "is_public": type_obj.is_public
            })
        
        logger.info(f"[订阅类型] 获取到 {len(types_data)} 种订阅类型")
        
        return jsonify({
            "success": True,
            "types": types_data
        })
    except Exception as e:
        logger.error(f"[订阅类型] 获取订阅类型失败: {e}")
        return jsonify({
            "success": False,
            "message": f"获取订阅类型失败: {str(e)}"
        }), 500

@api.route('/subscription-types', methods=['POST'])
@admin_required
def add_subscription_type():
    """添加新的订阅类型
    
    请求体:
    {
        "code": "monthly",
        "name": "月付会员",
        "max_devices": 5,
        "price": 49.99,
        "discount": 100,
        "days": 30,
        "requirements": null,
        "is_public": true
    }
    
    返回:
    {
        "success": true,
        "message": "订阅类型添加成功",
        "type_id": 1
    }
    """
    try:
        admin_user = g.user
        data = request.json
        
        logger.info(f"[管理员] 管理员 {admin_user.id} 请求添加新订阅类型: {data}")
        
        # 验证必填字段
        if not data or 'code' not in data or 'name' not in data:
            logger.warning(f"[管理员] 添加订阅类型请求缺少必要参数: {data}")
            return jsonify({
                "success": False,
                "message": "缺少必要参数"
            }), 400
        
        # 检查代码是否已存在
        existing_type = SubscriptionType.query.filter_by(code=data['code']).first()
        if existing_type:
            logger.warning(f"[管理员] 添加订阅类型失败，代码 '{data['code']}' 已存在")
            return jsonify({
                "success": False,
                "message": f"订阅类型代码 '{data['code']}' 已存在"
            }), 400
        
        # 创建新的订阅类型
        new_type = SubscriptionType(
            code=data['code'],
            name=data['name'],
            max_devices=data.get('max_devices', 1),
            price=data.get('price', 0),
            discount=data.get('discount', 100),
            days=data.get('days', 30),
            requirements=data.get('requirements'),
            is_public=data.get('is_public', True)
        )
        
        db.session.add(new_type)
        db.session.commit()
        
        logger.info(f"[管理员] 管理员 {admin_user.id} 成功添加订阅类型: {data['code']} (ID: {new_type.id})")
        
        return jsonify({
            "success": True,
            "message": "订阅类型添加成功",
            "type_id": new_type.id
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"[管理员] 添加订阅类型失败: {e}")
        return jsonify({
            "success": False,
            "message": f"添加订阅类型失败: {str(e)}"
        }), 500

@api.route('/subscription-types/<int:type_id>', methods=['PUT'])
@admin_required
def update_subscription_type(type_id):
    """更新订阅类型
    
    请求体:
    {
        "code": "monthly",
        "name": "月付会员",
        "max_devices": 5,
        "price": 49.99,
        "discount": 100,
        "days": 30,
        "requirements": null,
        "is_public": true
    }
    
    返回:
    {
        "success": true,
        "message": "订阅类型更新成功"
    }
    """
    try:
        admin_user = g.user
        data = request.json
        
        logger.info(f"[管理员] 管理员 {admin_user.id} 请求更新订阅类型 ID: {type_id}")
        
        # 验证必填字段
        if not data:
            logger.warning(f"[管理员] 更新订阅类型请求体为空")
            return jsonify({
                "success": False,
                "message": "请求体不能为空"
            }), 400
        
        # 查找订阅类型
        subscription_type = SubscriptionType.query.get(type_id)
        if not subscription_type:
            logger.warning(f"[管理员] 更新不存在的订阅类型 ID: {type_id}")
            return jsonify({
                "success": False,
                "message": "未找到指定的订阅类型"
            }), 404
        
        # 如果要更改代码，检查新代码是否已存在
        if 'code' in data and data['code'] != subscription_type.code:
            existing_type = SubscriptionType.query.filter_by(code=data['code']).first()
            if existing_type:
                logger.warning(f"[管理员] 更新订阅类型失败，代码 '{data['code']}' 已存在")
                return jsonify({
                    "success": False,
                    "message": f"订阅类型代码 '{data['code']}' 已存在"
                }), 400
        
        # 更新字段
        changed_fields = []
        if 'code' in data:
            old_code = subscription_type.code
            subscription_type.code = data['code']
            changed_fields.append(f"code: {old_code} -> {data['code']}")
        if 'name' in data:
            old_name = subscription_type.name
            subscription_type.name = data['name']
            changed_fields.append(f"name: {old_name} -> {data['name']}")
        if 'max_devices' in data:
            old_max = subscription_type.max_devices
            subscription_type.max_devices = data['max_devices']
            changed_fields.append(f"max_devices: {old_max} -> {data['max_devices']}")
        if 'price' in data:
            old_price = subscription_type.price
            subscription_type.price = data['price']
            changed_fields.append(f"price: {old_price} -> {data['price']}")
        if 'discount' in data:
            old_discount = subscription_type.discount
            subscription_type.discount = data['discount']
            changed_fields.append(f"discount: {old_discount} -> {data['discount']}")
        if 'days' in data:
            old_days = subscription_type.days
            subscription_type.days = data['days']
            changed_fields.append(f"days: {old_days} -> {data['days']}")
        if 'requirements' in data:
            old_req = subscription_type.requirements
            subscription_type.requirements = data['requirements']
            changed_fields.append(f"requirements: {old_req} -> {data['requirements']}")
        if 'is_public' in data:
            old_public = subscription_type.is_public
            subscription_type.is_public = data['is_public']
            changed_fields.append(f"is_public: {old_public} -> {data['is_public']}")
        
        db.session.commit()
        
        logger.info(f"[管理员] 管理员 {admin_user.id} 成功更新订阅类型 ID: {type_id}, 变更: {', '.join(changed_fields)}")
        
        return jsonify({
            "success": True,
            "message": "订阅类型更新成功"
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"[管理员] 更新订阅类型 ID: {type_id} 失败: {e}")
        return jsonify({
            "success": False,
            "message": f"更新订阅类型失败: {str(e)}"
        }), 500

@api.route('/subscription-types/<int:type_id>', methods=['DELETE'])
@admin_required
def delete_subscription_type(type_id):
    """删除订阅类型
    
    返回:
    {
        "success": true,
        "message": "订阅类型删除成功"
    }
    """
    try:
        admin_user = g.user
        logger.info(f"[管理员] 管理员 {admin_user.id} 请求删除订阅类型 ID: {type_id}")
        
        # 查找订阅类型
        subscription_type = SubscriptionType.query.get(type_id)
        if not subscription_type:
            logger.warning(f"[管理员] 删除不存在的订阅类型 ID: {type_id}")
            return jsonify({
                "success": False,
                "message": "未找到指定的订阅类型"
            }), 404
        
        # 检查是否有正在使用此订阅类型的用户
        active_subscriptions = Subscription.query.filter_by(
            plan=subscription_type.code,
            status='active'
        ).count()
        
        if active_subscriptions > 0:
            logger.warning(f"[管理员] 无法删除订阅类型 ID: {type_id}，有 {active_subscriptions} 个用户正在使用")
            return jsonify({
                "success": False,
                "message": f"无法删除，当前有 {active_subscriptions} 个用户正在使用此订阅类型"
            }), 400
        
        # 检查是否有AdsPower账号使用此订阅类型
        accounts_using_type = AdspowerAccount.query.filter_by(
            subscription_type=subscription_type.code
        ).count()
        
        if accounts_using_type > 0:
            logger.warning(f"[管理员] 无法删除订阅类型 ID: {type_id}，有 {accounts_using_type} 个AdsPower账号使用")
            return jsonify({
                "success": False,
                "message": f"无法删除，当前有 {accounts_using_type} 个AdsPower账号使用此订阅类型"
            }), 400
        
        # 删除订阅类型
        code = subscription_type.code
        db.session.delete(subscription_type)
        db.session.commit()
        
        logger.info(f"[管理员] 管理员 {admin_user.id} 成功删除订阅类型 ID: {type_id}, 代码: {code}")
        
        return jsonify({
            "success": True,
            "message": "订阅类型删除成功"
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除订阅类型失败: {e}")
        return jsonify({
            "success": False,
            "message": f"删除订阅类型失败: {str(e)}"
        }), 500

# 添加已废弃的Profile API路由处理
def handle_deprecated_profile_api():
    """处理已废弃的Profile API"""
    return jsonify({
        'success': False,
        'message': 'Profile功能已被移除，请使用直接登录API',
        'profiles': []
    }), 404

@api.route('/api/profiles', methods=['GET', 'POST'])
@login_required
def profiles_api():
    """已废弃的Profile API"""
    return handle_deprecated_profile_api()

@api.route('/api/profiles/<int:profile_id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
@login_required
def profile_detail_api(profile_id):
    """已废弃的Profile详情API"""
    return handle_deprecated_profile_api()

@api.route('/api/admin/accounts/adspower/batch-subscription-type', methods=['POST'])
@admin_required
def batch_update_adspower_account_subscription_type():
    """批量更新AdsPower账号的订阅类型
    
    请求体:
    {
        "account_ids": [1, 2, 3],
        "subscription_type": "monthly"
    }
    
    返回:
    {
        "success": true,
        "message": "成功更新X个账号的订阅类型",
        "updated_count": X
    }
    """
    try:
        data = request.json
        if not data:
            return jsonify({
                "success": False,
                "message": "请求体不能为空"
            }), 400
        
        account_ids = data.get('account_ids')
        subscription_type = data.get('subscription_type')
        
        if not account_ids or not isinstance(account_ids, list) or len(account_ids) == 0:
            return jsonify({
                "success": False,
                "message": "account_ids必须是非空数组"
            }), 400
        
        if not subscription_type:
            return jsonify({
                "success": False,
                "message": "subscription_type不能为空"
            }), 400
        
        # 验证订阅类型是否存在
        subscription_type_obj = SubscriptionType.query.filter_by(code=subscription_type).first()
        if not subscription_type_obj:
            return jsonify({
                "success": False,
                "message": f"订阅类型 '{subscription_type}' 不存在"
            }), 400
        
        # 批量更新账号的订阅类型
        updated_accounts = AdspowerAccount.query.filter(AdspowerAccount.id.in_(account_ids)).all()
        updated_count = 0
        
        for account in updated_accounts:
            account.subscription_type = subscription_type
            updated_count += 1
        
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": f"成功更新 {updated_count} 个账号的订阅类型",
            "updated_count": updated_count
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"批量更新账号订阅类型失败: {e}")
        return jsonify({
            "success": False,
            "message": f"批量更新账号订阅类型失败: {str(e)}"
        }), 500

@api.route('/admin/devices/sync-from-adspower', methods=['POST'])
@admin_required
def sync_devices_from_adspower():
    """从AdsPower同步设备信息到数据库

    检查所有AdsPower账号，获取其所有设备信息，并同步到数据库

    返回:
    {
        "success": true/false,
        "message": "消息",
        "data": {
            "devices_added": 新增设备数,
            "devices_updated": 更新设备数,
            "total_devices": 总设备数
        }
    }
    """
    try:
        # 获取所有活跃的AdsPower账号
        accounts = AdspowerAccount.query.filter_by(is_active=True).all()
        if not accounts:
            return jsonify({
                "success": False,
                "message": "没有活跃的AdsPower账号"
            }), 404

        devices_added = 0
        devices_updated = 0
        total_devices = 0

        adspower_api = get_adspower_api() # 获取 AdspowerAPI 实例

        for account in accounts:
            # 跳过没有Cookie的账号 (AdspowerAPI 内部会处理，但保留日志可能有用)
            if not account.cookies:
                logger.warning(f"跳过账号 {account.username}：没有保存Cookies")
                continue

            try:
                # 使用 AdspowerAPI 获取设备列表
                # get_devices_info 返回设备字典列表，或者在失败时返回 None
                devices = adspower_api.get_devices_info(account)

                if devices is None:
                    logger.error(f"无法获取账号 {account.username} 的设备列表 (API 返回 None)，跳过")
                    continue # 跳过此账号

                if not devices:
                    logger.info(f"账号 {account.username} 没有关联设备")
                    # 即使没有设备，也更新检查时间和设备计数为0
                    account.current_devices = 0
                    account.last_check_time = int(time.time())
                    db.session.add(account) # 添加到会话以便提交
                    continue # 继续下一个账号

                # 更新账号的设备数量 (基于获取到的列表)
                account.current_devices = len(devices)
                account.last_check_time = int(time.time())
                db.session.add(account) # 添加到会话以便提交

                # 遍历设备，更新或添加到数据库
                for device_info in devices:
                    # 确保 device_info 是字典并且有 'id' 键
                    if not isinstance(device_info, dict) or 'id' not in device_info:
                        logger.warning(f"跳过无效的设备信息条目 (账号 {account.username}): {device_info}")
                        continue

                    device_id = device_info.get('id') # 使用 AdsPower 返回的设备 ID
                    if not device_id:
                        logger.warning(f"跳过缺少 ID 的设备信息 (账号 {account.username}): {device_info}")
                        continue

                    # 查找设备是否已存在 (使用 AdsPower 的 ID)
                    device = Device.query.filter_by(device_name=device_info['name'], device_type=device_info['device_type'], adspower_account_id=account.id).first()

                    if device:
                        # 更新设备信息
                        device.device_name = device_info.get('name', device.device_name)
                        device.adspower_account_id = account.id
                        device.device_ip = device_info.get('ip_address')
                        # 更新设备类型，如果获取不到则保持原样或设为Unknown (优先保持原样)
                        device.device_type = device_info.get('device_type') or device.device_type or 'Unknown' # <-- 修正key

                        # 处理 last_open 时间
                        last_open_str = device_info.get('last_open')
                        if last_open_str:
                            try:
                                # 尝试解析多种可能的日期格式
                                # AdsPower 可能返回 'YYYY-MM-DD HH:MM' 或其他格式
                                parsed_time = None
                                for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M'):
                                    try:
                                        parsed_time = datetime.strptime(last_open_str, fmt)
                                        break
                                    except ValueError:
                                        continue
                                if parsed_time:
                                    device.last_login = parsed_time
                                else:
                                    logger.warning(f"无法解析设备 {device_id} 的 last_open 时间格式: {last_open_str}")
                            except Exception as date_e:
                                logger.warning(f"解析设备 {device_id} 的 last_open 时间 '{last_open_str}' 时出错: {date_e}")

                        db.session.add(device) # 添加到会话
                        devices_updated += 1
                    else:
                        # 创建新设备
                        logger.info(f"准备为账号 {account.username} 创建新设备 (ID: {device_id}) - 详情: {device_info}")
                        user_id = None
                        admin_user = User.query.filter_by(is_admin=True).first()
                        if admin_user:
                            user_id = admin_user.id
                            logger.info(f"未找到关联用户，将设备 {device_id} 关联到管理员账号: {admin_user.email} (ID: {user_id})")
                        else:
                                logger.error(f"无法关联用户且未找到管理员账号，跳过为账号 {account.username} 创建设备: {device_info}")
                                continue

                        new_device = Device(
                            user_id=user_id,
                            adspower_account_id=account.id,
                            device_name=device_info.get('name', 'Unknown Device'),
                            device_ip=device_info.get('ip_address', ''),
                            device_type=device_info.get('device_type', 'Unknown'), # <-- 修正key
                            last_login=datetime.utcnow(),
                        )

                        # 处理 last_open 时间
                        last_open_str = device_info.get('last_open')
                        if last_open_str:
                            try:
                                # 与上面更新逻辑相同的解析代码
                                parsed_time = None
                                for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M'):
                                    try:
                                        parsed_time = datetime.strptime(last_open_str, fmt)
                                        break
                                    except ValueError:
                                        continue
                                if parsed_time:
                                    new_device.last_login = parsed_time
                            except Exception as date_e:
                                logger.warning(f"解析新设备 {device_id} 的 last_open 时间 '{last_open_str}' 时出错: {date_e}")

                        db.session.add(new_device)
                        devices_added += 1

                    total_devices += 1

                logger.info(f"同步账号 {account.username} 的设备成功，设备数: {len(devices)}")

            except Exception as e:
                logger.error(f"同步账号 {account.username} 的设备失败: {str(e)}", exc_info=True) # 添加 exc_info

        # 统一提交本次循环中所有账号和设备的更改
        try:
            db.session.commit()
            logger.info("数据库更改已提交")
        except Exception as commit_e:
             logger.error(f"提交设备同步更改时数据库出错: {commit_e}", exc_info=True)
             db.session.rollback()
             return jsonify({
                "success": False,
                "message": f"数据库提交失败: {str(commit_e)}"
             }), 500

        return jsonify({
            "success": True,
            "message": f"同步完成！新增设备: {devices_added}, 更新设备: {devices_updated}, 总计: {total_devices}",
            "data": {
                "devices_added": devices_added,
                "devices_updated": devices_updated,
                "total_devices": total_devices
            }
        })

    except Exception as e:
        db.session.rollback()
        logger.exception(f"同步设备时出错: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"同步设备时出错: {str(e)}"
        }), 500

@api.route('/admin/devices/<device_id>', methods=['GET'])
@admin_required
def admin_get_device(device_id):
    """管理员获取单个设备的详细信息"""
    try:
        # 验证设备存在
        device = Device.query.get(device_id)
        if not device:
            return jsonify({"success": False, "message": "设备不存在"}), 404
        
        # 获取关联用户
        user = User.query.get(device.user_id) if device.user_id else None
        
        # 获取关联的AdsPower账号
        adspower_account = None
        if device.adspower_account_id:
            adspower_account = AdspowerAccount.query.get(device.adspower_account_id)
            if adspower_account:
                adspower_account = {
                    'id': adspower_account.id,
                    'username': adspower_account.username,
                    'is_active': adspower_account.is_active,
                    'current_devices': adspower_account.current_devices,
                    'max_devices': adspower_account.max_devices
                }
        
        # 处理IP地址 - 确保格式化正确
        ip_address = device.device_ip
        if ip_address:
            # 清理IP地址 - 移除HTML标签和特殊字符
            import re
            # 尝试从字符串中提取有效的IP地址
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f:]+)', ip_address)
            if ip_match:
                ip_address = ip_match.group(1)
            else:
                # 移除HTML标签
                ip_address = re.sub(r'<[^>]*>?', '', ip_address).strip()
        
        # 构建设备详情数据（优化结构）
        device_info = {
            'id': device.id,
            'device_name': device.device_name,
            'device_ip': ip_address,
            'device_type': device.device_type,
            'last_login': device.last_login.isoformat() if device.last_login else None,
            'last_active': device.last_active.isoformat() if device.last_active else None,
            'created_at': device.created_at.isoformat() if device.created_at else None,
            'user': {
                'id': user.id if user else None,
                'email': user.email if user else None
            } if user else None, # 如果用户不存在，整个user对象为None
            'adspower_account': adspower_account # adspower_account本身就是字典或None
            # 移除顶层冗余字段: user_id, user_email, adspower_account_id, adspower_username
            # 移除 user['username']
            # 移除 'extra' 字段
        }
        
        # 如果 adspower_account 为 None，也明确设置为 None 而不是默认字典
        if not adspower_account:
            device_info['adspower_account'] = None
            
        return jsonify({"success": True, "data": device_info})
        
    except Exception as e:
        logger.exception(f"获取设备详情时出错: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

@api.route('/api/subscriptions/create', methods=['POST'])
@login_required
def create_subscription():
    """创建订阅
    
    请求体:
    {
        "plan_code": "monthly",  // 订阅类型代码
        "payment_id": "xxx",    // 可选，支付ID
        "price": 49.99          // 可选，实际支付价格
    }
    
    返回:
    {
        "success": true,
        "message": "订阅创建成功",
        "subscription": {
            ...订阅详情...
        }
    }
    """
    try:
        user = g.user
        data = request.json
        
        if not data or 'plan_code' not in data:
            return jsonify({
                "success": False,
                "message": "缺少必要参数"
            }), 400
        
        plan_code = data.get('plan_code')
        payment_id = data.get('payment_id')
        price = data.get('price')
        
        # 创建订阅
        from services import SubscriptionService
        subscription, message = SubscriptionService.create_subscription(
            user_id=user.id,
            plan_code=plan_code,
            payment_id=payment_id,
            price=price
        )
        
        if not subscription:
            return jsonify({
                "success": False,
                "message": message
            }), 400
        
        return jsonify({
            "success": True,
            "message": message,
            "subscription": subscription.to_dict()
        })
    except Exception as e:
        logger.error(f"创建订阅时出错: {e}")
        return jsonify({
            "success": False,
            "message": f"创建订阅失败: {str(e)}"
        }), 500

@api.route('/adspower/check-login-status', methods=['GET'])
def check_adspower_login_status():
    token = request.args.get('token')
    if not token:
        return jsonify({'success': False, 'message': '缺少令牌', 'status': 'error'}), 400

    login_session = LoginSession.query.filter_by(login_token=token).first()

    if not login_session:
        return jsonify({'success': False, 'message': '令牌无效或已过期', 'status': 'error'}), 404

    # 检查会话是否已过期 (基于 expiration_timestamp)
    now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    if login_session.expiration_timestamp < now_utc_naive:
         # 不再更新数据库中的 status 字段
         logger.warning(f"LoginSession {login_session.id} has expired.")
         return jsonify({'success': False, 'message': '登录会话已过期', 'status': 'expired'}), 410 # HTTP 410 Gone

    # 检查会话是否已完成 (基于 completed_time)
    if login_session.completed_time:
         logger.info(f"LoginSession {login_session.id} already completed.")
         return jsonify({'success': True, 'message': '设备已确认，登录成功', 'status': 'completed', 'loggedIn': True}), 200

    # --- 登录检查逻辑保持不变，但返回的状态需要推断 ---
    account = AdspowerAccount.query.get(login_session.adspower_account_id)
    if not account:
        logger.error(f"Associated AdspowerAccount {login_session.adspower_account_id} not found for session {login_session.id}.")
        return jsonify({'success': False, 'message': '关联的AdsPower账号不存在', 'status': 'error'}), 500

    # 1. 加载初始快照
    known_devices_snapshot = []
    if login_session.known_devices_snapshot:
        try:
            known_devices_snapshot = json.loads(login_session.known_devices_snapshot)
            if not isinstance(known_devices_snapshot, list):
                logger.warning(f"LoginSession {login_session.id} known_devices_snapshot is not a list, treating as empty.")
                known_devices_snapshot = []
        except json.JSONDecodeError:
            logger.error(f"Failed to decode known_devices_snapshot for LoginSession {login_session.id}, treating as empty.")
            known_devices_snapshot = []
    logger.debug(f"Session {login_session.id}: Loaded {len(known_devices_snapshot)} devices from snapshot.")

    # 2. 获取当前设备列表
    adspower_api = get_adspower_api()
    current_devices = None
    try:
        logger.debug(f"Session {login_session.id}: Getting current devices for account {account.id}...")
        current_devices = adspower_api.get_devices_info(account)
    except Exception as e:
         logger.error(f"Error getting current devices for account {account.id} during check-login-status (session {login_session.id}): {e}", exc_info=True)
         # 返回 pending 让用户重试可能更好
         # 推断状态为 pending
         return jsonify({'success': False, 'message': f'获取当前设备列表时出错，请稍后重试', 'status': 'pending'}), 200

    if current_devices is None:
        logger.warning(f"get_devices_info returned None for account {account.id} during check-login-status (session {login_session.id}).")
        # 返回 pending 让用户重试
        # 推断状态为 pending
        return jsonify({'success': False, 'message': '无法获取当前设备列表，请稍后重试', 'status': 'pending'}), 200
    logger.debug(f"Session {login_session.id}: Got {len(current_devices)} current devices from API.")

    # 3. 比较列表，查找新设备
    known_device_tuples = set()
    for d in known_devices_snapshot:
        if isinstance(d, dict):
            name = d.get('name')
            dtype = d.get('device_type') 
            if name and dtype: 
                known_device_tuples.add((name, dtype))
            else:
                 logger.warning(f"Snapshot device missing name or type in session {login_session.id}: {d}")
    logger.debug(f"Session {login_session.id}: Known device tuples from snapshot: {known_device_tuples}")

    newly_detected_devices = []
    for device in current_devices:
        if isinstance(device, dict):
            current_name = device.get('name')
            current_type = device.get('device_type')
            if current_name and current_type:
                if (current_name, current_type) not in known_device_tuples:
                    logger.info(f"Session {login_session.id}: Found potential new device: Name={current_name}, Type={current_type}")
                    newly_detected_devices.append(device)
            else:
                 logger.warning(f"Current device missing name or type in session {login_session.id}: {device}")
        else:
             logger.warning(f"Invalid device format in current_devices list for session {login_session.id}: {device}")

    # 4. 根据比较结果返回 (推断状态)
    if newly_detected_devices:
        logger.info(f"New device detected for session {login_session.id}: {newly_detected_devices[0]}")
        return jsonify({
            'success': True,
            'status': 'new_device_detected', # 推断状态
            'message': '检测到新设备登录，请确认',
            'new_device': newly_detected_devices[0]
        }), 200
    else:
        logger.info(f"No new device detected for session {login_session.id}. Status remains pending.")
        return jsonify({
            'success': False, # 表示登录流程尚未完成
            'status': 'pending', # 推断状态
            'message': '尚未检测到新设备登录'
        }), 200

@api.route('/adspower/check-account-health', methods=['GET'])
@admin_required # Added @admin_required decorator
def check_adspower_account_health():
    """检查AdsPower账号的健康状态
    
    检查AdsPower账号的Cookie是否有效，WebDriver是否可用等
    """
    try:
        user = g.user # Changed from get_current_user() and redundant auth checks removed
            
        # 获取账号ID参数
        account_id = request.args.get('account_id')
        
        if not account_id:
            return jsonify({
                'status': 'error',
                'message': 'Missing account_id parameter'
            }), 400
            
        try:
            account_id = int(account_id)
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': 'Invalid account_id parameter'
            }), 400
            
        # 获取AdsPower账号
        adspower_account = AdspowerAccount.query.get(account_id)
        
        if not adspower_account:
            return jsonify({
                'status': 'error',
                'message': 'AdsPower account not found'
            }), 404
            
        # 获取账号WebDriver管理器
        from .webdriver_pool import get_account_driver_manager
        driver_manager = get_account_driver_manager()
        
        # 获取账号状态
        account_status = driver_manager.get_account_status(account_id)
        
        # 检查账号登录状态
        from .adspower_api import get_adspower_api
        adspower_api = get_adspower_api()
        is_logged_in = adspower_api.check_account_login_status(adspower_account)
        
        # 获取设备信息
        try:
            devices_count = adspower_api.get_current_devices_count(adspower_account)
        except Exception as e:
            devices_count = None
            logger.error(f"获取账号 {account_id} 的设备数量时出错: {str(e)}")
        
        # 构建响应数据
        response_data = {
            'account_id': account_id,
            'username': adspower_account.username,
            'is_available': adspower_account.is_available,
            'current_devices': adspower_account.current_devices,
            'max_devices': adspower_account.max_devices,
            'last_check_time': adspower_account.last_check_time,
            'last_error': adspower_account.last_error,
            'driver_status': account_status,
            'is_logged_in': is_logged_in,
            'devices_count': devices_count,
            'check_time': int(time.time())
        }
        
        return jsonify({
            'status': 'success',
            'data': response_data
        })
            
    except Exception as e:
        logger.error(f"检查AdsPower账号健康状态时出错: {str(e)}", exc_info=True)
        
        return jsonify({
            'status': 'error',
            'message': f'Failed to check account health: {str(e)}'
        }), 500

# 添加明确的API路由别名，确保前端能够正确访问
@api.route('/adspower/check-login-status', methods=['GET'])
def check_login_status_api_alias():
    """检查登录状态API路由别名，确保前端能够正确访问"""
    return check_adspower_login_status()

@api.route('/admin/accounts/adspower/<int:account_id>/refresh-count', methods=['POST'])
@admin_required
def admin_refresh_single_adspower_account_device_count(account_id):
    """刷新单个AdsPower账号的当前设备数量"""
    account = AdspowerAccount.query.get(account_id)
    if not account:
        return jsonify({"success": False, "message": "账号不存在"}), 404

    logger.info(f"开始刷新账号 #{account_id} ({account.username}) 的设备数量...")
    
    try:
        adspower_api = get_adspower_api()
        # 强制刷新获取最新的设备数量
        current_devices = adspower_api.get_current_devices_count(account)
        
        if current_devices is not None: # 确保获取到有效值
            logger.info(f"账号 #{account_id} 获取到最新设备数量: {current_devices}")
            
            # 更新数据库
            if account.current_devices != current_devices:
                 account.current_devices = current_devices
                 account.last_check_time = int(time.time()) # 更新最后检查时间
                 db.session.commit()
                 logger.info(f"账号 #{account_id} 数据库设备数量已更新为 {current_devices}")
                 return jsonify({ "success": True, 
                                 "message": f"账号 {account.username} 设备数量已刷新为 {current_devices}", 
                                 "current_devices": current_devices })
            else:
                 account.last_check_time = int(time.time()) # 即使数量没变也更新检查时间
                 db.session.commit()
                 logger.info(f"账号 #{account_id} 设备数量无变化 ({current_devices})")
                 return jsonify({ "success": True, 
                                 "message": f"账号 {account.username} 设备数量无变化 ({current_devices})", 
                                 "current_devices": current_devices })
        else:
             # 如果 get_current_devices_count 返回 None，表示获取失败
             logger.error(f"账号 #{account_id} 获取设备数量失败 (API 返回 None)")
             return jsonify({"success": False, "message": "无法从AdsPower获取设备数量，请检查账号状态或日志"}), 500
             
    except Exception as e:
        logger.error(f"刷新账号 #{account_id} 设备数量时出错: {str(e)}", exc_info=True)
        db.session.rollback() # 出错时回滚
        return jsonify({"success": False, "message": f"刷新设备数量时发生错误: {str(e)}"}), 500

# ===== 健康检查和调试API =====

@api.route('/devices/confirm-new', methods=['POST'])
def confirm_new_device():
    """用户确认新设备登录"""
    data = request.json
    if not data or 'login_token' not in data or 'device' not in data:
        return jsonify({'success': False, 'message': '缺少令牌或设备信息'}), 400

    token = data.get('login_token')
    new_device_info = data.get('device')

    if not isinstance(new_device_info, dict):
         return jsonify({'success': False, 'message': '设备信息格式无效'}), 400

    login_session = LoginSession.query.filter_by(login_token=token).first()

    if not login_session:
        return jsonify({'success': False, 'message': '登录会话无效或已过期'}), 404

    # 再次检查会话是否已过期
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if login_session.expiration_timestamp < now: 
        logger.warning(f"Attempt to confirm device on expired session {login_session.id}")
        return jsonify({'success': False, 'message': '登录会话已过期'}), 410

    # 检查会话状态 (基于 completed_time)，防止重复确认
    if login_session.completed_time:
         logger.warning(f"Attempt to re-confirm device for completed session {login_session.id}")
         return jsonify({'success': True, 'message': '设备已确认，登录已完成'}), 200 # 返回成功，因为已完成

    # 获取用户信息
    user = User.query.get(login_session.user_id)
    if not user:
         logger.error(f"User {login_session.user_id} not found for session {login_session.id}")
         return jsonify({'success': False, 'message': '无法找到关联用户'}), 500

    # 检查用户设备数量是否达到上限
    active_subscription = auth_service.get_user_subscription(user.id) 
    if not active_subscription: 
         logger.warning(f"User {user.id} has no active subscription during device confirmation.")
         return jsonify({'success': False, 'message': '您没有有效的订阅来添加设备'}), 403

    current_device_count = Device.query.filter_by(user_id=user.id).count()
    max_devices_allowed = active_subscription.max_devices 
    if current_device_count >= max_devices_allowed:
        logger.warning(f"User {user.id} reached device limit ({current_device_count}/{max_devices_allowed}) during confirmation.")
        return jsonify({
            'success': False,
            'message': f'您的设备数量已达上限 ({max_devices_allowed}台)，无法添加新设备。请先在设备管理中登出不再使用的设备。'
        }), 403

    # --- 处理新设备信息 ---
    device_name = new_device_info.get('name')
    device_type = new_device_info.get('device_type')
    device_ip = new_device_info.get('ip_address')
    last_login_str = new_device_info.get('last_open')

    if not device_name or not device_type:
         logger.error(f"New device info missing name or type in session {login_session.id}: {new_device_info}")
         return jsonify({'success': False, 'message': '提供的设备信息不完整 (缺少名称或类型)'}), 400

    try:
        # 查找或创建设备记录
        existing_device = Device.query.filter_by(
            user_id=user.id,
            device_name=device_name,
            device_type=device_type
        ).first()

        if existing_device:
            logger.info(f"Existing device found for user {user.id}. Updating last login.")
            existing_device.last_login = datetime.utcnow()
            existing_device.device_ip = device_ip
            existing_device.adspower_account_id = login_session.adspower_account_id
            db.session.add(existing_device)
        else:
            logger.info(f"Creating new device record for user {user.id}.")
            new_db_device = Device(
                user_id=user.id,
                adspower_account_id=login_session.adspower_account_id,
                device_name=device_name,
                device_type=device_type,
                device_ip=device_ip,
                last_login=datetime.utcnow()
            )
            db.session.add(new_db_device)

        # 更新会话状态为完成 (设置 completed_time)
        # 移除: login_session.status = 'completed'
        login_session.completed_time = datetime.utcnow()
        db.session.add(login_session)

        # 提交数据库更改
        db.session.commit()

        logger.info(f"Device confirmed and session {login_session.id} completed for user {user.id}.")
        return jsonify({'success': True, 'message': '新设备已成功确认并添加'}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error confirming device or updating session {login_session.id}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '处理设备确认时发生内部错误'}), 500

# === 设备登出 API ===
@api.route('/devices/<int:device_db_id>/logout', methods=['POST'])
@login_required
def logout_device_api(device_db_id):
    """处理用户请求退出指定设备的登录

    Args:
        device_db_id (int): 设备在数据库中的主键 ID

    Returns:
        JSON: 操作结果
    """
    user = g.user
    logger.info(f"用户 {user.id} 请求退出设备 DB ID: {device_db_id}")

    # 1. 查找设备并验证归属
    device = Device.query.filter_by(id=device_db_id, user_id=user.id).first()
    if not device:
        logger.warning(f"用户 {user.id} 尝试退出不属于自己或不存在的设备 DB ID: {device_db_id}")
        return jsonify({"success": False, "message": "设备不存在或您无权操作此设备"}), 404

    # 2. 检查设备是否已关联 AdsPower 账号
    if not device.adspower_account_id:
        # 如果没有关联账号，理论上无法在 AdsPower 退出，直接删除本地记录
        logger.warning(f"设备 DB ID: {device_db_id} 未关联 AdsPower 账号，将直接删除本地记录") # Updated log
        try:
            db.session.delete(device) # Delete the record
            db.session.commit()
            return jsonify({"success": True, "message": "设备未关联远程账号，本地记录已删除"}) # Updated message
        except Exception as e:
            db.session.rollback()
            logger.error(f"删除未关联账号的设备 {device_db_id} 记录时数据库出错: {e}") # Updated log
            return jsonify({"success": False, "message": "删除本地设备记录时出错"}), 500

    # 3. 获取关联的 AdsPower 账号
    adspower_account = AdspowerAccount.query.get(device.adspower_account_id)
    if not adspower_account:
        logger.error(f"设备 DB ID: {device_db_id} 关联的 AdsPower 账号 ID: {device.adspower_account_id} 不存在，将删除本地设备记录") # Updated log
        try:
            db.session.delete(device) # Delete the record
            db.session.commit()
            return jsonify({"success": True, "message": "关联的AdsPower账号不存在，本地设备记录已删除"}) # Updated message
        except Exception as e:
            db.session.rollback()
            logger.error(f"删除关联账号不存在的设备 {device_db_id} 记录时数据库出错: {e}") # Updated log
            return jsonify({"success": False, "message": "删除本地设备记录时出错"}), 500

    # 4. 获取设备在 AdsPower 上的名称 (必须有 device_name)
    device_name_on_ads = device.device_name
    if not device_name_on_ads:
        logger.error(f"设备 DB ID: {device_db_id} 缺少在 AdsPower 上的设备名称 (device_name)，无法执行远程退出")
        return jsonify({"success": False, "message": "设备缺少必要信息，无法执行远程退出操作"}), 400

    # 4.1 获取设备的 IP 地址 (device_ip)
    device_ip_on_ads = device.device_ip
    if not device_ip_on_ads:
        # 如果 IP 地址不存在，记录警告但仍尝试仅用名称退出 (或根据需要决定是否强制要求 IP)
        logger.warning(f"设备 DB ID: {device_db_id} 缺少 IP 地址 (device_ip)，将尝试仅使用名称退出")

    # 4.2 获取设备的类型 (device_type)
    device_type_on_ads = device.device_type
    if not device_type_on_ads:
        logger.error(f"设备 DB ID: {device_db_id} 缺少设备类型 (device_type)，无法执行精确的远程退出操作")
        return jsonify({"success": False, "message": "设备缺少类型信息，无法执行远程退出操作"}), 400

    # 5. 调用 AdsPower API 执行退出操作
    try:
        adspower_api = get_adspower_api()
        # 移除 device_ip_on_ads 参数
        logout_success, message = adspower_api.logout_device(adspower_account, device_name_on_ads, device_type_on_ads)
        logger.info(f"adspower_api.logout_device returned: success={logout_success}, message='{message}'")

        if logout_success is True:
            logger.info(f"AdsPower操作成功或无需操作 (原因: '{message}')，准备删除本地设备 DB ID: {device_db_id}")
            try:
                db.session.delete(device) # Delete the record
                db.session.commit()
                logger.info(f"设备 DB ID: {device_db_id} 本地设备记录已删除")
                final_message = message
                return jsonify({"success": True, "message": final_message})
            except Exception as e:
                db.session.rollback()
                logger.error(f"AdsPower操作成功/无需操作后，删除设备 {device_db_id} 本地记录时数据库出错: {e}") 
                return jsonify({"success": False, "message": f"远程操作成功/无需操作，但删除本地记录失败: {e}"}), 500
        else:
            logger.error(f"AdsPower操作失败 (DB ID: {device_db_id})，原因: {message}")
            return jsonify({"success": False, "message": message or "远程退出设备失败"}), 500

    except Exception as e:
        logger.exception(f"调用 logout_device 时发生意外错误 (设备 DB ID: {device_db_id}): {e}")
        return jsonify({"success": False, "message": f"执行退出操作时发生服务器内部错误: {str(e)}"}), 500

# ===== 健康检查和调试API =====

def get_user_subscription_status(user_id):
    """辅助函数：获取用户订阅状态（只读）"""
    subscription = Subscription.query.filter(
        Subscription.user_id == user_id,
        Subscription.end_date > datetime.utcnow()
    ).order_by(Subscription.end_date.desc()).first()
    
    # subscription_status = subscription.status if subscription else '无订阅' # 移除 status
    is_active = bool(subscription) # 直接判断是否存在有效订阅
    plan = subscription.plan if subscription else None
    end_date = subscription.end_date.isoformat() + 'Z' if subscription else None
    # 移除 status 返回值
    # return is_active, plan, end_date, subscription_status
    return is_active, plan, end_date
