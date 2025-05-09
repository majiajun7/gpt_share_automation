import logging
import json
from datetime import datetime, timedelta

from flask import Blueprint, render_template
import pyotp
import time

from .models import db, LoginSession, AdspowerAccount
from .adspower_api import get_adspower_api

# 配置日志
logger = logging.getLogger(__name__)

# 创建页面蓝图 (没有URL前缀)
main_bp = Blueprint('main', __name__)

# --- 移动过来的直接登录页面路由 ---
@main_bp.route('/adspower/direct-login/<token>', methods=['GET'])
def adspower_direct_login(token):
    """处理AdsPower直接登录页面
    
    Args:
        token: 登录令牌
        
    Returns:
        渲染的登录页面或错误页面
    """
    try:
        # 验证令牌
        login_session = LoginSession.query.filter_by(login_token=token).first()
        if not login_session:
            return render_template('error.html',
                                  error_title="登录失败",
                                  error_message="无效的登录令牌"), 400
        
        # 获取AdsPower账号信息
        adspower_account = AdspowerAccount.query.get(login_session.adspower_account_id)
        if not adspower_account:
            return render_template('error.html',
                                  error_title="登录失败",
                                  error_message="未找到AdsPower账号信息"), 404
        
        # --- 修改：计算过期时间戳 ---
        session_duration = getattr(login_session, 'session_duration_seconds', 120) # Default 120 seconds
        expiration_timestamp = login_session.login_time + timedelta(seconds=session_duration)
        now_utc = datetime.utcnow()

        # 检查会话是否已过期
        if now_utc >= expiration_timestamp:
            if login_session.login_status != 'expired':
                login_session.login_status = 'expired'
                db.session.commit()
            return render_template('error.html',
                                  error_title="会话已过期",
                                  error_message="登录会话已过期，请返回重新获取登录链接"), 400

        # 更新会话状态 (如果需要)
        if login_session.login_status == 'pending': # Only update if pending
            login_session.login_status = 'active'
            db.session.commit()
        # --- 修改结束 ---
        
        # --- 移除此处获取和存储初始设备信息的逻辑 --- 
        # initial_count_exists = hasattr(login_session, 'initial_devices_count')
        # initial_count_value = getattr(login_session, 'initial_devices_count', None) if initial_count_exists else None

        # if initial_count_exists and initial_count_value is None:
        #     try:
        #         ads_api = get_adspower_api()
        #         devices = ads_api.get_devices_info(adspower_account, force_refresh=True)
        #         if devices is None:
        #             devices = []
        #         other_devices = [d for d in devices if isinstance(d, dict) and d.get('status') == 'inactive']
        #         login_session.initial_devices_count = len(other_devices)
        #         login_session.initial_devices_info = json.dumps(other_devices) # 保存初始设备信息列表
        #         db.session.commit()
        #         logger.info(f"为会话 {token} 存储了 {len(other_devices)} 个初始设备数量")
        #     except Exception as e:
        #         logger.error(f"为会话 {token} 获取初始设备信息时出错: {str(e)}", exc_info=True)
        #         login_session.initial_devices_count = 0
        #         login_session.initial_devices_info = json.dumps([]) # 保存空列表以防出错
        #         db.session.commit()
        # elif not initial_count_exists:
        #      logger.error(f"Database schema mismatch: LoginSession missing 'initial_devices_count' for session {token}")

        # 生成当前的TOTP验证码
        totp_code = None
        time_remaining_totp = 30 # Default TOTP remaining time
        if adspower_account.totp_secret:
            try:
                totp = pyotp.TOTP(adspower_account.totp_secret)
                totp_code = totp.now()
                current_time = int(time.time())
                time_step = 30
                next_step = ((current_time // time_step) + 1) * time_step
                time_remaining_totp = next_step - current_time
                logger.info(f"已为账号 {adspower_account.username} 生成TOTP验证码，剩余有效期: {time_remaining_totp}秒")
            except Exception as e:
                logger.error(f"生成TOTP验证码时出错: {str(e)}")
        
        # 渲染登录页面, 传递过期时间戳
        return render_template('adspower_login.html',
                              username=adspower_account.username,
                              password=adspower_account.password,
                              totp_secret=adspower_account.totp_secret,
                              account_id=adspower_account.id,
                              login_token=token,
                              totp_code=totp_code,
                              time_remaining_totp=time_remaining_totp, # Pass TOTP specific remaining time
                              expiration_timestamp_iso=expiration_timestamp.isoformat() + 'Z' # Pass expiration timestamp in ISO format (UTC)
                              )
        
    except Exception as e:
        logger.exception(f"处理AdsPower直接登录页面时出错: {str(e)}")
        return render_template('error.html',
                              error_title="服务器错误",
                              error_message=f"处理登录请求时出错: {str(e)}"), 500
# --- 移动路由结束 --- 