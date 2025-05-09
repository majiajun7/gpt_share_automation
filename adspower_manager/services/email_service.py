import random
# Remove smtplib, ssl, socket, email.mime.*, email.header
# import smtplib
# import logging
# import ssl
# import socket
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# from email.header import Header
import logging # Keep logging
from datetime import datetime, timedelta
import os
# from flask_mail import Message # Import later inside function if preferred, or keep here
from threading import Thread
from flask import current_app, render_template

# 使用直接导入，假设根目录已在 sys.path 中
from extensions import mail # Keep this import

# 使用相对导入 models (models.py 在上一级)
from ..models import EmailVerification, db

# 配置日志
logger = logging.getLogger(__name__)

# Remove SECURE_CIPHERS constant
# SECURE_CIPHERS = (
#     "..."
# )

class EmailService:
    """邮件服务，用于发送验证码和通知邮件 (使用 Flask-Mail)"""

    def __init__(self, app=None):
        """初始化邮件服务 (简化)

        Args:
            app: Flask应用实例
        """
        # We don't need to store config values here anymore,
        # Flask-Mail reads them from the app context.
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """通过应用实例配置邮件服务 (简化)

        Args:
            app: Flask应用实例
        """
        # Can potentially be empty if Flask-Mail is initialized elsewhere,
        # but logging is good.
        logger.info(f"EmailService using Flask-Mail initialized.")
        # Log some config values read by Flask-Mail for verification
        try:
            logger.info(f"Flask-Mail Config: Server={app.config.get('MAIL_SERVER')}, Port={app.config.get('MAIL_PORT')}, SSL={app.config.get('MAIL_USE_SSL')}, TLS={app.config.get('MAIL_USE_TLS')}")
        except Exception as e:
            logger.warning(f"Could not log Flask-Mail config during init_app: {e}")

    def generate_verification_code(self, length=6):
        """生成数字验证码
        
        Args:
            length: 验证码长度，默认6位
            
        Returns:
            生成的验证码
        """
        digits = "0123456789"
        return ''.join(random.choice(digits) for _ in range(length))
    
    def send_verification_email(self, email, code_type="register"):
        """发送验证码邮件 (使用 Flask-Mail)

        Args:
            email: 收件人邮箱
            code_type: 验证码类型，register/login/reset

        Returns:
            (success, message, code): 成功状态，消息，验证码
        """
        # Import Message here to avoid potential circular imports if mail is initialized late
        from flask_mail import Message

        subjects = {
            "register": "【AI服务拼车共享平台】注册验证码",
            "login": "【AI服务拼车共享平台】登录验证码",
            "reset": "【AI服务拼车共享平台】密码重置验证码"
        }
        subject = subjects.get(code_type, "【AI服务拼车共享平台】验证码")
        code = self.generate_verification_code()

        try:
             from flask import current_app
             code_expiry_minutes_runtime = current_app.config.get('EMAIL_CODE_EXPIRY_MINUTES', 10)
        except Exception:
             code_expiry_minutes_runtime = 10 # Fallback
        expiry_time = datetime.utcnow() + timedelta(minutes=code_expiry_minutes_runtime)

        # Save code to DB (keep this logic)
        try:
            existing_verification = EmailVerification.query.filter_by(
                email=email,
                code_type=code_type,
                is_used=False
            ).first()
            if existing_verification:
                existing_verification.code = code
                existing_verification.expires_at = expiry_time
                existing_verification.created_at = datetime.utcnow()
            else:
                verification = EmailVerification(
                    email=email,
                    code=code,
                    code_type=code_type,
                    expires_at=expiry_time
                )
                db.session.add(verification)
            db.session.commit()
            logger.info(f"已生成{code_type}验证码: {email}")
        except Exception as e:
            logger.error(f"保存验证码时出错: {str(e)}")
            db.session.rollback()
            return False, "生成验证码失败，请稍后重试", None

        # Build HTML content (keep this)
        html_content = f"""
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ width: 100%; max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #f0f8ff; padding: 20px; text-align: center; border-bottom: 1px solid #ddd; }}
                .content {{ padding: 20px; }}
                .code {{ font-size: 24px; font-weight: bold; color: #007bff; letter-spacing: 5px; background-color: #e9ecef; padding: 10px 15px; border-radius: 5px; display: inline-block; margin: 10px 0; }}
                .footer {{ font-size: 12px; color: #6c757d; margin-top: 30px; text-align: center; border-top: 1px solid #eee; padding-top: 15px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>AI服务拼车共享平台</h2>
                </div>
                <div class="content">
                    <p>您好！</p>
                    <p>感谢您使用AI服务拼车共享平台。您的验证码是：</p>
                    <p class="code">{code}</p>
                    <p>此验证码将在 <strong>{code_expiry_minutes_runtime}分钟</strong> 后失效，请尽快完成验证。请勿将验证码告知他人。</p>
                    <p>如果您并未请求此验证码，请忽略本邮件。</p>
                </div>
                <div class="footer">
                    <p>此邮件由系统自动发送，请勿直接回复。</p>
                    <p>© {datetime.utcnow().year} AI服务拼车共享平台. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # --- Use Flask-Mail to send --- 
        try:
            # Create Flask-Mail Message object
            # Sender is automatically taken from MAIL_DEFAULT_SENDER
            msg = Message(subject=subject,
                          recipients=[email],
                          html=html_content)

            logger.debug(f"准备使用 Flask-Mail 发送邮件到: {email}")
            # Send the email using the mail extension
            mail.send(msg)
            logger.info(f"验证码邮件已通过 Flask-Mail 成功发送到: {email}")
            return True, "验证码已发送，请查收邮件", code

        except Exception as e:
            # Catch potential exceptions during mail.send()
            # These could be connection errors, auth errors, etc., handled by Flask-Mail/smtplib
            logger.exception(f"使用 Flask-Mail 发送邮件时出错: {e}")
            # You might want more specific error handling based on Flask-Mail exceptions if needed
            return False, f"发送邮件失败: {str(e)}", None
        # --- End Flask-Mail sending logic ---

    def verify_code(self, email, code, code_type="register"):
        """验证邮箱验证码
        
        Args:
            email: 邮箱
            code: 用户输入的验证码
            code_type: 验证码类型
            
        Returns:
            (success, message): 验证结果和消息
        """
        try:
            # 查询未使用的验证码记录
            verification = EmailVerification.query.filter_by(
                email=email,
                code=code,
                code_type=code_type,
                is_used=False
            ).first()
            
            if not verification:
                logger.warning(f"验证码不存在或已使用: {email}")
                return False, "验证码错误或已失效"
            
            # 检查验证码是否过期
            if verification.expires_at < datetime.utcnow():
                logger.warning(f"验证码已过期: {email}")
                return False, "验证码已过期，请重新获取"
            
            # 标记验证码为已使用
            verification.is_used = True
            verification.used_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"验证码验证成功: {email}")
            return True, "验证成功"
            
        except Exception as e:
            logger.error(f"验证码验证出错: {str(e)}")
            return False, "验证失败，请稍后重试" 