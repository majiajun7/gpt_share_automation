import os
import logging
from datetime import timedelta

# 获取 config.py 文件所在的目录的绝对路径
basedir = os.path.abspath(os.path.dirname(__file__))

# --- 核心 Flask 应用配置 ---

# 用于会话管理、CSRF保护等的密钥
# 重要提示：在生产环境中务必保密此密钥！生成一个强随机密钥。
# 可以从环境变量读取，或者生成一个随机值
SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)

# --- JWT 配置 --- 
# JWT 密钥，通常与 Flask 的 SECRET_KEY 相同
JWT_SECRET_KEY = SECRET_KEY 
# JWT 访问令牌有效期
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES_HOURS', 24))) # 默认24小时
# JWT 刷新令牌有效期 (如果使用)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES_DAYS', 30))) # 默认30天

# --- 数据库配置 ---

# SQLite数据库文件的路径
# 通常建议将其放在项目根目录下的 'instance' 文件夹中
INSTANCE_FOLDER_PATH = os.path.join(basedir, 'instance')
DB_NAME = 'app.db' # 数据库文件名
DB_PATH = os.path.join(INSTANCE_FOLDER_PATH, DB_NAME)
# SQLAlchemy 数据库 URI
SQLALCHEMY_DATABASE_URI = f'sqlite:///{DB_PATH}'
# 关闭不必要的事件通知，提升性能
SQLALCHEMY_TRACK_MODIFICATIONS = False

# --- 应用特定配置 ---

# Flask 开发服务器运行的端口
PORT = int(os.environ.get('PORT', 5000))

# 试用期天数 (恢复定义以解决 models.py 中的 ImportError)
TRIAL_PERIOD_DAYS = int(os.environ.get('TRIAL_PERIOD_DAYS', 7))

# 每个普通用户可注册的最大设备数 (恢复定义，虽然可能被 SUBSCRIPTION_PLANS 覆盖)
MAX_DEVICES_PER_USER = int(os.environ.get('MAX_DEVICES_PER_USER', 2))

# --- AdsPower 相关配置 (从 adspower_manager/config.py 迁移并整合) ---
ADSPOWER_API_BASE = os.environ.get('ADSPOWER_API_BASE', 'https://api-global.adspower.net/v1')  # API基础地址
ADSPOWER_API_KEY = os.environ.get('ADSPOWER_API_KEY', 'your_adspower_api_key_placeholder')  # 默认API密钥 (占位符)
MAX_DEVICES_PER_ADSPOWER_ACCOUNT = int(os.environ.get('MAX_DEVICES_PER_ADSPOWER_ACCOUNT', 10)) # 每个ADSpower账号最多设备数
CHECK_EXPIRATION_INTERVAL = int(os.environ.get('CHECK_EXPIRATION_INTERVAL', 3600))  # 检查订阅过期的间隔（秒）
ADSPOWER_REFRESH_INTERVAL = int(os.environ.get('ADSPOWER_REFRESH_INTERVAL', 60)) # 设备信息刷新间隔（秒，原为分钟，改为秒）
ADSPOWER_COOKIE_MAX_AGE = int(os.environ.get('ADSPOWER_COOKIE_MAX_AGE', 86400 * 7)) # ADSpower登录Cookie存活时间（秒）
# 备用的全局 AdsPower Cookies (可选)
ADSPOWER_COOKIES = None

# --- 邮件配置 (保持原样，确保 MAIL_ 前缀) ---
MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.163.com')  # 你的 SMTP 服务器
MAIL_PORT = int(os.environ.get('MAIL_PORT', 465))                 # 端口 (587 for TLS, 465 for SSL)
MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'False').lower() == 'true'  # 是否使用 TLS
MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'True').lower() == 'true' # 是否使用 SSL (163 邮箱推荐)
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'chatgptsubscribe@163.com') # 你的邮箱账号
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'KYr8q4uu5aCvHLTC')     # !!! 你的163邮箱授权码 !!!
MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', '"AI服务拼车共享平台" <chatgptsubscribe@163.com>') # 默认发件人
EMAIL_CODE_EXPIRY_MINUTES = int(os.environ.get('EMAIL_CODE_EXPIRY_MINUTES', 10)) # 验证码有效期（分钟）
MAIL_DEBUG = os.environ.get('MAIL_DEBUG', 'False').lower() == 'true' # 设置为 False 禁用 smtplib 的调试输出

# 是否强制要求邮箱验证 (使用根目录的默认 True)
REQUIRE_EMAIL_VERIFICATION = os.environ.get('REQUIRE_EMAIL_VERIFICATION', 'True').lower() == 'true'

# --- 密码策略 (保持根目录的配置) ---
PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 8))
PASSWORD_REQUIRE_NUMBER = os.environ.get('PASSWORD_REQUIRE_NUMBER', 'True').lower() == 'true'
PASSWORD_REQUIRE_SPECIAL_CHAR = os.environ.get('PASSWORD_REQUIRE_SPECIAL_CHAR', 'False').lower() == 'true'
# 添加登录失败锁定配置 (从 adspower_manager/config.py 迁移)
FAILED_LOGIN_MAX_ATTEMPTS = int(os.environ.get('FAILED_LOGIN_MAX_ATTEMPTS', 5))
FAILED_LOGIN_LOCKOUT_TIME = int(os.environ.get('FAILED_LOGIN_LOCKOUT_TIME', 300)) # 锁定时间（秒）

# --- TOTP 配置 (保持根目录的配置) ---
TOTP_VERIFICATION_TIMEOUT = int(os.environ.get('TOTP_VERIFICATION_TIMEOUT', 60)) # 验证窗口时间（秒），应为30的倍数

# --- Alipay 配置 (保持根目录的占位符和 env 读取方式) ---
ALIPAY_APP_ID = os.environ.get('ALIPAY_APP_ID', 'your_alipay_app_id_placeholder')
ALIPAY_PRIVATE_KEY = os.environ.get('ALIPAY_PRIVATE_KEY', 'your_alipay_private_key_placeholder')
ALIPAY_PUBLIC_KEY = os.environ.get('ALIPAY_PUBLIC_KEY', 'your_alipay_public_key_placeholder')
ALIPAY_NOTIFY_URL = os.environ.get('ALIPAY_NOTIFY_URL', None)
ALIPAY_RETURN_URL = os.environ.get('ALIPAY_RETURN_URL', 'http://localhost:5000/payment/result')

# --- 易支付 (Epay / 彩虹易支付) 配置 ---
EPAY_PID = os.environ.get('EPAY_PID', '1683') # 你的商户ID
EPAY_KEY = os.environ.get('EPAY_KEY', 'ygn4JZ0ICFEXZtyFiupDCVnlTSqBFuZ0') # 你的商户密钥
EPAY_SUBMIT_URL = os.environ.get('EPAY_SUBMIT_URL', 'https://pay.netzz.net/submit.php') # Submit接口地址
EPAY_API_URL = os.environ.get('EPAY_API_URL', 'https://pay.netzz.net/mapi.php') # MAPI接口地址 (备用)
# !!重要!!: 下面的URL需要根据你的实际部署域名或IP进行修改
# Use localhost:5000 as default for local development
EPAY_NOTIFY_URL = os.environ.get('EPAY_NOTIFY_URL', 'http://138.2.51.180:5000/api/payments/epay/notify') # 异步通知URL
EPAY_RETURN_URL = os.environ.get('EPAY_RETURN_URL', 'http://138.2.51.180:5000/payments/epay/result') # 同步跳转URL

# --- API限流配置 (可选，从 adspower_manager/config.py 迁移) ---
API_RATE_LIMIT = {
    'default': os.environ.get('API_RATE_LIMIT_DEFAULT', '60/minute'),
    'login': os.environ.get('API_RATE_LIMIT_LOGIN', '10/minute'),
    'register': os.environ.get('API_RATE_LIMIT_REGISTER', '5/minute'),
    'payment': os.environ.get('API_RATE_LIMIT_PAYMENT', '10/minute')
}

# --- 其他可能的配置 (保持占位符) ---

# 日志级别
# LOG_LEVEL = logging.INFO