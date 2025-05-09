import os
import sys
import threading

import click
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import jwt
from datetime import datetime, timedelta
import functools
import logging
import traceback
import uuid
import shutil
import json
import random
import string
import atexit
from flask_migrate import Migrate

# 创建Flask应用
app = Flask(__name__)

# --- 从 config.py 加载配置 --- 
app.config.from_pyfile('config.py')

# 确保实例路径存在
instance_path = os.path.join(app.root_path, app.instance_path)
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

# 初始化应用的主要功能
def init_app():
    # 检测是否为CLI命令模式（例如flask --help）
    # 对于CLI命令，只设置最基本的日志，避免输出额外信息
    is_cli_command = len(sys.argv) > 1 and sys.argv[0].endswith('flask') and sys.argv[1] != 'run'
    
    # 配置日志
    if is_cli_command and '--help' in sys.argv:
        logging.basicConfig(level=logging.ERROR)  # 对于--help命令，只输出错误日志
    else:
        logging.basicConfig(level=logging.INFO, 
                           format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        # 2. 获取特定模块的 logger
        # webdriver_pool_logger = logging.getLogger('adspower_manager.webdriver_pool')
        # 3. 单独为这个 logger 设置 DEBUG 级别
        # webdriver_pool_logger.setLevel(logging.DEBUG)
    
    logger = logging.getLogger(__name__)
    
    
    # 导入依赖模块
    from extensions import mail
    from adspower_manager.models import db, User, Subscription, Device, AdspowerAccount, SubscriptionType, EmailVerification, LoginSession
    from adspower_manager.scheduler import init_scheduler
    from adspower_manager.api_routes import api as api_blueprint
    from adspower_manager.page_routes import main_bp as main_blueprint
    from adspower_manager.webdriver_pool import init_driver_pool, shutdown_driver_pool, start_account_manager, stop_account_manager, get_account_driver_manager, get_driver_pool
    
    # 初始化JWT
    jwt_manager = JWTManager(app)
    
    # 初始化数据库
    db.init_app(app)
    # 初始化 Flask-Migrate
    migrate = Migrate(app, db, directory='migrations')
    # 初始化 Flask-Mail
    mail.init_app(app)
    
    # 注册蓝图
    app.register_blueprint(api_blueprint)
    app.register_blueprint(main_blueprint, url_prefix='/ads_manager')
    
    # 如果是CLI命令模式，到此为止即可，不初始化资源
    if is_cli_command:
        logger.info("Running in CLI command mode, skipping resource initialization.")
        return logger
    
    # --- 在 Gunicorn fork worker 之前初始化资源 ---
    logger.info("Initializing application resources...")
    try:
        # 初始化 WebDriver 池和 Account Manager
        logger.info("Initializing WebDriverPool...")
        init_driver_pool(pool_size=10, driver_timeout=1800, check_interval=300)
        logger.info("WebDriverPool initialized.")
        
        logger.info("Initializing AccountWebDriverManager...")
        manager = get_account_driver_manager()
        logger.info("AccountWebDriverManager obtained.")
        
        logger.info("Starting AccountWebDriverManager background thread...")
        start_account_manager()
        logger.info("AccountWebDriverManager started.")
        
        # 注册需要管理的账号 (需要 app context)
        with app.app_context():
            register_accounts_from_db()
        
        logger.info("Initializing scheduler...")
        global scheduler_thread
        scheduler_thread = init_scheduler(app)
        if scheduler_thread and scheduler_thread.is_alive():
            logger.info("Scheduler started successfully.")
        else:
            logger.warning("Scheduler failed to start.")
            
        logger.info("Application resources initialized successfully.")
            
    except Exception as e:
        logger.error(f"Error during application resource initialization: {e}", exc_info=True)
        # 根据需要决定是否让应用启动失败
        # raise e # 如果初始化失败则阻止应用启动
        
    # 注册退出清理函数
    def cleanup_resources():
        if not hasattr(app, '_resources_initialized') or not app._resources_initialized:
            return
            
        logger.info("Flask application shutting down. Cleaning up resources...")
        
        # 停止 AccountWebDriverManager
        try:
            manager = get_account_driver_manager()
            if manager:
                stop_thread = threading.Thread(target=lambda: stop_account_manager())
                stop_thread.daemon = True
                stop_thread.start()
                stop_thread.join(timeout=5.0)
                
                if stop_thread.is_alive():
                    logger.warning("AccountWebDriverManager停止操作超时，继续清理其他资源")
                
                logger.info("AccountWebDriverManager stopped and global reference cleared.")
        except Exception as e:
            logger.error(f"Error stopping AccountWebDriverManager: {e}", exc_info=True)
    
        # 关闭底层 WebDriver Pool
        try:
            stop_thread = threading.Thread(target=lambda: shutdown_driver_pool())
            stop_thread.daemon = True
            stop_thread.start()
            stop_thread.join(timeout=5.0)
            
            if stop_thread.is_alive():
                logger.warning("WebDriverPool停止操作超时，但全局引用已在shutdown_driver_pool中清除")
            
            logger.info("WebDriverPool shutdown completed.")
        except Exception as e:
            logger.error(f"Error shutting down WebDriverPool: {e}", exc_info=True)
    
        logger.info("Resource cleanup attempt complete.")
    
    # 注册清理函数
    atexit.register(cleanup_resources)
    
    return logger

# 前端页面路由
@app.route('/')
def index():
    """首页，显示登录界面"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """控制面板页面，前端自己会检查登录状态并重定向"""
    return render_template('dashboard.html')

@app.route('/admin')
def admin_dashboard():
    """管理后台页面，前端自己会检查管理员权限"""
    return render_template('admin.html')

@app.route('/admin/adspower')
def admin_adspower():
    """重定向到主管理页面的AdsPower部分"""
    return redirect('/admin#adspower')

@app.route('/test/totp')
def totp_test_page():
    """TOTP验证码测试页面"""
    return render_template('totp_test.html')

# 支付结果页 (Epay 同步跳转)
@app.route('/payments/epay/result')
def epay_payment_result():
    """易支付同步跳转结果页
    
    只渲染模板，实际状态由前端 JS 轮询 API 获取。
    需要确保 URL 中包含 out_trade_no 参数。
    """
    order_id = request.args.get('out_trade_no')
    # 可以选择性地传递 order_id 给模板，虽然 JS 也会从 URL 获取
    return render_template('epay_result.html', order_id=order_id)

# 注册需要管理的账号函数
def register_accounts_from_db():
    from adspower_manager.models import AdspowerAccount
    from adspower_manager.webdriver_pool import get_account_driver_manager
    
    logger = logging.getLogger(__name__)
    logger.info("Registering active accounts from database...")
    try:
        accounts = AdspowerAccount.query.filter_by(is_active=True).all()
        if not accounts:
            logger.info("No active accounts found in DB to register.")
            return
        manager = get_account_driver_manager()
        registered_count = 0
        for acc in accounts:
            try:
                cookies = acc.cookies
                manager.add_managed_account(
                    account_id=acc.id,
                    username=acc.username,
                    password=acc.password,
                    totp_secret=acc.totp_secret,
                    cookies=cookies
                )
                registered_count += 1
                logger.info(f"Registered account: {acc.username} (ID: {acc.id})")
            except Exception as reg_err:
                logger.error(f"Failed to register account {acc.username} (ID: {acc.id}): {reg_err}")
        logger.info(f"Finished registering accounts. Registered: {registered_count}/{len(accounts)}")
    except Exception as db_err:
         logger.error(f"Error fetching accounts from database for registration: {db_err}")

def init_default_data():
    """初始化默认数据"""
    from adspower_manager.models import db, User, SubscriptionType
    
    logger = logging.getLogger(__name__)
    try:
        # 创建默认管理员用户
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                email='admin@example.com',
                is_admin=True,
                is_active=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            logger.info("创建了默认管理员账号: admin@example.com / admin123")
        
        # 创建默认普通用户
        user = User.query.filter_by(email='user@example.com').first()
        if not user:
            user = User(
                email='user@example.com',
                is_admin=False,
                is_active=True
            )
            user.set_password('user123')
            db.session.add(user)
            logger.info("创建了默认普通用户账号: user@example.com / user123")
        
        # 创建默认订阅类型
        test_subscription = SubscriptionType.query.filter_by(code='test').first()
        if not test_subscription:
            test_subscription = SubscriptionType(
                code='test',
                name='测试套餐',
                max_devices=1,
                price=1,
                discount=100,
                days=1,
                requirements=None,
                is_public=True
            )
            db.session.add(test_subscription)
            logger.info("创建了默认订阅类型: 测试套餐 (test)")
        
        # 提交更改
        db.session.commit()
        logger.info("初始数据创建完成")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"初始化默认数据时出错: {str(e)}")

# 添加 Flask CLI 命令
@app.cli.command('init-db')
def initialize_database():
    """创建初始数据库表和默认数据。"""
    from config import DB_PATH, SECRET_KEY, PORT
    from adspower_manager.models import db
    
    # 配置基本日志以用于CLI命令
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    click.echo('Initializing the database...')
    # db.create_all() # 通常由 migrations 处理
    with app.app_context():
        init_default_data() # 调用创建默认数据的函数
    click.echo('Database initialized with default data.')

# 在脚本末尾调用 init_app，但在 if __name__ == '__main__' 之外
# 这样当 Gunicorn 导入 app 时，初始化就会执行
logger = init_app()

if __name__ == '__main__':
    # 当直接运行 app.py 时 (通常用于调试)
    # init_app() 已经在上面被调用了
    from config import PORT
    logger.info(f"Starting Flask app directly via __main__ on port {PORT}")
    # 注意：直接运行可能不会完全模拟 Gunicorn 环境，特别是多进程/线程行为
    app.run(debug=False, host='0.0.0.0', port=PORT)