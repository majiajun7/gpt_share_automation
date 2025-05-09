# ChatGPT拼车服务 - AI服务拼车共享平台

## 简介

本项目是一个多用户共享AI服务订阅的平台，主要用于管理和分发AdsPower浏览器账号。通过此平台，用户可以购买订阅，共享使用AdsPower服务，从而节省成本。平台提供了用户认证、订阅管理、设备管理和支付处理功能，同时支持基于Selenium的浏览器自动化来维护AdsPower账号的登录状态。

## 主要特性

*   **用户认证**: 邮箱验证码登录/注册，安全的密码策略，防止暴力破解
*   **订阅管理**: 支持多种类型的订阅计划（如月付、季付、学生等），灵活的订阅期限设置
*   **设备管理**: 支持多设备登录，限制每个用户的设备数量，自动记录设备信息
*   **AdsPower集成**: 自动管理AdsPower账号和浏览器实例，维护登录状态
*   **浏览器自动化**: 使用Selenium WebDriver池自动登录和维护AdsPower账号
*   **支付系统**: 集成易支付(Epay)和支付宝支付接口，自动处理订单和订阅延期
*   **管理后台**: 管理员可以监控用户、订阅、设备和支付状态

## 技术栈

*   **后端**: Python 3.11, Flask 2.x
*   **数据库**: SQLite (通过SQLAlchemy ORM)
*   **容器化**: Docker (基于python:3.11-slim镜像)
*   **依赖管理**: `requirements.txt`
*   **数据库迁移**: Flask-Migrate 3.x
*   **前端**: Bootstrap 5.1.3, jQuery 3.6.0, Bootstrap Icons 1.10.5
*   **邮件服务**: Flask-Mail (默认使用163邮箱SMTP)
*   **任务调度**: APScheduler
*   **浏览器自动化**: Selenium WebDriver, Chromium
*   **Web服务器**: Gunicorn (生产环境)
*   **安全**: JWT认证, TOTP(两因素认证), Bcrypt密码哈希

## 环境准备

在开始之前，请确保您的系统已安装以下软件：

*   Python (版本 >= 3.8，推荐3.11)
*   pip (Python 包管理器)
*   Docker (如需容器化部署)
*   Chromium 浏览器(如需在本地运行浏览器自动化)
*   Git

## 安装步骤

1.  **克隆仓库**:
    ```bash
    git clone [您的仓库地址]
    cd gpt_share_automation
    ```

2.  **创建并激活虚拟环境** (推荐):
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # macOS/Linux
    # .venv\Scripts\activate  # Windows
    ```

3.  **安装依赖**:
    ```bash
    pip install -r requirements.txt
    ```

## 配置说明

项目的核心配置位于 `config.py` 文件中。您可能需要根据您的环境调整以下配置：

*   **数据库连接**: 默认使用SQLite，存储在 `instance/app.db`
*   **密钥**: `SECRET_KEY` 和 `JWT_SECRET_KEY` 需设置为安全的随机值
*   **邮件配置**: 设置 `MAIL_SERVER`, `MAIL_USERNAME`, `MAIL_PASSWORD` 等邮件服务参数
    (默认配置使用163邮箱: chatgptsubscribe@163.com)
*   **支付配置**: 
    - 易支付: `EPAY_PID`, `EPAY_KEY`, `EPAY_SUBMIT_URL`
    - 支付宝: `ALIPAY_APP_ID`, `ALIPAY_PRIVATE_KEY`, `ALIPAY_PUBLIC_KEY`
*   **AdsPower配置**: `ADSPOWER_API_BASE` 和 `ADSPOWER_API_KEY`
*   **安全配置**: 
    - 密码策略: `PASSWORD_MIN_LENGTH` (默认8), `PASSWORD_REQUIRE_NUMBER` (默认True)
    - 登录失败锁定: `FAILED_LOGIN_MAX_ATTEMPTS` (默认5), `FAILED_LOGIN_LOCKOUT_TIME` (默认300秒)

您可以创建一个 `instance/config.py` 文件来覆盖默认配置，该文件通常会被 `.gitignore` 忽略，适合存放敏感信息：

```python
SECRET_KEY = 'your_secure_secret_key'
SQLALCHEMY_DATABASE_URI = 'sqlite:///instance/custom_app.db'
MAIL_USERNAME = 'your_email@example.com'
MAIL_PASSWORD = 'your_email_password'
ADSPOWER_API_KEY = 'your_adspower_api_key'
```

## 运行项目

### 1. 初始化数据库

首次运行前，需要初始化数据库：

```bash
flask db upgrade
flask init-db  # 创建默认账号和订阅类型
```

初始化后会创建以下默认账号：
* 管理员账号: admin@example.com / admin123
* 普通用户账号: user@example.com / user123
* 测试订阅类型: 测试套餐 (1元/1天)

### 2. 使用 Flask 开发服务器

```bash
flask run
# 或者
python app.py
```

默认情况下，应用会运行在 `http://127.0.0.1:5000/`。端口可在config.py中通过PORT环境变量配置。

### 3. 使用 Docker

```bash
# 构建Docker镜像
docker build -t gpt_share_automation .

# 运行Docker容器
docker run -p 5000:5000 gpt_share_automation
# 如需挂载配置卷
# docker run -p 5000:5000 -v $(pwd)/instance:/app/instance gpt_share_automation
```

Docker镜像已预先配置了Chromium和ChromeDriver，用于浏览器自动化功能。

## 项目结构

```
gpt_share_automation/
├── .git/                        # Git 版本控制目录
├── .venv/                       # Python 虚拟环境
├── adspower_manager/            # AdsPower管理模块
│   ├── api_routes.py            # API路由处理
│   ├── models.py                # 数据库模型定义
│   ├── page_routes.py           # 页面路由处理
│   ├── services/                # 服务层
│   │   ├── email_service.py     # 邮件发送服务
│   │   └── payment_service.py   # 支付处理服务
│   ├── webdriver_pool.py        # WebDriver池管理
│   └── adspower_api.py          # AdsPower API客户端
├── error_screenshots/           # 错误截图存储目录
├── instance/                    # Flask实例目录(数据库、配置)
├── migrations/                  # 数据库迁移脚本
├── templates/                   # HTML模板
│   ├── admin.html               # 管理员后台页面
│   ├── dashboard.html           # 用户控制面板
│   ├── index.html               # 首页/登录/注册页
│   ├── adspower_login.html      # AdsPower登录页面
│   ├── epay_result.html         # 易支付结果页面
│   └── totp_test.html           # TOTP测试页面
├── app.py                       # 应用入口点
├── config.py                    # 配置文件
├── Dockerfile                   # Docker构建文件
├── extensions.py                # Flask扩展初始化(Mail)
├── requirements.txt             # Python依赖列表
└── README.md                    # 项目说明文件
```

## API端点

主要API端点包括：

*   **认证相关**:
    - `POST /api/login`: 用户登录
    - `POST /api/register`: 用户注册
    - `POST /api/send_verification_code`: 发送验证码

*   **订阅相关**:
    - `GET /api/subscription`: 获取当前用户订阅信息
    - `GET /api/subscription_types`: 获取可用订阅计划
    - `POST /api/subscription/extend`: 延长订阅

*   **设备管理**:
    - `GET /api/devices`: 获取设备列表
    - `POST /api/devices`: 注册新设备
    - `DELETE /api/devices/<id>`: 删除设备

*   **支付相关**:
    - `POST /api/payments/create`: 创建支付订单
    - `GET /api/payments/status/<order_id>`: 查询支付状态
    - `POST /api/payments/epay/notify`: 易支付异步通知回调

*   **AdsPower相关**:
    - `GET /api/adspower/accounts`: 获取AdsPower账号列表(管理员)
    - `POST /api/adspower/accounts`: 添加AdsPower账号(管理员)
    - `GET /api/adspower/status`: 获取AdsPower连接状态

## 数据库模型

主要数据库模型包括：

*   **User**: 用户信息
*   **Subscription**: 用户订阅
*   **SubscriptionType**: 订阅类型与价格
*   **Device**: 用户设备
*   **AdspowerAccount**: AdsPower账号
*   **Payment**: 支付记录
*   **LoginSession**: 登录会话
*   **EmailVerification**: 邮箱验证码
*   **ChatGPTAccount**: ChatGPT账号(与Subscription关联)

## 数据库迁移

数据库结构变更通过Flask-Migrate管理：

```bash
# 初始化迁移环境(仅首次)
flask db init

# 生成迁移脚本
flask db migrate -m "变更描述"

# 应用迁移
flask db upgrade
```

## 浏览器自动化

项目使用Selenium WebDriver池自动管理AdsPower账号：

*   **WebDriverPool**: 维护基础WebDriver实例池
*   **AccountWebDriverManager**: 为每个AdsPower账号维护一组预热的WebDriver实例
*   自动登录、处理验证码、导航到设备管理页面
*   处理会话过期、Cookie刷新等情况

## 部署

推荐的生产环境部署方式：

*   **应用服务器**: Gunicorn (已在Dockerfile中配置)
*   **反向代理**: Nginx
*   **进程管理**: Systemd 或 Supervisor

确保在生产环境中：
*   禁用调试模式 (`FLASK_DEBUG=False`)
*   设置安全的随机 `SECRET_KEY`
*   配置适当的日志级别和输出路径
*   部署时使用HTTPS
*   设置正确的支付回调URL (`EPAY_NOTIFY_URL`, `EPAY_RETURN_URL`)

## 常见问题

*   **验证码未收到**: 检查邮件服务器配置，或查看垃圾邮件文件夹
*   **浏览器自动化失败**: 确保Chromium和ChromeDriver正确安装，检查error_screenshots目录中的错误截图
*   **支付回调问题**: 确保您的服务器能被支付平台访问，正确配置了回调URL
*   **登录失败**: 系统有登录失败锁定机制，默认5次失败后锁定账号5分钟 