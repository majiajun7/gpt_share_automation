# 使用官方 Python 运行时作为父镜像
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 防止 Python 将 .pyc 文件写入磁盘
ENV PYTHONDONTWRITEBYTECODE 1
# 确保 Python 输出直接发送到终端，而不是缓冲
ENV PYTHONUNBUFFERED 1

# 安装系统依赖：chromium和chromium-driver
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# 安装 pipenv（如果项目使用 Pipfile）或直接安装 requirements.txt
# 如果使用 requirements.txt:
COPY requirements.txt requirements.txt
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目代码到工作目录
COPY . .

# 确保驱动目录存在并将 chromedriver 移动到项目目录
RUN mkdir -p /app/adspower_manager/drivers/ && \
    cp /usr/bin/chromedriver /app/adspower_manager/drivers/ && \
    chmod +x /app/adspower_manager/drivers/chromedriver

# 暴露应用程序运行的端口
# Flask 默认运行在 5000 端口，根据您的 config.py 或 app.py 确认
EXPOSE 5000

# 定义环境变量（如果需要）
# ENV FLASK_APP=app.py
# ENV FLASK_RUN_HOST=0.0.0.0

# 运行应用的命令
# 先执行数据库迁移，然后启动应用 (仅用于开发或首次启动)
# CMD ["sh", "-c", "flask db upgrade && flask run --host=0.0.0.0 --port=5000"]
# 生产环境启动命令 (使用 Gunicorn)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--timeout", "120", "app:app"] 