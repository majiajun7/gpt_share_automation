# extensions.py
from flask_mail import Mail

# 创建 Mail 实例，供其他模块导入
mail = Mail()

# 注意：如果其他地方也需要共享 db 实例，
# 最佳实践通常也是在这里创建 db = SQLAlchemy()
# 然后在 models.py 和 app.py 中导入它。
# 但为了最小化改动，我们暂时保持 db 在 models.py 中创建。