from datetime import datetime, timedelta
import logging
# 使用相对导入从上级目录导入 models
from ..models import db, User, Subscription, Device, AdspowerAccount, SubscriptionType
# 从根目录导入 config (假设根目录已在 sys.path)
from config import TRIAL_PERIOD_DAYS

# 配置日志
logger = logging.getLogger(__name__)

class SubscriptionService:
    """订阅服务类，处理用户订阅的创建、更新和管理"""

    @classmethod
    def create_trial(cls, user_id):
        """为用户创建试用订阅

        Args:
            user_id: 用户ID

        Returns:
            (Subscription, message) 元组
        """
        try:
            # 查询用户
            user = User.query.get(user_id)
            if not user:
                return None, "用户不存在"

            # 检查是否已有活跃订阅
            active_sub = cls.get_active_subscription(user_id)
            if active_sub:
                return None, "用户已有活跃订阅，不能创建试用"

            # 检查是否已使用过试用
            has_trial = cls.has_used_trial(user_id)
            if has_trial:
                return None, "用户已使用过试用订阅"

            # 创建试用订阅
            start_date = datetime.utcnow()
            end_date = start_date + timedelta(days=TRIAL_PERIOD_DAYS)

            subscription = Subscription(
                user_id=user_id,
                plan="trial",
                start_date=start_date,
                end_date=end_date,
                payment_id=None,
                price=0.0,
                max_devices=1,  # 试用版只允许1个设备
                is_trial=True,
                created_at=datetime.utcnow()
            )

            db.session.add(subscription)
            db.session.commit()

            # 分配AdsPower账号和创建设备 (根据项目实际逻辑决定是否保留或修改)
            # success = cls.allocate_adspower_account(user_id, subscription.id)
            # if not success:
            #     logger.warning(f"为用户 {user_id} 分配AdsPower账号失败")

            logger.info(f"为用户 {user_id} 创建了试用订阅 {subscription.id}")
            return subscription, "成功创建试用订阅"

        except Exception as e:
            logger.error(f"创建试用订阅时出错: {e}")
            db.session.rollback()
            return None, f"服务器错误: {str(e)}"

    @classmethod
    def allocate_adspower_account(cls, user_id, subscription_id):
        """为用户分配ADSpower账号 (示例逻辑，可能需要根据实际情况调整)

        Args:
            user_id: 用户ID
            subscription_id: 订阅ID

        Returns:
            是否分配成功
        """
        try:
            # 查询可用的ADSpower账号
            available_account = AdspowerAccount.query.filter(
                AdspowerAccount.is_active == True,
                AdspowerAccount.current_devices < AdspowerAccount.max_devices
            ).order_by(
                AdspowerAccount.current_devices  # 优先选择设备数较少的账号
            ).first()

            if not available_account:
                logger.error("没有可用的ADSpower账号")
                return False

            # 创建默认设备 (这部分逻辑可能需要根据新流程调整或移除)
            # device = Device(
            #     user_id=user_id,
            #     adspower_account_id=available_account.id,
            #     device_name=f"Default_Device_{user_id}",
            #     device_ip="0.0.0.0",
            #     status="inactive",
            #     created_at=datetime.utcnow()
            # )
            # db.session.add(device)

            # 更新ADSpower账号设备计数 (如果需要的话)
            # available_account.current_devices += 1

            # db.session.commit()
            logger.info(f"已为用户 {user_id} 分配ADSpower账号 {available_account.id}") # , 创建了设备 {device.id}
            # 需要将账号信息关联到用户或订阅，例如 UserAdspowerAccount
            return True

        except Exception as e:
            logger.error(f"分配ADSpower账号时出错: {e}")
            db.session.rollback()
            return False

    @classmethod
    def has_used_trial(cls, user_id):
        """检查用户是否已使用过试用订阅

        Args:
            user_id: 用户ID

        Returns:
            是否使用过试用
        """
        trial = Subscription.query.filter_by(
            user_id=user_id,
            is_trial=True
        ).first()

        return trial is not None

    @classmethod
    def get_active_subscription(cls, user_id):
        """获取用户的活跃订阅

        Args:
            user_id: 用户ID

        Returns:
            活跃的Subscription对象或None
        """
        active_sub = Subscription.query.filter(
            Subscription.user_id == user_id,
            Subscription.end_date > datetime.utcnow()
        ).order_by(
            Subscription.end_date.desc()  # 获取结束时间最晚的订阅
        ).first()

        return active_sub

    @staticmethod
    def create_or_extend_subscription(user_id, plan_code, payment_id=None, price=None):
        """创建或延长订阅 (重构自 payment_service.py)

        Args:
            user_id: 用户ID
            plan_code: 订阅计划类型代码
            payment_id: 支付ID
            price: 价格

        Returns:
            (Subscription, message) 元组
        """
        try:
            # 获取订阅类型信息
            subscription_type = SubscriptionType.query.filter_by(code=plan_code).first()
            if not subscription_type:
                logger.error(f"找不到订阅类型: {plan_code}")
                return None, f"找不到订阅类型: {plan_code}"

            # 检查是否已有活跃订阅
            existing_sub = Subscription.query.filter(
                Subscription.user_id == user_id,
                Subscription.end_date > datetime.utcnow()
            ).first()

            if existing_sub:
                # 如果已有相同类型的活跃订阅，则延长订阅
                if existing_sub.plan == plan_code:
                    new_end_date = existing_sub.extend(subscription_type.days)
                    existing_sub.payment_id = payment_id
                    existing_sub.price = price if price is not None else subscription_type.price
                    db.session.commit()

                    logger.info(f"已延长用户 {user_id} 的订阅，新到期时间: {new_end_date}")
                    return existing_sub, "订阅已续期"
                else:
                    # 如果是不同类型的订阅，阻止创建新订阅
                    logger.warning(f"用户 {user_id} 尝试购买类型 {plan_code}，但已有活跃订阅 {existing_sub.plan}")
                    return None, f"您已有有效的 '{existing_sub.plan}' 订阅，无法同时购买 '{plan_code}' 订阅。请等待当前订阅结束后再购买。"

            # 创建新订阅
            now = datetime.utcnow()
            subscription = Subscription(
                user_id=user_id,
                plan=plan_code,
                start_date=now,
                end_date=now + timedelta(days=subscription_type.days),
                payment_id=payment_id,
                price=price if price is not None else subscription_type.price,
                max_devices=subscription_type.max_devices,
                created_at=now,
                updated_at=now
            )

            db.session.add(subscription)
            db.session.commit()

            logger.info(f"已为用户 {user_id} 创建{plan_code}订阅，到期时间: {subscription.end_date}")
            return subscription, "订阅创建成功"

        except Exception as e:
            logger.error(f"创建或延长订阅时出错: {e}")
            db.session.rollback()
            return None, f"创建或延长订阅失败: {str(e)}"

    # 可以添加其他订阅相关的方法，如取消订阅、获取订阅历史等