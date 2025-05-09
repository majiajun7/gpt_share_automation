import logging
import time
import uuid
from datetime import datetime, timedelta
from flask import url_for
# from alipay import AliPay
from ..models import db, Payment, Subscription, User, ChatGPTAccount, SubscriptionType
from config import (
    ALIPAY_APP_ID, ALIPAY_PRIVATE_KEY, ALIPAY_PUBLIC_KEY, 
    ALIPAY_NOTIFY_URL, ALIPAY_RETURN_URL,
    EPAY_PID
)
import random
import string
import json
from .subscription_service import SubscriptionService
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

logger = logging.getLogger(__name__)

class PaymentService:
    """支付服务基类"""
    
    def __init__(self):
        pass # Keep __init__ if empty, or add other initializations if needed
    
    def create_subscription(self, user_id, plan_id, payment_id, amount):
        """创建订阅"""
        from ..models import SubscriptionType # Import here to avoid circular dependency issues
        sub_type = SubscriptionType.query.filter_by(code=plan_id).first()
        
        if not sub_type:
            logger.error(f"创建订阅失败：找不到订阅类型代码: {plan_id}")
            return None
        
        # 查找可用的ChatGPT账号
        chatgpt_account = ChatGPTAccount.query.filter_by(
            is_active=True
        ).order_by(
            ChatGPTAccount.current_users
        ).first()
        
        if not chatgpt_account:
            logger.error("没有可用的ChatGPT账号")
            return None
        
        # 创建订阅记录
        now = datetime.utcnow()
        subscription = Subscription(
            user_id=user_id,
            plan=plan_id,
            start_date=now,
            end_date=now + timedelta(days=sub_type.days),
            payment_id=payment_id,
            price=amount,
            max_devices=sub_type.max_devices,
            chatgpt_account_id=chatgpt_account.id,
            created_at=now
        )
        
        # 更新ChatGPT账号用户计数
        chatgpt_account.current_users += 1
        
        db.session.add(subscription)
        db.session.commit()
        
        logger.info(f"为用户 {user_id} 创建了 {plan_id} 订阅，到期日: {subscription.end_date}")
        return subscription
    
    def extend_subscription(self, subscription, plan_id, payment_id, amount):
        """延长订阅"""
        from ..models import SubscriptionType
        sub_type = SubscriptionType.query.filter_by(code=plan_id).first()
        if not sub_type:
            logger.error(f"延长订阅失败：找不到订阅类型代码: {plan_id}")
            return None
        
        # Use sub_type details for extension logic
        if subscription.end_date > datetime.utcnow():
            subscription.end_date = subscription.end_date + timedelta(days=sub_type.days)
        else:
            subscription.start_date = datetime.utcnow()
            subscription.end_date = subscription.start_date + timedelta(days=sub_type.days)
        
        subscription.payment_id = payment_id
        subscription.price = amount
        subscription.plan = plan_id
        subscription.max_devices = max(subscription.max_devices, sub_type.max_devices)
        subscription.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"为用户 {subscription.user_id} 延长了订阅，新到期日: {subscription.end_date}")
        return subscription

    def create_payment(self, user_id, amount, payment_method, days, plan_id):
        """创建支付记录
        
        Args:
            user_id: 用户ID
            amount: 金额
            payment_method: 支付方式（alipay, wechat等）
            days: 订阅天数
            plan_id: 订阅计划代码 (例如 'test', 'monthly')
            
        Returns:
            Payment对象，或None表示失败
        """
        try:
            # 生成唯一支付号
            payment_id = self._generate_payment_id()
            
            # 创建支付记录
            payment = Payment(
                payment_id=payment_id,
                order_id=payment_id,  # 设置order_id等于payment_id
                user_id=user_id,
                amount=amount,
                payment_method=payment_method,
                status='pending',
                created_at=datetime.utcnow(),
                subscription_days=days,
                plan_id=plan_id  # <--- 保存 plan_id
            )
            
            db.session.add(payment)
            db.session.commit()
            
            # 在日志中也记录 plan_id
            logger.info(f"为用户 {user_id} 创建了支付记录 {payment_id} (套餐: {plan_id}), 金额: {amount}, 天数: {days}")
            return payment
            
        except Exception as e:
            logger.error(f"创建支付记录时出错: {e}")
            db.session.rollback()
            return None
    
    def _generate_payment_id(self):
        """生成唯一支付ID (类时间戳格式)
        
        Returns:
            支付ID字符串 (格式: YYYYMMDDHHMMSS + 4位随机数)
        """
        # 新格式: YYYYMMDDHHMMSS + 4位随机数
        timestamp_part = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_part = ''.join(random.choices(string.digits, k=4)) # 4位纯数字
        payment_id = f"{timestamp_part}{random_part}"
        logger.debug(f"生成新的支付/订单ID: {payment_id}")
        return payment_id
    
    def process_payment_success(self, payment_id):
        """核心处理支付成功逻辑 (供内部调用)
        
        Args:
            payment_id: 支付ID (通常等于 out_trade_no)
            
        Returns:
            (bool, str): 是否处理成功, 消息
        """
        try:
            # 查找支付记录 (使用 payment_id，它等于 order_id)
            payment = Payment.query.filter_by(payment_id=payment_id).first()
            if not payment:
                logger.error(f"核心支付处理失败：找不到支付记录 {payment_id}")
                return False, f"找不到支付记录 {payment_id}"

            # !! 检查状态，防止重复处理 !!
            if payment.status != 'pending':
                 logger.warning(f"核心支付处理：订单 {payment_id} 状态为 {payment.status}，无需重复处理。")
                 # 认为是成功的，因为订单已经处理过
                 return True, f"订单状态为 {payment.status}，无需重复处理"
            
            # 更新支付状态
            payment.status = 'paid' # 使用 'paid' 表示已付款，区别于可能的 'completed'
            payment.paid_at = datetime.utcnow()
            
            # --- 创建或延长订阅 ---
            # 获取 plan_code (之前创建支付记录时应该保存了)
            plan_code = getattr(payment, 'plan_id', None) # 假设 plan_id 存储了套餐代码
            if not plan_code:
                logger.error(f"核心支付处理失败：订单 {payment_id} 缺少 plan_id 信息")
                payment.status = 'error'
                payment.remarks = "缺少 plan_id"
                db.session.commit()
                return False, f"订单 {payment_id} 缺少 plan_id"

            # 调用 SubscriptionService 处理订阅
            subscription, message = SubscriptionService.create_or_extend_subscription(
                user_id=payment.user_id,
                plan_code=plan_code,
                payment_id=payment.payment_id, # 使用 payment_id
                price=payment.amount # 使用记录的金额
            )
            
            if not subscription:
                logger.error(f"核心支付处理失败：处理支付 {payment_id} 时创建/延长订阅失败: {message}")
                payment.status = 'error' # 标记为错误状态
                payment.remarks = f"订阅处理失败: {message}"
                db.session.commit()
                return False, f"创建/延长订阅失败: {message}"
            
            # 更新支付记录关联的订阅ID
            payment.subscription_id = subscription.id
            # payment.status 保持 'paid'
            db.session.commit()
            logger.info(f"核心支付处理成功：支付 {payment_id} 已完成，已为用户 {payment.user_id} 创建/延长订阅 (ID: {subscription.id})")
            return True, "支付成功并已处理订阅"

        except Exception as e:
            logger.exception(f"核心支付处理失败：处理支付 {payment_id} 时发生异常")
            db.session.rollback()
            # 尝试再次查找 payment 并标记为错误 (如果回滚前能找到)
            try:
                 payment = Payment.query.filter_by(payment_id=payment_id).first()
                 if payment and payment.status == 'pending': # 只有 pending 才标记 error
                     payment.status = 'error'
                     payment.remarks = f"内部处理异常: {str(e)[:100]}" # 记录部分错误信息
                     db.session.commit()
            except Exception as finalize_err:
                 logger.error(f"核心支付处理失败：标记订单 {payment_id} 为错误时再次失败: {finalize_err}")

            return False, f"内部处理异常: {e}"

    # --- 新增: 处理易支付特定逻辑 ---
    def process_epay_payment(self, out_trade_no: str, epay_trade_no: str, amount_str: str) -> (bool, str):
        """处理易支付成功回调的业务逻辑。

        Args:
            out_trade_no: 商户订单号 (我们的 payment_id / order_id)
            epay_trade_no: 易支付平台的订单号
            amount_str: 回调中收到的金额字符串

        Returns:
            (bool, str): 处理是否成功, 消息
        """
        logger.info(f"[易支付处理] 开始处理订单: {out_trade_no}, 易支付单号: {epay_trade_no}, 金额: {amount_str}")

        # 1. 查找支付记录
        payment = Payment.query.filter_by(order_id=out_trade_no).first()
        if not payment:
            logger.error(f"[易支付处理] 失败：找不到订单 {out_trade_no}")
            return False, f"找不到订单 {out_trade_no}"

        # 2. 验证金额
        try:
            # 将数据库金额和回调金额都转为 Decimal 进行比较
            expected_amount = Decimal(payment.amount).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            received_amount = Decimal(amount_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            
            if expected_amount != received_amount:
                 logger.error(f"[易支付处理] 失败：订单 {out_trade_no} 金额不匹配。预期: {expected_amount},收到: {received_amount}")
                 # 可选：将订单标记为异常状态
                 payment.status = 'error'
                 payment.remarks = f"金额不匹配: 预期={expected_amount}, 收到={received_amount}"
                 db.session.commit()
                 return False, "订单金额不匹配"
        except (InvalidOperation, TypeError) as e:
            logger.error(f"[易支付处理] 失败：订单 {out_trade_no} 金额格式无效。预期值: '{payment.amount}', 收到值: '{amount_str}'. 错误: {e}")
            payment.status = 'error'
            payment.remarks = f"金额格式无效: 收到='{amount_str}'"
            db.session.commit()
            return False, "金额格式无效"
        except Exception as e: # Catch unexpected errors during decimal conversion/comparison
            logger.exception(f"[易支付处理] 失败：订单 {out_trade_no} 金额比较时发生未知错误。")
            payment.status = 'error'
            payment.remarks = f"金额比较错误: {str(e)[:100]}"
            db.session.commit()
            return False, "金额比较时发生错误"

        # 3. 检查状态 (再次检查，process_payment_success 内部也会检查)
        if payment.status != 'pending':
            logger.warning(f"[易支付处理] 订单 {out_trade_no} 状态为 {payment.status}，无需处理。")
            return True, f"订单状态为 {payment.status}，无需重复处理"

        # 4. 更新易支付交易号
        payment.transaction_id = epay_trade_no # 记录易支付的 trade_no
        # 先提交 transaction_id，即使后续订阅失败也保留凭证
        try:
            db.session.commit()
            logger.info(f"[易支付处理] 已更新订单 {out_trade_no} 的 transaction_id 为 {epay_trade_no}")
        except Exception as e:
            logger.exception(f"[易支付处理] 更新订单 {out_trade_no} transaction_id 时失败，回滚")
            db.session.rollback()
            # 如果更新失败，后续处理也无法进行
            return False, "更新支付凭证失败"

        # 5. 调用核心支付成功处理逻辑 (处理状态更新和订阅)
        # 使用 payment.payment_id (等于 order_id)
        success, message = self.process_payment_success(payment.payment_id) 
        
        # process_payment_success 内部会提交或回滚，这里只需返回结果
        return success, message

class AlipayService(PaymentService):
    """支付宝支付服务"""
    
    def __init__(self):
        super().__init__()
        self.alipay = None
        self.mock_mode = True
        
        # 检查支付宝配置是否有效
        if self._check_alipay_config():
            try:
                # 初始化支付宝客户端
                self.alipay = AliPay(
                    appid=ALIPAY_APP_ID,
                    app_notify_url=ALIPAY_NOTIFY_URL,
                    app_private_key_string=ALIPAY_PRIVATE_KEY,
                    alipay_public_key_string=ALIPAY_PUBLIC_KEY,
                    sign_type="RSA2"
                )
                self.mock_mode = False
                # logger.info("支付宝支付服务初始化成功")
            except Exception as e:
                logger.error(f"初始化支付宝客户端失败: {str(e)}")
                self.mock_mode = True
        else:
            # 默认为模拟支付模式，无需显示警告
            # logger.warning("支付宝配置无效，将使用模拟支付模式")
            self.mock_mode = True
    
    def _check_alipay_config(self):
        """检查支付宝配置是否有效"""
        # 检查APP ID
        if not ALIPAY_APP_ID or ALIPAY_APP_ID == 'your_alipay_app_id_placeholder':
            return False
        
        # 检查私钥
        if not ALIPAY_PRIVATE_KEY or 'your_alipay_private_key' in ALIPAY_PRIVATE_KEY:
            return False
        
        # 检查公钥
        if not ALIPAY_PUBLIC_KEY or 'alipay_public_key' in ALIPAY_PUBLIC_KEY:
            return False
        
        return True
    
    def create_payment(self, user_id, plan_id, return_url=None):
        """创建支付宝支付"""
        sub_type = SubscriptionType.query.filter_by(code=plan_id).first()
        if not sub_type:
            logger.error(f"找不到订阅计划: {plan_id}")
            return None, None
        
        # 创建订单号
        payment_id = f"GPT{int(time.time())}{uuid.uuid4().hex[:6]}"
        
        # 创建支付记录
        payment = Payment(
            user_id=user_id,
            payment_id=payment_id,
            amount=sub_type.price,
            currency='CNY',
            payment_method='alipay',
            status='pending',
            plan_id=plan_id,
            created_at=datetime.utcnow()
        )
        
        db.session.add(payment)
        db.session.commit()
        
        if self.mock_mode:
            # 模拟支付模式，返回模拟支付页面URL
            mock_url = f"/payment/mock?order_id={payment_id}&amount={sub_type.price}&plan_id={plan_id}"
            logger.info(f"使用模拟支付模式，订单号: {payment_id}, 金额: {sub_type.price}")
            return payment, mock_url
        
        # 生成支付页面链接
        pay_url = self.alipay.api_alipay_trade_page_pay(
            out_trade_no=payment_id,
            total_amount=str(sub_type.price),  # 支付宝要求字符串
            subject=f"{sub_type.name} - ChatGPT账号共享服务",
            return_url=return_url or ALIPAY_RETURN_URL,
            notify_url=ALIPAY_NOTIFY_URL
        )
        
        # 完整的支付链接
        pay_url = f"https://openapi.alipay.com/gateway.do?{pay_url}"
        
        logger.info(f"为用户 {user_id} 创建支付宝支付，订单号: {payment_id}, 金额: {sub_type.price}")
        return payment, pay_url
    
    def verify_payment(self, data):
        """验证支付宝回调"""
        try:
            if self.mock_mode:
                # 模拟模式下总是返回成功
                logger.warning("使用模拟支付模式验证回调")
                order_id = data.get('out_trade_no')
                if not order_id:
                    return False, None
                    
                # 查找订单
                payment = Payment.query.filter_by(payment_id=order_id).first()
                if not payment:
                    return False, None
                    
                # 更新支付状态
                payment.status = 'completed'
                payment.paid_at = datetime.utcnow()
                
                # 创建订阅
                user = User.query.get(payment.user_id)
                if not user:
                    logger.error(f"找不到用户 {payment.user_id}")
                    return False, None
                    
                # 查找用户现有订阅 (Remove status filter)
                subscription = Subscription.query.filter_by(
                    user_id=user.id,
                    # status='active' # <-- REMOVE THIS LINE
                ).filter(
                    Subscription.end_date > datetime.utcnow() # <-- Check end_date instead
                ).order_by(Subscription.end_date.desc()).first()
                
                # 查找订阅计划
                plan_id = data.get('plan_id', 'monthly')
                sub_type = SubscriptionType.query.filter_by(code=plan_id).first()
                
                if subscription:
                    # 延长订阅
                    self.extend_subscription(
                        subscription, 
                        plan_id, 
                        payment.id, 
                        payment.amount
                    )
                else:
                    # 创建新订阅
                    self.create_subscription(
                        user.id,
                        plan_id,
                        payment.id,
                        payment.amount
                    )
                    
                # 更新支付记录的订阅ID (Remove status filter)
                subscription = Subscription.query.filter_by(
                    user_id=user.id,
                    # status='active' # <-- REMOVE THIS LINE
                ).filter(
                    Subscription.end_date > datetime.utcnow() # <-- Check end_date instead
                ).order_by(Subscription.end_date.desc()).first()
                    
                if subscription:
                    payment.subscription_id = subscription.id
                    db.session.commit()
                    
                return True, payment
            
            # 校验签名
            signature_verified = self.alipay.verify(data, data.pop("sign"))
            if not signature_verified:
                logger.error("支付宝回调签名校验失败")
                return False, None
            
            # 获取支付宝交易号和订单号
            trade_no = data.get('trade_no')
            order_id = data.get('out_trade_no')
            trade_status = data.get('trade_status')
            total_amount = float(data.get('total_amount', '0'))
            
            # 查询订单
            payment = Payment.query.filter_by(payment_id=order_id).first()
            if not payment:
                logger.error(f"找不到订单: {order_id}")
                return False, None
            
            # 检查金额
            if abs(payment.amount - total_amount) > 0.01:  # 允许1分钱的误差
                logger.error(f"订单金额不匹配: {payment.amount} vs {total_amount}")
                return False, None
            
            # 处理支付状态
            if trade_status == 'TRADE_SUCCESS' or trade_status == 'TRADE_FINISHED':
                # 更新支付记录
                payment.status = 'completed'
                payment.paid_at = datetime.utcnow()
                payment.transaction_id = trade_no
                
                # 查询用户
                user = User.query.get(payment.user_id)
                if not user:
                    logger.error(f"找不到用户: {payment.user_id}")
                    db.session.commit()
                    return True, payment
                
                # 查询用户当前订阅
                existing_subscription = Subscription.query.filter_by(
                    user_id=user.id,
                ).order_by(Subscription.end_date.desc()).first()
                
                # 确定订阅计划
                plan_id = None
                for plan in SUBSCRIPTION_PLANS:
                    if abs(plan['price'] - payment.amount) < 0.01:
                        plan_id = plan['id']
                        break
                
                if not plan_id:
                    logger.error(f"无法确定订阅计划, 金额: {payment.amount}")
                    db.session.commit()
                    return True, payment
                
                # 创建或延长订阅
                if existing_subscription:
                    subscription = self.extend_subscription(
                        existing_subscription, 
                        plan_id, 
                        payment.id, 
                        payment.amount
                    )
                else:
                    subscription = self.create_subscription(
                        user.id, 
                        plan_id, 
                        payment.id, 
                        payment.amount
                    )
                
                # 关联订阅到支付记录
                if subscription:
                    payment.subscription_id = subscription.id
                
                db.session.commit()
                logger.info(f"支付成功并已处理，订单号: {order_id}, 用户: {user.username}")
                return True, payment
            
            # 其他支付状态
            logger.info(f"支付状态: {trade_status}, 订单号: {order_id}")
            return True, payment
        
        except Exception as e:
            logger.exception(f"处理支付宝回调时出错: {str(e)}")
            return False, None
    
    def query_payment(self, order_id):
        """查询支付状态"""
        try:
            payment = Payment.query.filter_by(payment_id=order_id).first()
            if not payment:
                return None, "订单不存在"

            if self.mock_mode:
                logger.warning("使用模拟模式查询支付状态")
                # 模拟模式下，如果付款已完成，返回完成状态
                if payment.status == 'completed':
                    return payment, "success"
                    
                # 模拟模式下，我们可以检查模拟支付URL是否被访问过
                # 这里简单实现：如果订单创建时间超过30秒，我们假设它已被支付
                if (datetime.utcnow() - payment.created_at).total_seconds() > 30:
                    # 更新支付状态
                    payment.status = 'completed'
                    payment.paid_at = datetime.utcnow()
                    
                    # 创建或延长订阅
                    user = User.query.get(payment.user_id)
                    
                    # 查找用户现有订阅 (Remove status filter)
                    subscription = Subscription.query.filter_by(
                        user_id=user.id,
                        # status='active' # <-- REMOVE THIS LINE
                    ).filter(
                        Subscription.end_date > datetime.utcnow() # <-- Check end_date instead
                    ).order_by(Subscription.end_date.desc()).first()
                    
                    if subscription:
                        # 延长订阅
                        self.extend_subscription(
                            subscription, 
                            payment.plan_id, 
                            payment.id, 
                            payment.amount
                        )
                    else:
                        # 创建新订阅
                        self.create_subscription(
                            user.id,
                            payment.plan_id,
                            payment.id,
                            payment.amount
                        )
                    
                    # 更新支付记录的订阅ID (Remove status filter)
                    subscription = Subscription.query.filter_by(
                        user_id=user.id,
                        # status='active' # <-- REMOVE THIS LINE
                    ).filter(
                        Subscription.end_date > datetime.utcnow() # <-- Check end_date instead
                    ).order_by(Subscription.end_date.desc()).first()
                        
                    if subscription:
                        payment.subscription_id = subscription.id
                        
                    db.session.commit()
                    return payment, "success"
                else:
                    return payment, "pending"
            
            # 实际向支付宝查询
            response = self.alipay.api_alipay_trade_query(out_trade_no=order_id)
            
            if response.get('code') == '10000' and response.get('trade_status') in ('TRADE_SUCCESS', 'TRADE_FINISHED'):
                # 更新支付记录
                payment.status = 'completed'
                payment.paid_at = datetime.utcnow()
                payment.transaction_id = response.get('trade_no')
                db.session.commit()
                
                return payment, 'success'
            
            return payment, response.get('msg') or '支付尚未完成'
        
        except Exception as e:
            logger.exception(f"查询支付状态时出错: {str(e)}")
            return None, str(e)
    
    def cancel_payment(self, order_id):
        """取消支付"""
        try:
            result = self.alipay.api_alipay_trade_cancel(out_trade_no=order_id)
            logger.info(f"取消支付, 订单号: {order_id}, 结果: {result}")
            
            if result.get('code') == '10000' and result.get('action') in ('close', 'refund'):
                # 更新支付记录
                payment = Payment.query.filter_by(payment_id=order_id).first()
                if payment:
                    payment.status = 'cancelled'
                    db.session.commit()
                    
                return True, 'success'
            
            return False, result.get('msg') or '取消支付失败'
        
        except Exception as e:
            logger.exception(f"取消支付时出错: {str(e)}")
            return False, str(e)
    
    def refund_payment(self, order_id, amount=None, reason=None):
        """退款"""
        try:
            payment = Payment.query.filter_by(payment_id=order_id).first()
            if not payment:
                return False, '找不到订单'
            
            refund_amount = amount or payment.amount
            
            result = self.alipay.api_alipay_trade_refund(
                out_trade_no=order_id,
                refund_amount=str(refund_amount),
                refund_reason=reason or '用户申请退款'
            )
            
            logger.info(f"退款, 订单号: {order_id}, 金额: {refund_amount}, 结果: {result}")
            
            if result.get('code') == '10000' and result.get('fund_change') == 'Y':
                # 更新支付记录
                payment.status = 'refunded'
                db.session.commit()
                
                # 如果有关联的订阅，也需要更新
                if payment.subscription_id:
                    subscription = Subscription.query.get(payment.subscription_id)
                    if subscription:
                        # 退款后，通常订阅应立即失效，可以将结束日期设为当前时间
                        if subscription.end_date > datetime.utcnow():
                            subscription.end_date = datetime.utcnow()
                            logger.info(f"因退款，订阅 {subscription.id} 的结束日期已设置为当前时间")
                        db.session.commit()
                
                return True, 'success'
            
            return False, result.get('msg') or '退款失败'
        
        except Exception as e:
            logger.exception(f"退款时出错: {str(e)}")
            return False, str(e)

    def cancel_subscription(self, user_id):
        """取消用户的订阅"""
        # 查找活跃订阅
        subscription = Subscription.query.filter(
            Subscription.user_id == user_id,
            Subscription.end_date > datetime.utcnow() # 查找结束日期在未来的订阅
        ).order_by(Subscription.end_date.desc()).first()
        
        if not subscription:
            logger.warning(f"未找到用户 {user_id} 的活动订阅")
            return False, "未找到活动订阅"
            
        # 标记订阅为已取消 (或直接设置结束日期为过去?)
        # subscription.status = 'cancelled' # <-- 移除此行
        # 更好的方式可能是记录取消时间，或者直接让其自然过期
        # 暂时不修改结束日期，让其自然过期。如果需要立即终止，可以设置 end_date = datetime.utcnow()
        logger.info(f"用户 {user_id} 的订阅 {subscription.id} 将在 {subscription.end_date} 自然到期")
        # db.session.commit() # 无需提交更改，除非修改了 end_date
        
        return True, "订阅将在到期后结束"

class ChatGPTSubscriptionService:
    """ChatGPT订阅管理服务"""
    
    @staticmethod
    def assign_chatgpt_account(user_id):
        """为用户分配ChatGPT账号
        
        Args:
            user_id: 用户ID
            
        Returns:
            分配的ChatGPT账号对象，或None表示失败
        """
        try:
            # 查找用户是否已有分配的ChatGPT账号
            existing_account = ChatGPTAccount.query.filter_by(
                user_id=user_id,
                is_active=True
            ).first()
            
            if existing_account:
                logger.info(f"用户 {user_id} 已经分配了ChatGPT账号 {existing_account.id}")
                return existing_account
            
            # 查找可用的未分配ChatGPT账号
            available_account = ChatGPTAccount.query.filter_by(
                user_id=None,
                is_active=True
            ).first()
            
            if not available_account:
                logger.error("没有可用的ChatGPT账号")
                return None
            
            # 分配账号给用户
            available_account.user_id = user_id
            available_account.assigned_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"为用户 {user_id} 分配了ChatGPT账号 {available_account.id}")
            return available_account
            
        except Exception as e:
            logger.error(f"分配ChatGPT账号时出错: {e}")
            db.session.rollback()
            return None
    
    @staticmethod
    def release_chatgpt_account(user_id):
        """释放用户分配的ChatGPT账号
        
        Args:
            user_id: 用户ID
            
        Returns:
            是否释放成功
        """
        try:
            # 查找用户分配的ChatGPT账号
            accounts = ChatGPTAccount.query.filter_by(
                user_id=user_id,
                is_active=True
            ).all()
            
            if not accounts:
                logger.info(f"用户 {user_id} 没有分配的ChatGPT账号")
                return True
            
            # 释放所有账号
            for account in accounts:
                account.user_id = None
                account.assigned_at = None
            
            db.session.commit()
            
            logger.info(f"已释放用户 {user_id} 的 {len(accounts)} 个ChatGPT账号")
            return True
            
        except Exception as e:
            logger.error(f"释放ChatGPT账号时出错: {e}")
            db.session.rollback()
            return False 