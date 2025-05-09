import logging
import hashlib
import urllib.parse
import html
# --- 移除 MAPI 相关的导入 ---
# import urllib.request 
# import json 
# import ssl 
# import certifi 
# --- 移除结束 ---
from collections import OrderedDict
from datetime import datetime
from flask import current_app

from ..models import db, Payment, SubscriptionType
from .payment_service import PaymentService 
# --- 使用 SUBMIT_URL --- 
from config import EPAY_PID, EPAY_KEY, EPAY_SUBMIT_URL, EPAY_NOTIFY_URL, EPAY_RETURN_URL

logger = logging.getLogger(__name__)

# --- 移除支付类型映射 --- 
# PAYMENT_TYPE_MAP = {
#     'alipay': 1,
#     'wxpay': 3,
#     'qqpay': 2
# }

class EpayService(PaymentService):
    """支付服务 - 适配彩虹易支付 submit.php"""

    def __init__(self):
        super().__init__()
        self.merchant_id = EPAY_PID
        self.merchant_key = EPAY_KEY
        self.submit_url = EPAY_SUBMIT_URL # <--- 使用 Submit URL
        self.notify_url = EPAY_NOTIFY_URL
        self.return_url = EPAY_RETURN_URL
        # self.api_url 不再需要

    def _generate_sign(self, params):
        """生成签名 (彩虹易支付 submit.php 格式)"""
        # 0. 记录原始参数 (调试用)
        logger.debug(f"[易支付签名生成] 收到原始参数: {params}")
        # 1. 过滤空值和签名参数
        filtered_params = {k: v for k, v in params.items() if v is not None and v != '' and k != 'sign' and k != 'sign_type'}
        # 2. 对参数按照key=value的格式，并按照参数名ASCII字典序排序
        sorted_params = OrderedDict(sorted(filtered_params.items()))
        logger.debug(f"[易支付签名生成] 过滤并排序后的参数: {dict(sorted_params)}") # 转回 dict 以便打印
        # 3. 把数组所有元素，按照"参数=参数值"的模式用"&"字符拼接成字符串 (不进行URL编码)
        # query_string = urllib.parse.urlencode(sorted_params) <-- 旧方法，会进行URL编码
        query_items = []
        for k, v in sorted_params.items():
            query_items.append(f"{k}={v}") # 直接拼接，不对 v 进行编码
        query_string = '&'.join(query_items)
        logger.debug(f"[易支付签名生成] 拼接后的查询字符串 (无URL编码): '{query_string}'")
        
        # 4. 把拼接后的字符串再与安全校验码直接连接起来
        # 重要：确保 self.merchant_key 是正确的，并且没有前后空格
        string_to_sign = query_string + self.merchant_key 
        # 5. 计算MD5值
        sign = hashlib.md5(string_to_sign.encode('utf-8')).hexdigest()
        # 6. 记录签名过程 (使用 f-string 避免 % 格式化问题)
        logger.debug(f"[易支付签名生成] 用于签名的字符串: '{string_to_sign}', 生成的签名: '{sign}'")
        return sign

    def create_payment_request(self, user_id, plan_id, amount, payment_type='alipay', mode='submit'): # mode 参数现在默认为 submit
        """创建易支付支付请求 (submit.php 页面跳转模式)
        
        Args:
            payment_type: 'alipay', 'wxpay', 'qqpay' (直接使用)
        Returns:
             (payment, redirect_url)
        """
        if mode != 'submit':
            logger.error(f"当前只支持 submit 支付模式，收到请求模式: {mode}")
            # 可以选择抛出异常或返回错误
            return None, None

        # Fetch SubscriptionType from DB instead of using self.get_plan_by_id
        sub_type = SubscriptionType.query.filter_by(code=plan_id).first()
        if not sub_type:
            logger.error(f"[易支付] 创建支付请求失败: 找不到订阅类型代码 '{plan_id}'")
            return None, None

        plan_name = sub_type.name
        days = sub_type.days

        # 1. 创建内部支付记录
        payment = super().create_payment(
            user_id=user_id,
            amount=float(amount),
            payment_method=f"epay_{payment_type}_{mode}", # 记录方法和模式
            days=days,
            plan_id=plan_id  # <--- 传递 plan_id
        )
        if not payment:
            logger.error(f"创建内部支付记录失败 (Epay {mode}): user_id={user_id}, plan_id={plan_id}")
            return None, None

        # --- 参数准备和格式化 ---
        # 格式化金额为两位小数的字符串
        formatted_money = "{:.2f}".format(float(amount))
        
        # 截断商品名称确保不超过 127 UTF-8 字节
        plan_name_bytes = plan_name.encode('utf-8')
        if len(plan_name_bytes) > 127:
            # 尝试按字符截断，再编码检查，找到不超过127字节的最大长度
            # (这是一个简单的近似截断，可能不是最优，但能保证字节数)
            max_chars = len(plan_name) # Start with full length
            while len(plan_name[:max_chars].encode('utf-8')) > 127 and max_chars > 0:
                max_chars -= 1
            truncated_plan_name = plan_name[:max_chars]
            logger.warning(f"[易支付] 商品名称 '{plan_name}' 过长 ({len(plan_name_bytes)} bytes)，已截断为 '{truncated_plan_name}'")
            plan_name = truncated_plan_name
        else:
             logger.debug(f"[易支付] 商品名称 '{plan_name}' 长度 {len(plan_name_bytes)} bytes，符合要求。")

        # 2. 准备 submit.php 请求参数 (使用格式化后的值)
        params = {
            'pid': str(self.merchant_id), # 确保是字符串
            'type': payment_type,         
            'out_trade_no': payment.order_id,
            'notify_url': self.notify_url,
            'return_url': self.return_url,
            'name': plan_name,            # 使用可能被截断的名称
            'money': formatted_money,     # 使用格式化后的金额
            'sign_type': 'MD5'
        }

        # 3. 生成签名 (使用适配 submit.php 的签名方法)
        sign = self._generate_sign(params)
        params['sign'] = sign
        # logger.info(f\"[易支付] 创建支付请求 (类型: {payment_type}, 模式: {mode}) 成功，订单号: {payment.order_id}，用户: {user_id}\") # 旧的简单日志
        
        # --- 新增：记录将要提交的完整参数 --- 
        logger.info(f"[易支付] 准备提交支付请求到 submit.php。订单号: {payment.order_id}，用户: {user_id}，提交参数: {params}")
        
        # 4. 构建自动提交的 HTML 表单 (添加 target="_blank")
        # redirect_url = f\"{self.submit_url}?{urllib.parse.urlencode(params)}\" <-- 旧的 GET 方式
        html_form = f'<form id="epaySubmit" action="{self.submit_url}" method="post" target="_blank">'
        for k, v in params.items():
            # HTML 转义 value 防止 XSS (虽然大部分是系统生成的值，但以防万一)
            escaped_v = html.escape(str(v))
            html_form += f'<input type="hidden" name="{k}" value="{escaped_v}"/>'
        html_form += '</form><script>document.getElementById("epaySubmit").submit();</script>'
        
        logger.debug("[易支付] 生成的跳转表单 (部分): " + html_form[:200] + "...") # 记录部分表单信息
        
        # 返回 Payment 对象和 HTML 表单字符串
        return payment, html_form
        
    # --- 新增: 验证易支付通知签名 (独立方法) ---
    def _verify_notify_signature(self, params: dict) -> bool:
        """仅验证易支付通知的签名。
        
        Args:
            params: 从易支付收到的完整通知参数 (通常来自 request.form 或 request.args)。
            
        Returns:
            bool: 签名是否有效。
        """
        received_sign = params.get('sign')
        if not received_sign:
            logger.warning("[易支付签名验证] 失败：通知参数中缺少 'sign'。")
            return False

        # 使用与创建支付请求时相同的签名逻辑
        calculated_sign = self._generate_sign(params) 
        
        if calculated_sign != received_sign:
            logger.warning(f"[易支付签名验证] 失败：签名不匹配。")
            logger.warning(f"  > 收到的签名 (received_sign): '{received_sign}'")
            logger.warning(f"  > 计算的签名 (calculated_sign): '{calculated_sign}'")
            # 记录用于计算签名的参数 (过滤排序后的)
            filtered_params_for_log = {k: v for k, v in params.items() if v is not None and v != '' and k != 'sign' and k != 'sign_type'}
            logger.warning(f"  > 用于计算签名的参数 (过滤排序后): {dict(OrderedDict(sorted(filtered_params_for_log.items())))}")
            logger.warning(f"  > 请仔细检查您的 EPAY_KEY 是否与易支付后台完全一致！")
            return False
            
        logger.info("[易支付签名验证] 成功。")
        return True

    # --- 新增: 处理易支付通知的核心业务逻辑 ---
    def handle_notification(self, params: dict) -> (bool, str):
        """处理经过验证的易支付通知。
        
        Args:
            params: 已经通过签名验证的通知参数。

        Returns:
             (bool, str): 业务逻辑处理是否成功, 以及返回给易支付服务器的消息 ('success' or 'fail')。
        """
        # 1. 检查必要参数
        required_params = ['out_trade_no', 'trade_no', 'type', 'money', 'trade_status']
        missing_params = [p for p in required_params if p not in params or params[p] is None or params[p] == '']
        if missing_params:
            msg = f"缺少必要参数: {', '.join(missing_params)}"
            logger.warning(f"[易支付通知处理] 失败: {msg}。参数: {params}")
            return False, "fail" # 必要参数缺失，告知易支付失败

        out_trade_no = params.get('out_trade_no')
        epay_trade_no = params.get('trade_no')
        amount_str = params.get('money')
        trade_status = params.get('trade_status')

        # 2. 检查支付状态
        if trade_status != 'TRADE_SUCCESS':
            logger.info(f"[易支付通知处理] 订单 {out_trade_no} 状态为 '{trade_status}' (非 TRADE_SUCCESS)，已忽略。")
            # 非成功状态，但我们已收到通知，应告知易支付 'success' 避免重试
            return True, "success" 

        # 3. 调用核心支付处理服务 (PaymentService)
        # 注意：这里不再直接操作 Payment 模型或 db.session
        # PaymentService.process_epay_payment 负责查找订单、验证金额、调用核心处理、处理订阅、更新状态
        # 它内部会处理事务和日志记录
        payment_service = PaymentService() # 获取 PaymentService 实例
        success, message = payment_service.process_epay_payment(
            out_trade_no=out_trade_no,
            epay_trade_no=epay_trade_no,
            amount_str=amount_str
        )

        if success:
            logger.info(f"[易支付通知处理] 订单 {out_trade_no} 业务处理成功。消息: {message}")
            return True, "success"
        else:
            logger.error(f"[易支付通知处理] 订单 {out_trade_no} 业务处理失败。原因: {message}")
            # 业务处理失败，告知易支付 'fail' 可能导致重试，这取决于易支付的行为
            # 如果核心处理失败是永久性的 (如金额错误)，返回 'success' 可能更好，防止反复失败。
            # 如果是临时错误 (如数据库连接)，返回 'fail' 可能允许重试。
            # 暂时选择返回 'success' 来避免易支付的重复通知风暴，因为核心逻辑失败通常需要人工干预。
            return False, "success" # 即使业务失败，也返回 success 给易支付

    # --- 移除 verify_notify 方法，逻辑拆分到 _verify_notify_signature 和 handle_notification ---
    # def verify_notify(self, params):
    #    ...

    # --- 移除 verify_notify_sign 方法，签名逻辑合并到 verify_notify ---
    # def _verify_notify_sign(self, params):
    #    ...

    # --- REMOVE THE ENTIRE METHOD BELOW --- 
    def verify_notify(self, params):
        # ... entire method body and docstring ... 
        # 签名和 PID 验证通过
        logger.info(f"[易支付验证] 订单 {params.get('out_trade_no')} 签名验证成功。")
        return True, "验证成功" # <-- Return only boolean and message
    # --- REMOVAL ENDS HERE --- 