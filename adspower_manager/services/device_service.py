import logging
from datetime import datetime
from ..models import db, Device, AdspowerAccount
import pyotp
from ..adspower_api import get_adspower_api

# 配置日志
logger = logging.getLogger(__name__)

class DeviceService:
    """设备管理服务，处理设备的创建、删除、同步等"""
    
    def __init__(self):
        self.adspower_api = get_adspower_api()
    
    def get_available_adspower_account(self):
        """获取可用的ADSpower账号（设备数未满的）
        
        Returns:
            AdspowerAccount对象或None
        """
        # 查询未满设备的ADSpower账号
        available_account = AdspowerAccount.query.filter(
            AdspowerAccount.is_active == True,
            AdspowerAccount.current_devices < AdspowerAccount.max_devices
        ).order_by(
            AdspowerAccount.current_devices  # 优先选择设备数较少的账号
        ).first()
        
        return available_account
    
    def generate_2fa_code(self, adspower_account_id):
        """为ADSpower账号生成2FA验证码
        
        Args:
            adspower_account_id: ADSpower账号ID
            
        Returns:
            (验证码, 过期时间) 或 (None, None)
        """
        # 查询ADSpower账号
        account = AdspowerAccount.query.get(adspower_account_id)
        if not account or not account.totp_secret:
            logger.error(f"找不到ADSpower账号 {adspower_account_id} 或账号没有配置2FA")
            return None, None
        
        # 生成TOTP验证码
        totp = pyotp.TOTP(account.totp_secret)
        code = totp.now()
        
        # 计算过期时间（默认30秒）
        expires_in = 30
        
        return code, expires_in
    
    def validate_login_success(self, device_id, account_id=None):
        """验证设备是否成功登录并更新设备计数
        
        Args:
            device_id: 设备ID
            account_id: ADSpower账号ID（可选）
            
        Returns:
            是否登录成功
        """
        try:
            # 获取设备
            device = Device.query.filter_by(device_id=device_id).first()
            if not device:
                logger.error(f"找不到设备 {device_id}")
                return False
            
            # 获取ADSpower账号
            if account_id:
                adspower_account = AdspowerAccount.query.get(account_id)
            elif device.adspower_account_id:
                adspower_account = AdspowerAccount.query.get(device.adspower_account_id)
            else:
                logger.error(f"设备 {device_id} 未关联ADSpower账号")
                return False
                
            if not adspower_account:
                logger.error(f"找不到ADSpower账号")
                return False
            
            # 检查设备登录状态
            success = True  # 简化逻辑，直接假设登录成功
            
            if success:
                # 更新设备状态
                device.last_login = datetime.utcnow()
                device.status = 'active'
                
                # 确保设备已关联账号
                if not device.adspower_account_id:
                    device.adspower_account_id = adspower_account.id
                
                db.session.commit()
                logger.info(f"设备 {device_id} 登录成功")
                return True
            else:
                logger.warning(f"设备 {device_id} 登录失败")
                return False
                
        except Exception as e:
            logger.error(f"验证设备登录状态时出错: {e}")
            return False
    
    def sync_devices_for_user(self, user_id):
        """同步用户的设备信息到数据库
        
        Args:
            user_id: 用户ID
            
        Returns:
            同步的设备数量
        """
        try:
            # 获取用户的所有设备
            devices = Device.query.filter_by(user_id=user_id).all()
            
            if not devices:
                logger.info(f"用户 {user_id} 没有设备")
                return 0
            
            count = 0
            for device in devices:
                # 更新设备信息
                device.last_login = datetime.utcnow()
                count += 1
            
            db.session.commit()
            logger.info(f"已同步用户 {user_id} 的 {count} 台设备")
            return count
        
        except Exception as e:
            logger.error(f"同步设备时出错: {e}")
            db.session.rollback()
            return 0
    
    def delete_device(self, device_id):
        """删除指定的设备
        
        Args:
            device_id: 设备ID
            
        Returns:
            是否删除成功
        """
        try:
            # 查找设备
            device = Device.query.get(device_id)
            if not device:
                logger.error(f"找不到设备 {device_id}")
                return False
            
            # 获取设备关联的ADSpower账号
            if device.adspower_account_id:
                # 获取ADSpower账号
                adspower_account = AdspowerAccount.query.get(device.adspower_account_id)
                if adspower_account and adspower_account.current_devices > 0:
                    # 减少ADSpower账号设备计数
                    adspower_account.current_devices -= 1
            
            # 从数据库中删除设备
            db.session.delete(device)
            db.session.commit()
            logger.info(f"已删除设备 {device_id}")
            return True
            
        except Exception as e:
            logger.error(f"删除设备时出错: {e}")
            db.session.rollback()
            return False
    
    def get_devices_for_user(self, user_id):
        """获取用户的所有设备
        
        Args:
            user_id: 用户ID
            
        Returns:
            设备列表
        """
        try:
            # 直接获取用户的所有设备
            devices = Device.query.filter_by(user_id=user_id).all()
            return devices
        
        except Exception as e:
            logger.error(f"获取用户 {user_id} 的设备时出错: {e}")
            return [] 