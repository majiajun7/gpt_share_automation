from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains # <-- Import ActionChains
import time
import json
import os
import sys
import platform
import logging
from config import ADSPOWER_COOKIES
from .webdriver_pool import get_account_driver_manager # Import get_account_driver_manager
import threading
from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
from webdriver_manager.chrome import ChromeDriverManager
from adspower_manager.models import AdspowerAccount
from adspower_manager.webdriver_pool import get_account_driver_manager, AccountWebDriverManager # Import AccountWebDriverManager
import re
import hashlib
from sqlalchemy.orm import object_session

# 配置日志
logger = logging.getLogger(__name__)


class AdspowerAPI:
    """AdsPower API访问类"""

    def __init__(self, base_url="https://app-global.adspower.net"):
        """初始化AdsPower API接口
        
        Args:
            base_url: AdsPower平台的基础URL
        """
        self.base_url = base_url
        self.account_driver_lock = threading.RLock()

    def _get_driver(self, account_id, cookies, username=None, password=None, totp_secret=None):
        """获取WebDriver实例

        Args:
            account_id: 账号ID
            cookies: 账号cookies
            username: 用户名（用于登录时使用）
            password: 密码（用于登录时使用）
            totp_secret: TOTP密钥（用于登录时使用）
            
        Returns:
            WebDriver: WebDriver实例
        """
        # --- 获取账号邮箱用于日志 ---
        # 尝试从 AccountWebDriverManager 的缓存获取 email
        driver_manager = get_account_driver_manager()
        account_email = username or driver_manager.account_drivers.get(str(account_id), {}).get('email', '未知邮箱')
        log_prefix = f"[AdsAPI] 账号 {account_email}" # 使用邮箱作为主要标识
        # ---\
        logger.debug(f"{log_prefix} 请求底层WebDriver实例")
        # 使用账号WebDriver管理器获取专用驱动
        driver = driver_manager.get_driver(
            account_id=account_id,
            cookies=cookies,
            username=username,
            password=password,
            totp_secret=totp_secret
        )
        return driver

    def _release_driver(self, account_id, driver):
        """释放WebDriver实例

        Args:
            account_id: 账号ID
            driver: 要释放的WebDriver实例
        """
        # --- 获取账号邮箱用于日志 ---
        driver_manager = get_account_driver_manager()
        account_email = driver_manager.account_drivers.get(str(account_id), {}).get('email', '未知邮箱')
        log_prefix = f"[AdsAPI] 账号 {account_email}" # 使用邮箱作为主要标识
        # ---\
        logger.debug(f"{log_prefix} _release_driver 被调用，但AccountWebDriverManager管理实例生命周期，无需操作")
        # 使用账号WebDriver管理器，无需释放，只需更新最后使用时间
        pass

    def _load_cookies(self, driver, cookies, account_id="未知账号", account_email="未知邮箱"):
        """加载Cookie到指定的WebDriver实例

        Args:
            driver: WebDriver实例
            cookies: 要加载的Cookie列表或字符串
            account_id: 账号ID (用于日志)
            account_email: 账号邮箱 (用于日志)

        Returns:
            bool: 是否成功加载Cookie
        """
        log_prefix = f"[AdsAPI] 账号 {account_email}" # 使用邮箱作为主要标识
        try:
            # 先访问一次网站，才能添加Cookie
            driver.get(self.base_url)
            time.sleep(2)  # 等待页面加载

            if not cookies:
                logger.error(f"{log_prefix} 加载Cookie失败：没有可用的Cookies")
                return False

            logger.info(f"{log_prefix} 准备加载 {len(cookies) if isinstance(cookies, list) else '未知数量'} 个Cookie")

            driver.delete_all_cookies()

            if isinstance(cookies, str):
                try:
                    cookies = json.loads(cookies)
                except:
                    logger.error(f"{log_prefix} Cookies格式无效")
                    return False

            for cookie in cookies:
                try:
                    if isinstance(cookie, str):
                        try:
                            cookie = json.loads(cookie)
                        except:
                            continue

                    if not isinstance(cookie, dict) or 'name' not in cookie or 'value' not in cookie:
                        continue

                    cookie_dict = {
                        'name': cookie['name'],
                        'value': cookie['value'],
                        'domain': cookie.get('domain', '.adspower.net'),
                        'path': cookie.get('path', '/')
                    }

                    if 'expiry' in cookie:
                        cookie_dict['expiry'] = cookie['expiry']

                    driver.add_cookie(cookie_dict)
                except Exception as e:
                    logger.warning(f"{log_prefix} 添加单个Cookie失败: {str(e)}")

            driver.refresh()
            time.sleep(2)

            current_url = driver.current_url
            if "login" in current_url.lower():
                logger.warning(f"{log_prefix} Cookie加载后检测到登录页面，可能无效")
                return False

            return True
        except Exception as e:
            logger.error(f"{log_prefix} 加载Cookie时出错: {str(e)}")
            return False

    def get_devices_info(self, account):
        """获取AdsPower账号的设备列表信息 (适配新的个人设置页面HTML)

        Args:
            account: AdspowerAccount对象

        Returns:
            list: 设备信息列表, 每个设备包含 'id', 'name', 'ip_address', 'status', 'last_open' 等键。
                  如果获取失败或无设备，返回空列表。
        """
        method_start_time = time.time()
        account_id = str(account.id)
        # --- 获取 account_email 用于日志 ---
        account_email = account.username if hasattr(account, 'username') else '未知邮箱'
        log_prefix = f"[AdsAPI] 账号 {account_email}" # 使用邮箱作为主要标识
        logger.info(f"{log_prefix} 开始获取设备信息 (时间: {method_start_time:.3f})")

        # account_email = account.username # 这行可以移除，上面已获取
        # 获取原始的 Cookie (存储在 cookies 字段中)
        original_cookies_str = self._get_account_cookies(account) # 使用辅助方法获取
        driver = None # 初始化 driver
        instance_id = None # <-- Initialize instance_id to None here

        try:
            driver_get_start = time.time()
            logger.info(f"{log_prefix} 准备获取WebDriver实例用于设备扫描 (时间: {driver_get_start:.3f})")
            # 获取 driver manager 实例
            driver_manager = get_account_driver_manager()
            # 调用 driver_manager 获取 driver (只传递 account_id)
            # Manager 内部会处理凭据和 Cookie
            driver, instance_id = driver_manager.get_driver(
                account_id=account_id # 仅传递 account_id
            )
            driver_get_end = time.time()
            logger.info(f"{log_prefix} WebDriver实例获取完成 (耗时: {driver_get_end - driver_get_start:.3f}秒)")

            if not driver:
                logger.error(f"{log_prefix} 无法获取WebDriver实例，无法扫描设备")
                return None # 返回 None 表示驱动获取失败

            # --- 导航到个人设置页面
            device_page_url = f"{self.base_url}/personalSettings"
            navigation_start = time.time()
            logger.info(f"{log_prefix} 开始导航到个人设置页面: {device_page_url} (时间: {navigation_start:.3f})")
            driver.get(device_page_url)
            # 使用 WebDriverWait 等待页面加载完成，而不是固定 time.sleep
            try:
                WebDriverWait(driver, 15).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "div[class^='_session_control_']"))
                )
                navigation_end = time.time()
                logger.info(f"{log_prefix} 个人设置页面加载完成，当前URL: {driver.current_url} (导航耗时: {navigation_end - navigation_start:.3f}秒)")

                # --- END: Check and skip new user guide ---

            except TimeoutException: # This except is for the main page load wait
                navigation_end = time.time()
                msg = f"{log_prefix} 加载个人设置页面超时 (耗时: {navigation_end - navigation_start:.3f}秒)"
                logger.error(msg)
                return None # 无法继续解析
            # --- END: Force Refresh ---

            # --- BEGIN: Parse device information ---
            parsing_successful = False # Initialize Flag (Moved earlier)
            try: # Outer try for parsing setup and 'More' button
                logger.info(f"{log_prefix} 开始解析设备列表...")
                session_control_area = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "div[class^='_session_control_']"))
                )
                logger.info(f"{log_prefix} 找到登录活动区域")

                # --- Locate the 'Other Devices' container specifically ---
                other_devices_container_start = time.time()
                logger.info(f"{log_prefix} 开始查找'其他'设备容器... (时间: {other_devices_container_start:.3f})")
                try:
                    other_devices_container = session_control_area.find_element(By.CSS_SELECTOR, "div[class^='_other_device_']")
                    other_devices_container_end = time.time()
                    logger.info(f"{log_prefix} 找到'其他'设备容器 (耗时: {other_devices_container_end - other_devices_container_start:.3f}秒)")

                    # --- ADD EXPLICIT WAIT for scroll_wrapper ---
                    scroll_wrapper_selector = "div[class^='_scroll_wrapper_']"
                    scroll_wrapper = None # Initialize scroll_wrapper
                    device_elements = []  # Initialize device_elements to be used throughout
                    try:
                        logger.debug(f"{log_prefix} 在'其他设备容器'内等待滚动区域 '{scroll_wrapper_selector}' 可见...")
                        scroll_wrapper = WebDriverWait(other_devices_container, 5).until(
                            EC.visibility_of_element_located((By.CSS_SELECTOR, scroll_wrapper_selector))
                        )
                        logger.debug(f"{log_prefix} 滚动区域 '{scroll_wrapper_selector}' 已找到并可见。")
                        # Populate the main device_elements list here
                        device_elements = scroll_wrapper.find_elements(By.CSS_SELECTOR, "div[class^='_info_wrapper_']")
                        logger.info(f"{log_prefix} 从'其他'设备的滚动区域内获取到 {len(device_elements)} 个初始设备条目") # Changed log slightly
                    except TimeoutException:
                        logger.info(f"{log_prefix} 在'其他设备容器'内等待滚动区域 '{scroll_wrapper_selector}' 超时或未找到，假设无设备条目。")
                        # device_elements remains [] as initialized
                    # --- END ADD EXPLICIT WAIT ---

                except NoSuchElementException:
                    other_devices_container_end = time.time()
                    logger.info(f"{log_prefix} 未找到'其他'设备容器，可能没有其他设备记录 (耗时: {other_devices_container_end - other_devices_container_start:.3f}秒)")
                    return [] # Return empty list if other_devices_container itself is not found

                # --- 点击 "更多" 按钮逻辑 (Search within 'other_devices_container') ---
                more_button_search_start = time.time()
                
                # Use the length of the already fetched device_elements for initial_count
                initial_count = len(device_elements)
                logger.info(f"{log_prefix} 用于'更多'按钮逻辑的初始'其他'设备数量: {initial_count} (基于显式等待结果)")
                
                # 使用JavaScript快速检查是否存在"更多"按钮
                logger.info(f"{log_prefix} 使用JavaScript检查'更多'按钮... (时间: {more_button_search_start:.3f})")
                
                has_more_button_js = """
                    return document.querySelector("div[class^='_other_device_'] div[class^='_see_more_']") !== null;
                """ # Updated selector for more button
                more_button_exists = driver.execute_script(has_more_button_js)
                more_button_search_js_end = time.time()
                logger.info(f"{log_prefix} JavaScript检查'更多'按钮完成 (检查耗时: {more_button_search_js_end - more_button_search_start:.3f}秒)")
                
                if more_button_exists and scroll_wrapper: # Only proceed if scroll_wrapper was found
                    logger.info(f"{log_prefix} JavaScript检测到'更多'按钮存在")
                    click_more_button_js = """
                        var moreBtn = document.querySelector("div[class^='_other_device_'] div[class^='_see_more_']"); // Updated selector
                        if (moreBtn) {
                            moreBtn.click();
                            return true;
                        }
                        return false;
                    """
                    more_button_click_start = time.time()
                    logger.info(f"{log_prefix} 使用JavaScript点击'更多'按钮... (时间: {more_button_click_start:.3f})")
                    click_success = driver.execute_script(click_more_button_js)
                    
                    if click_success:
                        logger.info(f"{log_prefix} JavaScript成功点击'更多'按钮 (时间: {time.time():.3f})")
                        
                        wait_for_more_start = time.time()
                        logger.info(f"{log_prefix} 开始等待设备列表更新... (时间: {wait_for_more_start:.3f})")
                        try:
                            # Wait for the number of _info_wrapper_ elements inside the *found* scroll_wrapper to increase
                            WebDriverWait(scroll_wrapper, 5).until(
                                lambda d: len(d.find_elements(By.CSS_SELECTOR, "div[class^='_info_wrapper_']")) > initial_count
                            )
                            wait_for_more_end = time.time()
                            # Re-fetch device_elements from the same scroll_wrapper
                            device_elements = scroll_wrapper.find_elements(By.CSS_SELECTOR, "div[class^='_info_wrapper_']")
                            final_count_after_wait = len(device_elements)
                            logger.info(f"{log_prefix} 设备列表更新成功，'其他'设备数量从 {initial_count} 增加到 {final_count_after_wait} (等待耗时: {wait_for_more_end - wait_for_more_start:.3f}秒)")
                        except TimeoutException:
                            wait_for_more_end = time.time()
                            logger.warning(f"{log_prefix} 等待设备列表更新超时 (等待: {wait_for_more_end - wait_for_more_start:.3f}秒)，'其他'设备数量未增加 (初始: {initial_count})")
                            # device_elements remains as it was before clicking 'More'
                    else:
                        logger.warning(f"{log_prefix} JavaScript未能点击'更多'按钮，可能点击时按钮已消失 (时间: {time.time():.3f})")
                elif scroll_wrapper: # if more button does not exist but scroll_wrapper does
                    logger.info(f"{log_prefix} JavaScript未检测到'更多'按钮，继续解析当前显示的 {len(device_elements)} 个设备")
                # If scroll_wrapper was not found, device_elements is already [], and we skip 'More' logic
                
                # --- REMOVE Redundant device element fetching section ---
                # The device_elements list is now populated correctly from the explicit wait and 'More' button logic

                devices = []
                js_extraction_successful = False

                # --- 尝试 JS 批量提取 ---
                if device_elements:
                    js_extraction_start = time.time()
                    logger.info(f"{log_prefix} 开始JavaScript批量提取'其他'设备信息... (时间: {js_extraction_start:.3f})")
                    try:
                        # --- Use the JS script from the PREVIOUS edit (which doesn't check isCurrent) ---
                        batch_script = r"""
                        return Array.from(arguments[0]).map(el => {
                            let name = '未知设备';
                            try {
                                let nameElem = el.querySelector("div[class^='_top_info_'] span");
                                if (nameElem && nameElem.textContent.trim()) {
                                    name = nameElem.textContent.trim();
                                } else {
                                    let parentElem = el.querySelector("div[class^='_top_info_']");
                                    name = parentElem ? parentElem.textContent.trim() : name;
                                }
                            } catch (e) { console.error("Error extracting device name: ", e); }

                            let ip = '';
                            try {
                                let ipElem = el.querySelector("div[class^='_bottom_info_']");
                                let ipText = ipElem ? ipElem.textContent.trim() : '';
                                // Regex to find IP (v4 or v6)
                                let ipMatch = ipText.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{3,})/);
                                if (ipMatch) ip = ipMatch[0]; // Use group 0 for the whole match
                            } catch (e) { console.error("Error extracting IP: ", e); }

                            let time = null;
                            try {
                                // Use the specific time span selector from Python logic
                                let dateElem = el.querySelector("span[class^='_date_']");
                                if (dateElem) time = dateElem.textContent.trim();
                            } catch (e) { console.error("Error extracting time: ", e); }


                            let deviceType = 'Unknown';
                            let rawHref = null;
                            try {
                                let useElem = el.querySelector("div[class^='_icon_'] svg use");
                                if (useElem) {
                                    rawHref = useElem.getAttribute('xlink:href') || useElem.getAttribute('href');
                                    if (rawHref && typeof rawHref === 'string' && rawHref.includes('#')) {
                                        deviceType = rawHref.split('#')[1] || 'Unknown';
                                    }
                                }
                            } catch (e) { console.error("Error extracting device type icon: ", e); }

                            return { name: name, ip: ip, time: time, type: deviceType };
                        });
                        """
                        # Pass the CORRECT device_elements (from scroll_wrapper)
                        js_execute_start = time.time()
                        logger.info(f"{log_prefix} 执行JavaScript脚本... (时间: {js_execute_start:.3f})")
                        all_devices_info = driver.execute_script(batch_script, device_elements)
                        js_execute_end = time.time()
                        logger.debug(f"{log_prefix} JavaScript原始返回数据: {json.dumps(all_devices_info)}")
                        logger.info(f"{log_prefix} JavaScript脚本执行完成 (耗时: {js_execute_end - js_execute_start:.3f}秒)，获取到 {len(all_devices_info)} 个原始'其他'设备信息")

                        js_processing_start = time.time()
                        logger.info(f"{log_prefix} 开始处理JavaScript返回的设备信息... (时间: {js_processing_start:.3f})")
                        processed_count = 0
                        for idx, info in enumerate(all_devices_info):
                            # No need to check isCurrent here, as we only passed 'other' devices
                            device_name = info.get('name', f'未知设备_{account_id}_{idx}')
                            generated_id = f"parsed_{hashlib.md5(device_name.encode()).hexdigest()[:8]}"
                            device_data = {
                                'id': generated_id,
                                'name': device_name,
                                'status': 'offline', # Assuming all 'other' devices are offline for this purpose
                                'ip_address': info.get('ip', ''),
                                'last_login': info.get('time'),
                                'device_type': info.get('type', 'Unknown')
                            }
                            devices.append(device_data)
                            processed_count += 1
                        js_processing_end = time.time()
                        js_extraction_end = time.time()
                        logger.info(f"{log_prefix} JavaScript返回数据处理完成 (耗时: {js_processing_end - js_processing_start:.3f}秒)，得到 {processed_count} 个'其他'设备信息")
                        logger.info(f"{log_prefix} 整个JavaScript提取过程完成 (总耗时: {js_extraction_end - js_extraction_start:.3f}秒)")
                        js_extraction_successful = True
                        parsing_successful = True # <--- JS success = parsing success

                    except Exception as js_e:
                        js_extraction_end = time.time()
                        logger.warning(f"{log_prefix} JavaScript批量提取'其他'设备信息失败 (耗时: {js_extraction_end - js_extraction_start:.3f}秒): {str(js_e)}", exc_info=True)
                        devices = [] # Reset list for fallback
                        js_extraction_successful = False
                        # parsing_successful remains False, let Python try

                else:
                    # No elements found initially in the scroll wrapper
                    logger.info(f"{log_prefix} 未在'其他'设备滚动区域找到设备元素。")
                    parsing_successful = True # Successfully determined there are 0 'other' elements

                # --- 回退到 Python 循环 ---
                if not js_extraction_successful and device_elements: # Iterate over the correct device_elements
                    python_fallback_start = time.time()
                    logger.info(f"{log_prefix} JavaScript提取失败，开始Python回退解析... (时间: {python_fallback_start:.3f})")
                    if not device_elements:
                         logger.info(f"{log_prefix} 未找到'其他'设备元素，无法进行Python回退解析。")
                         # parsing_successful remains False (or True if JS path set it)
                    else:
                        for i, element in enumerate(device_elements): # Use correct elements
                            # --- Python parsing loop (NO NEED to check for online status) ---
                            device_info = {}
                            try:
                                # REMOVED: Online status check is not needed as we target 'other' devices
                                name_element = element.find_element(By.CSS_SELECTOR, "div[class^='_top_info_'] span")
                                device_info['name'] = name_element.text.strip()
                                if not device_info['name']:
                                    name_parent = element.find_element(By.CSS_SELECTOR, "div[class^='_top_info_']")
                                    device_info['name'] = name_parent.text.strip()

                                type_element = element.find_element(By.CSS_SELECTOR, "div[class^='_icon_'] svg use")
                                href = type_element.get_attribute('xlink:href') or type_element.get_attribute('href')
                                device_info['device_type'] = href.split('#')[1] if href and '#' in href else 'Unknown'

                                ip_address = ""
                                last_login = None
                                try:
                                    bottom_info_elem = element.find_element(By.CSS_SELECTOR, "div[class^='_bottom_info_']")
                                    bottom_info_text = bottom_info_elem.text.strip()
                                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)', bottom_info_text)
                                    if ip_match: ip_address = ip_match.group(1)
                                    else: logger.warning(f"{log_prefix} [Python] 未能在'其他'设备 '{device_info.get('name', '未知')}' 的文本 '{bottom_info_text}' 中匹配到IP地址")

                                    time_element = element.find_element(By.CSS_SELECTOR, "span[class^='_date_']")
                                    last_login = time_element.text.strip()
                                except NoSuchElementException:
                                    logger.warning(f"{log_prefix} [Python] 解析'其他'设备 {device_info.get('name', '未知')} 的底部信息(IP/时间)时未找到特定元素")
                                except Exception as bottom_e:
                                    logger.error(f"{log_prefix} [Python] 解析'其他'设备 {device_info.get('name', '未知')} 的底部信息时发生意外错误: {bottom_e}", exc_info=True)

                                device_info['ip_address'] = ip_address
                                device_info['last_login'] = last_login
                                device_info['id'] = f"parsed_{hashlib.md5(device_info['name'].encode()).hexdigest()[:8]}"
                                device_info['status'] = 'offline' # Assuming 'other' devices are offline
                                devices.append(device_info)
                                logger.debug(f"{log_prefix} [Python] 成功解析'其他'设备: {device_info}")
                            except NoSuchElementException as parse_inner_err:
                                logger.warning(f"{log_prefix} [Python] 解析单个'其他'设备元素时出错(可能是名称或类型): {parse_inner_err} - 跳过元素 {i+1}")
                                continue
                            except Exception as parse_generic_err:
                                logger.error(f"{log_prefix} [Python] 解析单个'其他'设备元素 {i+1} 时发生未知错误: {parse_generic_err}", exc_info=True)
                                continue
                        # --- End of Python loop ---
                        python_fallback_end = time.time()
                        if devices: # If Python fallback produced results
                             parsing_successful = True
                             logger.info(f"{log_prefix} Python回退解析完成 (耗时: {python_fallback_end - python_fallback_start:.3f}秒)，共找到 {len(devices)} 个有效'其他'设备信息")
                        else: # Python fallback also failed or found nothing
                             logger.warning(f"{log_prefix} Python回退解析未找到有效'其他'设备信息 (耗时: {python_fallback_end - python_fallback_start:.3f}秒)")
                             # If JS failed AND Python found nothing, parsing_successful might still be False.
                             # Let's ensure it's True if we attempted Python fallback, even if 0 results.
                             parsing_successful = True


            except Exception as parse_outer_err: # Correctly aligned with the outer 'try' starting line 226
                # Catches errors in finding session_control_area, other_devices_container etc.
                logger.error(f"{log_prefix} 解析'其他'设备列表时发生外部错误: {parse_outer_err}", exc_info=True) # Correct indentation
                parsing_successful = False # Definite failure here
                if driver and instance_id:
                    driver_manager._save_error_screenshot(driver, account_id, instance_id, "get_devices_parsing_error")
                return None # <--- Return None for definite parsing failure

            # --- END: Parse device information ---
            parsing_end_time = time.time()
            method_end_time = time.time()
            log_method = "JS" if js_extraction_successful else "Python Fallback" if parsing_successful else "Failed"
            logger.info(f"{log_prefix} '其他'设备信息提取完成 (方法: {log_method})，共 {len(devices)} 个设备")
            logger.info(f"{log_prefix} 整个get_devices_info方法执行完成 (总耗时: {method_end_time - method_start_time:.3f}秒)")

            # Return devices list if parsing attempt was completed (parsing_successful is True)
            # Return None only if major exceptions occurred before or during parsing setup
            # If parsing_successful is True, return devices (even if empty)
            # If parsing_successful is False (due to parse_outer_err), None was already returned.
            # The logic implicitly handles this: if we reach here, parsing_successful should be True.
            logger.info(f"{log_prefix} 获取到的设备信息: {devices}") # <-- 新增日志记录
            return devices


        except (TimeoutException, WebDriverException) as wd_e:
             logger.error(f"{log_prefix} WebDriver/Timeout 错误导致获取设备信息失败: {getattr(wd_e, 'msg', str(wd_e))}")
             # parsing_successful remains False (initial value)
             return None # Return None for major webdriver/timeout issues

        except Exception as e:
            logger.error(f"{log_prefix} 获取设备信息时发生未知错误: {str(e)}", exc_info=True)
            # parsing_successful remains False (initial value)
            if driver and instance_id:
                 driver_manager._save_error_screenshot(driver, account_id, instance_id, "get_devices_outer_error")
            return None # Return None for major unexpected errors

        finally:
            if instance_id and account_id:
                release_success = locals().get('parsing_successful', False)
                logger.debug(f"{log_prefix} get_devices_info 完成，准备释放实例 {instance_id} 回管理器 (操作成功标志: {release_success})")
                try:
                    driver_manager.release_driver(account_id, instance_id, success=release_success)
                    logger.info(f"{log_prefix} 实例 {instance_id} 已释放回管理器")
                except Exception as release_e:
                    logger.error(f"{log_prefix} 释放实例 {instance_id} 时出错: {release_e}", exc_info=True)
            elif driver: # Should not happen if instance_id exists
                 logger.warning(f"{log_prefix} 有 driver 对象但无 instance_id 或 account_id，无法正常释放！")

        # Should not be reached
        logger.error(f"{log_prefix} get_devices_info 意外到达函数末尾，返回 None")
        return None # Return None if somehow reached end

    def get_current_devices_count(self, account):
        """获取当前设备数量

        Args:
            account: AdspowerAccount对象

        Returns:
            int: 设备数量
        """
        # --- 获取账号邮箱用于日志 ---
        account_email = account.username if hasattr(account, 'username') else '未知邮箱'
        log_prefix = f"[AdsAPI] 账号 {account_email}" # 使用邮箱作为主要标识
        # ---\
        logger.debug(f"{log_prefix} 请求设备数量")
        devices = self.get_devices_info(account)
        count = len(devices) if devices is not None else -1 # Return -1 if get_devices_info failed
        logger.debug(f"{log_prefix} 设备数量: {count}")
        return count if count >= 0 else 0 # Return 0 if count is -1 (error)

    def check_account_login_status(self, account):
        """检查账号的登录状态和Cookie有效性

        Args:
            account: AdspowerAccount对象

        Returns:
            bool: 是否已登录且Cookie有效
        """
        account_id = str(account.id)
        account_email = account.username if hasattr(account, 'username') else '未知邮箱'
        log_prefix = f"[AdsAPI] 账号 {account_email}" # 使用邮箱作为主要标识
        logger.info(f"{log_prefix} 开始检查登录状态和Cookie有效性")

        driver_manager = get_account_driver_manager()
        driver = None
        instance_id = None # <-- Initialize instance_id to None here

        # --- 不再需要检查缓存的健康状态，直接尝试获取驱动 ---
        # is_healthy = driver_manager.is_account_healthy(account_id)
        # if is_healthy: ... (移除旧的缓存检查逻辑)

        try:
            # 获取 driver (这会触发健康检查和可能的登录)
            # 只传递 account_id
            logger.debug(f"{log_prefix} 尝试从管理器获取实例以检查登录状态...")
            driver, instance_id = driver_manager.get_driver(account_id=account_id, timeout=60)

            if not driver:
                logger.error(f"{log_prefix} 无法获取WebDriver进行登录状态检查 (管理器返回 None)")
                # Explicitly update status? Maybe not needed, manager handles internal state.
                # driver_manager.health_status[account_id] = ...
                return False

            # --- 如果成功获取驱动，说明实例是健康的 (READY 状态) ---
            logger.info(f"{log_prefix} 成功获取到健康实例 {instance_id}，Cookie 有效")

            return True # Getting a READY driver means it's logged in and healthy

        except (RuntimeError, ValueError, TimeoutError) as manager_e: # Catch driver acquisition errors
             logger.warning(f"{log_prefix} 获取实例进行健康检查失败: {manager_e}")
             return False # Cannot get driver, assume unhealthy/login failed
        except Exception as e:
             logger.error(f"{log_prefix} 检查登录状态时发生意外错误: {e}", exc_info=True)
             return False # Unexpected error, assume failure
        finally:
             # 确保获取到的实例被释放回管理器
             if instance_id and account_id:
                  try:
                       logger.debug(f"{log_prefix} check_account_login_status 完成，释放实例 {instance_id}")
                       # If an error occurred *before* getting the driver, instance_id is None.
                       # If an error occurred *after*, assume success=False? Or let manager handle?
                       # Let's assume success=True here, as the check itself was just getting the driver.
                       # If getting driver failed, manager_e was caught. If other error, return False anyway.
                       driver_manager.release_driver(account_id, instance_id, success=True)
                  except Exception as release_e:
                       logger.error(f"{log_prefix} 释放实例 {instance_id} 时出错: {release_e}", exc_info=True)

    def disable_account(self, account):
        """禁用账号（Cookie失效时）

        Args:
            account: AdspowerAccount对象

        Returns:
            bool: 是否成功禁用
        """
        try:
            account_id = str(account.id)
            account_email = account.username if hasattr(account, 'username') else '未知邮箱'
            log_prefix = f"[AdsAPI] 账号 {account_email}" # 使用邮箱作为主要标识
            logger.warning(f"{log_prefix} 准备禁用账号")

            driver_manager = get_account_driver_manager()
            # 尝试关闭与此账号关联的驱动（如果存在）
            driver_manager.close_driver(account_id)

            account.is_active = False
            account.last_error = "Cookie已失效或登录失败，账号已自动禁用"
            account.last_check_time = int(time.time())

            try:
                from sqlalchemy.orm import object_session
                session = object_session(account)
                if session:
                    session.add(account)
                    session.commit()
                    logger.info(f"{log_prefix} 账号已成功禁用")
                    return True
                else:
                    logger.error(f"{log_prefix} 禁用账号失败：无法获取数据库会话")
                    return False # Added return False here
            except Exception as e:
                logger.error(f"{log_prefix} 禁用账号时数据库操作出错: {str(e)}", exc_info=True)
                session = object_session(account)
                if session:
                    session.rollback()
                return False

        except Exception as e:
            logger.error(f"[AdsAPI] 禁用账号 ({account.id if account else '未知'}) 过程中发生外部错误: {str(e)}", exc_info=True)
            return False

    def _get_account_cookies(self, account):
        """从账号对象中获取cookies

        Args:
            account: AdspowerAccount对象

        Returns:
            str or None: cookies字符串，如果无效或没有则返回None
        """
        account_id_str = str(account.id) if account else "未知ID"
        account_email = getattr(account, 'username', '未知邮箱')
        log_prefix = f"[AdsAPI] 账号 {account_email}" # 使用邮箱作为主要标识

        try:
            if not account:
                logger.error(f"[AdsAPI] 获取Cookie失败：account 对象为空")
                return None

            # 优先从新的 cookies 字段读取
            if hasattr(account, 'cookies') and account.cookies:
                 if isinstance(account.cookies, str):
                     # 尝试验证是否是有效的JSON，但即使不是也返回原始字符串，让调用者处理
                     try:
                         json.loads(account.cookies)
                         # logger.debug(f"{log_prefix} cookies 字段包含有效的JSON Cookie")
                     except (json.JSONDecodeError, TypeError):
                         logger.warning(f"{log_prefix} 的 cookies 不是有效的JSON字符串，但仍返回原始内容")
                     return account.cookies
                 else:
                     # 如果不是字符串，尝试序列化（虽然理论上不应该发生）
                     try:
                         logger.warning(f"{log_prefix} 的 cookies 字段不是字符串，尝试序列化")
                         return json.dumps(account.cookies)
                     except Exception as dump_e:
                         logger.error(f"{log_prefix} 无法序列化 cookies: {dump_e}")
                         return None
            else:
                # logger.info(f"{log_prefix} 没有可用的cookies (cookies字段为空或无效)") # 改为debug级别？
                logger.debug(f"{log_prefix} 没有可用的cookies (cookies字段为空)")
                return None
        except Exception as e:
            logger.error(f"{log_prefix} 获取账号cookies时出错: {str(e)}", exc_info=True)
            return None

    def logout_device(self, account, device_name, device_type):
        """通过Selenium退出指定名称和类型的设备登录 (使用同步JS执行)

        Args:
            account: AdspowerAccount 对象
            device_name: 要退出登录的设备在AdsPower页面上显示的名称
            device_type: 要退出登录的设备的类型 (例如 "Windows", "Mac")

        Returns:
            tuple: (bool, str) 操作是否成功及中文消息
        """
        account_id = str(account.id)
        account_email = account.username
        log_prefix = f"[AdsAPI] 账号 {account_email}"
        logger.info(f"{log_prefix} 开始尝试退出设备 '{device_name}' (类型: {device_type})")

        driver = None
        instance_id = None
        operation_success = False
        result_message = f"退出设备 '{device_name}' (类型: {device_type}) 的操作初始失败"

        driver_manager = get_account_driver_manager()

        # Define the JavaScript logout script for execute_script (still uses internal async/await)
        js_logout_script_sync = r"""
        /**
         * Sync Logout Script for execute_script (Still uses internal async/await)
         * Returns status strings.
         */
        async function logoutDeviceViaConsoleSync(targetName, targetType) { // Kept async for internal await
            console.log(`[JS Sync Logout] 开始: 名称=${targetName}, 类型=${targetType}`);

            // --- Define Helpers FIRST ---
            const scrollSel = "div[class^='_scroll_wrapper_']", sessionSel = "div[class^='_session_control_']";
            const rowSel = "div[class^='_info_wrapper_']", onlineSel = "[class*='_online_status_']";
            const nameSel = "div[class^='_top_info_'] span", typeSel = "div[class^='_icon_'] svg use";
            const logoutSel = "span[class^='_remove_login_']", moreSel = "div[class^='_see_more_']";
            const popSel = "div.el-popover.el-popper.session-popover[aria-hidden='false']";
            const confirmSel = "button[class*='_confirm_']", disabledCls = "_disabled_q26e2_66";
            const sleep = ms => new Promise(r => setTimeout(r, ms)); // Still need sleep definition
            const click = el => {
                try {
                    const r = el.getBoundingClientRect();
                    const x = r.left+r.width/2, y=r.top+r.height/2;
                    ['mousedown','mouseup','click'].forEach(t => el.dispatchEvent(
                        new MouseEvent(t, { bubbles:true, cancelable:true, view:window, clientX:x, clientY:y })
                    ));
                    return true;
                } catch(e) {
                    console.error(`[JS Sync Logout] 模拟点击失败: ${e}`);
                    return false;
                }
            };
            const getRows = () => (document.querySelector(scrollSel) || document.querySelector(sessionSel))?.querySelectorAll(rowSel) || [];
            // --- End Helpers ---

            // REMOVED initial sleep

            try {
                // 1. Click "More"
                const moreBtn = document.querySelector(moreSel);
                if (moreBtn && moreBtn.offsetParent) {
                    if (!click(moreBtn)) throw new Error('点击"更多"按钮失败');
                    console.log(`[JS Sync Logout] 已点击"更多"`);
                    const startRows = getRows().length; // Get initial count
                    let waited = 0;
                    // NOTE: execute_script might not fully wait for this await/loop
                    // Corrected loop: wait while row count has not increased and timeout not reached
                    while (getRows().length <= startRows && waited < 5000) {
                        await sleep(150); 
                        waited += 150;
                    }
                    // Log outcome
                    const finalRows = getRows().length;
                    if (finalRows > startRows) {
                        console.log(`[JS Sync Logout] "更多"后行数已从 ${startRows} 增加到 ${finalRows} (等待 ${waited}ms)`);
                    } else {
                        console.log(`[JS Sync Logout] "更多"后行数未在 ${waited}ms 内增加 (初始: ${startRows}, 当前: ${finalRows})`);
                    }
                    console.log(`[JS Sync Logout] "更多"后行数检查完成 (最终行数: ${finalRows}, 耗时: ${waited}ms)`);
                }

                // 2. Find & Click Logout Button
                let logoutBtn = null;
                getRows().forEach((row, i) => {
                    if (logoutBtn || row.querySelector(onlineSel)) return;
                    const nameEl = row.querySelector(nameSel), typeEl = row.querySelector(typeSel), logEl = row.querySelector(logoutSel);
                    if (!nameEl || !typeEl || !logEl) return;
                    const nm = nameEl.textContent.trim();
                    let tp = 'Unknown'; try { const h = typeEl.getAttribute('xlink:href')||typeEl.getAttribute('href'); if(h?.includes('#')) tp=h.split('#')[1]; } catch(e){}
                    if (nm === targetName && tp === targetType) {
                        console.log(`[JS Sync Logout] 在行 ${i} 找到目标`); logoutBtn = logEl;
                    }
                });

                 if (!logoutBtn) {
                     console.warn("[JS Sync Logout] 未找到目标退出按钮");
                     return "Success: Target Not Found"; // Use return
                 }
                 logoutBtn.scrollIntoView({ block: 'center' }); await sleep(150); // Still use internal await
                 try { logoutBtn.click(); } catch(e) {} await sleep(50); // Still use internal await
                 if (!click(logoutBtn)) throw new Error('模拟点击退出按钮失败');
                 console.log("[JS Sync Logout] 退出登录按钮已尝试点击");

                // 3. Wait for & Click Confirmation Popup
                await sleep(500); // Still use internal await
                let pop=null, t=0;
                console.log("[JS Sync Logout] 尝试查找弹窗，选择器:", popSel); // Added log
                // NOTE: execute_script might not fully wait for this await/loop
                while (!pop && t < 8000) {
                    pop = document.querySelector(popSel);
                    if (pop && pop.innerText.includes("确定要退出登录")) {
                        console.log("[JS Sync Logout] 找到弹窗内容匹配。"); // Added log
                        break;
                    }
                    pop = null; await sleep(250); t += 250;
                    console.log("[JS Sync Logout] 等待弹窗... t=", t); // Added log
                }
                 if (!pop) {
                    console.error("[JS Sync Logout] 错误：未找到确认弹窗或内容不符");
                    return "Error: 未找到确认弹窗或内容不符";
                 }
                 console.log("[JS Sync Logout] 找到弹窗，尝试查找确认按钮，选择器:", confirmSel);

                let confirmBtnEl = null;
                let confirmWaitTime = 0;
                const confirmBtnMaxWait = 5000; // Define max wait time

                // NOTE: execute_script might not fully wait for this await/loop
                while (confirmWaitTime < confirmBtnMaxWait) {
                    const c = pop.querySelector(confirmSel); // Find button within the popup
                    if (c) {
                        // Log button found, and its state, even if not "visible" by offsetParent yet
                        console.log(`[JS Sync Logout] 尝试确认按钮: ${c.outerHTML.substring(0,150)}... Visible (offsetParent): ${!!c.offsetParent}, Disabled: ${c.disabled}, textContent: '${c.textContent.trim()}'`);
                        if (c.offsetParent) { // Check for visibility via offsetParent
                            console.log("[JS Sync Logout] 找到可见的确认按钮。");
                            confirmBtnEl = c;
                            break;
                        }
                    } else {
                        // This log might be too frequent if the selector is correct but button not present *yet*
                        // console.log("[JS Sync Logout] 在弹窗内未找到确认按钮，当前选择器:", confirmSel);
                    }
                    await sleep(250); // Sleep interval
                    confirmWaitTime += 250;
                    if (confirmWaitTime < confirmBtnMaxWait && !confirmBtnEl) { // Only log 'waiting' if not about to exit loop and not found
                        console.log(`[JS Sync Logout] 等待确认按钮可见... T+${confirmWaitTime}ms`);
                    }
                }

                 if (!confirmBtnEl) {
                    console.error("[JS Sync Logout] 错误：确认按钮未找到或在超时前未变为可见");
                    return "Error: 确认按钮未找到或未变为可见";
                 }
                 // if (!click(confirmBtnEl)) throw new Error('模拟点击确认按钮失败'); // Original click
                 // Use more robust click simulation from console test
                 try {
                    const r = confirmBtnEl.getBoundingClientRect();
                    const x = r.left + r.width / 2, y = r.top + r.height / 2;
                    ['mousedown', 'mouseup', 'click'].forEach(evtType => confirmBtnEl.dispatchEvent(
                        new MouseEvent(evtType, { bubbles: true, cancelable: true, view: window, clientX: x, clientY: y })
                    ));
                    console.log("[JS Sync Logout] 已通过模拟事件点击确认按钮。");
                 } catch (e_click) {
                    console.error("[JS Sync Logout] 模拟点击确认按钮失败:", e_click);
                    return `Error: 模拟点击确认按钮失败: ${e_click.message}`;
                 }
                 console.log("[JS Sync Logout] 已点击确定。流程结束。");
                 return "Success: Confirmed"; // Use return

            } catch (e) {
                const errorMsg = `Error: ${e.message || e}`;
                console.error(`[JS Sync Logout] ${errorMsg}`);
                return errorMsg; // Use return
            }
        }
        // Invoke the function and return its result (Promise for async func)
        // execute_script handles the promise return value correctly in Selenium 4+
        return logoutDeviceViaConsoleSync(arguments[0], arguments[1]);
        """ # End of JS string

        try:
            # --- 获取 Driver (与之前逻辑类似) ---
            logger.debug(f"{log_prefix} 请求WebDriver实例用于退出设备...")
            driver, instance_id = driver_manager.get_driver(account_id=account_id, timeout=60) # Use account_id only

            if not driver:
                msg = f"{log_prefix} 无法获取WebDriver实例，无法退出设备"
                logger.error(msg)
                operation_success = False
                result_message = msg
                return False, msg # Return early if no driver

            logger.info(f"{log_prefix} 获取到实例 {instance_id} 用于退出操作")

            # --- 导航/确认页面 (与之前逻辑类似，日志更新为中文) ---
            current_url = driver.current_url
            target_page_url = f"{self.base_url}/personalSettings"
            if target_page_url not in current_url:
                logger.warning(f"{log_prefix} 实例 {instance_id} 不在预期页面 ({target_page_url})，当前在 {current_url}。尝试导航...")
                driver.get(target_page_url)
                try:
                    WebDriverWait(driver, 15).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, "div[class^='_session_control_']"))
                    )
                    logger.info(f"{log_prefix} 导航到个人设置页面完成")
                except TimeoutException:
                    msg = f"{log_prefix} 导航到个人设置页面超时"
                    logger.error(msg)
                    raise TimeoutException(msg) # 让外部处理程序处理释放
            else:
                logger.info(f"{log_prefix} 实例 {instance_id} 已在目标页面 {current_url}")

            # 确认主要元素存在 (与之前逻辑类似，日志更新为中文)
            try:
                WebDriverWait(driver, 15).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "div[class^='_session_control_']"))
                )
                logger.info(f"{log_prefix} 个人设置页面关键元素已确认")
            except TimeoutException:
                msg = f"{log_prefix} 加载个人设置页面超时（关键元素未找到）"
                logger.error(msg)
                raise TimeoutException(msg) # 让外部处理程序处理释放

            # --- BEGIN: 刷新页面并等待 **列表可见** --- # MODIFIED SECTION
            try:
                logger.info(f"{log_prefix} 执行退出操作前刷新页面...")
                driver.refresh()
                # 等待页面刷新完成，检查 **第一个设备行** 是否可见
                # This is a stronger indicator than just the container
                first_device_row_selector = "div[class^='_session_control_'] div[class^='_info_wrapper_']"
                logger.debug(f"{log_prefix} 等待第一个设备行可见 (选择器: {first_device_row_selector})...")
                WebDriverWait(driver, 20).until( # Increased timeout slightly to 20s
                    EC.visibility_of_element_located((By.CSS_SELECTOR, first_device_row_selector))
                )
                logger.info(f"{log_prefix} 页面刷新完成且至少一个设备行可见，准备执行退出脚本")
            except TimeoutException:
                # If timeout occurs, maybe there are no devices or the page failed to load list
                # Log a warning but continue to try executing the script, as JS handles 'Target Not Found'
                logger.warning(f"{log_prefix} 刷新后等待第一个设备行可见超时 (20s)。可能无设备或加载失败。仍尝试执行脚本...")
            except (WebDriverException) as refresh_err: # Keep catching other refresh errors
                msg = f"{log_prefix} 刷新个人设置页面或等待元素可见时出错: {getattr(refresh_err, 'msg', str(refresh_err))}"
                logger.error(msg)
                # 即使刷新失败，也尝试继续执行退出脚本，但记录错误
            # --- END: 刷新页面并等待 ---

            # --- BEGIN: 执行 Sync JavaScript 退出脚本 --- # MODIFIED
            try:
                # REMOVED: driver.set_script_timeout(30)
                logger.info(f"{log_prefix} 准备执行 Sync JavaScript 退出脚本...")
                # Execute the SYNC script
                js_result = driver.execute_script(js_logout_script_sync, device_name, device_type) # Use sync script

                # --- Log the ACTUAL result returned ---
                logger.info(f"{log_prefix} JavaScript execute_script 返回: {js_result} (类型: {type(js_result)})" )

                # --- Check success based on expected string --- (Logic Remains the Same)
                if isinstance(js_result, str) and js_result.startswith("Success"):
                    logger.info(f"{log_prefix} JavaScript 脚本报告成功: {js_result}")
                    operation_success = True
                    # Use a more specific message based on the return string
                    if js_result == "Success: Target Not Found":
                        result_message = f"设备 '{device_name}' (类型: {device_type}) 在页面上未找到，视为已退出"
                    else: # Assumes "Success: Confirmed"
                         result_message = f"设备 '{device_name}' (类型: {device_type}) 已成功退出登录"
                elif isinstance(js_result, str) and js_result.startswith("Error:"):
                     logger.error(f"{log_prefix} JavaScript 脚本明确返回错误: {js_result}")
                     operation_success = False
                     result_message = f"退出设备 '{device_name}' (类型: {device_type}) 失败：JS报告 - {js_result}"
                     driver_manager._save_error_screenshot(driver, account_id, instance_id, "logout_js_returned_error")
                else:
                    # Unexpected result
                    logger.error(f"{log_prefix} JavaScript 脚本返回意外结果: {js_result}。假设退出失败。")
                    operation_success = False
                    result_message = f"退出设备 '{device_name}' (类型: {device_type}) 失败：JS 返回意外结果 ({type(js_result).__name__})"
                    driver_manager._save_error_screenshot(driver, account_id, instance_id, "logout_js_unexpected_result")

            except WebDriverException as e_js_exec:
                # Catches other WebDriver errors during script execution
                error_message = getattr(e_js_exec, 'msg', str(e_js_exec))
                js_error_match = re.search(r"javascript error: (.*)", error_message, re.IGNORECASE)
                extracted_error = js_error_match.group(1).strip() if js_error_match else error_message

                if "[JS Sync Logout]" in extracted_error: # Check for new prefix
                     log_message = f"{log_prefix} JavaScript 退出脚本执行期间报告错误: {extracted_error}"
                     logger.error(log_message)
                     result_message = f"退出设备 '{device_name}' (类型: {device_type}) 失败：JS报告 - {extracted_error}"
                else:
                     log_message = f"{log_prefix} 执行 JavaScript 退出脚本时发生 WebDriver 错误: {extracted_error}"
                     logger.error(log_message, exc_info=True)
                     result_message = f"退出设备 '{device_name}' (类型: {device_type}) 失败：脚本执行错误"

                operation_success = False
                driver_manager._save_error_screenshot(driver, account_id, instance_id, "logout_js_execution_error")

            except Exception as e_generic_script:
                msg = f"{log_prefix} 执行 JavaScript 退出脚本时发生未知错误: {e_generic_script}"
                logger.error(msg, exc_info=True)
                operation_success = False
                result_message = f"退出设备 '{device_name}' (类型: {device_type}) 失败：未知脚本错误"
                driver_manager._save_error_screenshot(driver, account_id, instance_id, "logout_js_unknown_error")
            # --- END: 执行 Sync JavaScript 退出脚本 ---

            # --- BEGIN: 获取并打印 JS 控制台日志 (已注释) ---
            # try:
            #     if driver:
            #         browser_logs = driver.get_log('browser')
            #         if browser_logs:
            #             logger.debug(f"{log_prefix} JavaScript控制台日志开始 --------")
            #             for entry in browser_logs:
            #                 log_level = entry.get('level', 'UNKNOWN')
            #                 log_message = entry.get('message', '')
            #                 # 清理日志消息中的潜在控制字符或多余引用
            #                 log_message = log_message.replace('\\"', '"').replace('\n', '\n').strip('"')
            #                 logger.debug(f"{log_prefix} [JS Console {log_level}] {log_message}")
            #             logger.debug(f"{log_prefix} JavaScript控制台日志结束 --------")
            #         else:
            #             logger.debug(f"{log_prefix} 未获取到 JavaScript 控制台日志。")
            # except Exception as log_err:
            #     logger.warning(f"{log_prefix} 获取或处理 JavaScript 控制台日志时出错: {log_err}")
            # --- END: 获取并打印 JS 控制台日志 ---

        except (TimeoutException, WebDriverException) as wd_e:
             # Catch errors from navigation, initial waits, or re-raised TimeoutExceptions
             # Use Chinese log messages
             err_msg_extracted = getattr(wd_e, 'msg', str(wd_e))
             result_message = f"WebDriver/超时错误: {err_msg_extracted}"
             logger.error(f"{log_prefix} WebDriver/超时错误导致退出设备 '{device_name}' (类型: {device_type}) 失败: {result_message}")
             operation_success = False
             # Let finally handle the release
        except Exception as e:
            # Use Chinese log messages
            msg = f"{log_prefix} 退出设备 '{device_name}' (类型: {device_type}) 时发生未知错误: {str(e)}"
            logger.error(msg, exc_info=True)
            operation_success = False
            result_message = msg # Set result message for finally
            # Let finally handle the release

        finally:
            # Use the robust finally block, update log messages to Chinese
            if instance_id and account_id:
                logger.debug(f"{log_prefix} logout_device 完成，准备释放实例 {instance_id} (操作成功标志: {operation_success})")
                try:
                    driver_manager.release_driver(account_id, instance_id, success=operation_success)
                    logger.info(f"{log_prefix} 实例 {instance_id} 已释放回管理器")
                except Exception as release_e:
                    logger.error(f"{log_prefix} 释放实例 {instance_id} 时出错: {release_e}", exc_info=True)
            elif driver: # Should not happen if instance_id exists
                 logger.warning(f"{log_prefix} 存在 driver 对象但无 instance_id 或 account_id，无法正常释放！")

        # Return the final status and message
        return operation_success, result_message


# 全局AdsPower API实例
_adspower_api = None


def get_adspower_api():
    """获取全局AdsPower API实例"""
    global _adspower_api
    if _adspower_api is None:
        _adspower_api = AdspowerAPI()
    return _adspower_api

# --- Cookie Handling --- #

def get_stored_cookies(account):
    """从 AdspowerAccount 对象获取存储的 Cookies (JSON字符串)

    Args:
        account: AdspowerAccount 对象

    Returns:
        str: Cookies JSON 字符串，如果无效或不存在则返回 None
    """
    log_prefix = f"[Cookie Util 账号 {account.username} (ID: {account.id})]"
    # 优先从新的 cookies 字段读取
    if hasattr(account, 'cookies') and account.cookies:
        if isinstance(account.cookies, str):
            # 验证是否是有效的 JSON
            try:
                json.loads(account.cookies)
                logger.debug(f"{log_prefix} cookies 字段包含有效的JSON Cookie")
                return account.cookies
            except json.JSONDecodeError:
                logger.warning(f"{log_prefix} 的 cookies 不是有效的JSON字符串，但仍返回原始内容")
                return account.cookies # 返回原始字符串供调试?
            except Exception as parse_err:
                logger.error(f"{log_prefix} 解析 cookies 字符串时出错: {parse_err}")
                return None
        elif isinstance(account.cookies, (list, dict)):
            # 如果是列表或字典，尝试序列化（理论上不应发生，应存储为字符串）
            logger.warning(f"{log_prefix} 的 cookies 字段不是字符串，尝试序列化")
            try:
                return json.dumps(account.cookies)
            except Exception as dump_e:
                logger.error(f"{log_prefix} 无法序列化 cookies: {dump_e}")
                return None
        else:
            logger.warning(f"{log_prefix} cookies 字段类型未知: {type(account.cookies)}，无法使用")
            return None
            
    # 如果 cookies 字段为空或不存在，可以考虑是否需要回退到 remarks (如果确定旧数据可能存在那里)
    # 但为了清晰，这里默认只使用 cookies 字段
    # logger.info(f"{log_prefix} 没有可用的cookies (cookies字段为空或无效)")
    return None

def _login_and_get_cookies(self, account):
    # ... (函数内其他逻辑不变) ...
    
    try:
        # ... (登录操作代码) ...
        
        if login_success:
            logger.info(f"{log_prefix} 登录成功，获取新 Cookies")
            new_cookies_list = self.driver.get_cookies()
            
            if new_cookies_list:
                try:
                    new_cookies_str = json.dumps(new_cookies_list)
                    # 更新 account 对象的 cookies 字段
                    account.cookies = new_cookies_str 
                    # 如果需要，也更新 remarks? (注释掉)
                    # account.remarks = new_cookies_str 
                    db.session.add(account) # 将更改添加到会话
                    # 注意：这里不 commit，由调用者负责 commit
                    logger.info(f"{log_prefix} 新 Cookies 已更新到 account 对象的 cookies 字段 (未提交)")
                    return new_cookies_list, None
                except Exception as json_err:
                    error_message = f"序列化新 Cookie 失败: {json_err}"
                    logger.error(f"{log_prefix} {error_message}")
                    return None, error_message
            else:
                error_message = "登录成功但未能获取 Cookies"
                logger.warning(f"{log_prefix} {error_message}")
                return None, error_message
        else:
            # login_result 包含错误信息
            return None, login_result[1]
    except Exception as e:
         # ... (异常处理) ...
        return None, f"登录或获取 Cookie 时发生异常: {e}"
    finally:
        # ... (清理逻辑) ...
        pass
