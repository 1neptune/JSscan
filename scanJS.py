import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, urlunparse
import time
from collections import deque
import os
import hashlib
import re
import shutil
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==================== 配置 ====================
USE_SELENIUM = True  # 是否启用 Selenium 动态渲染
SELENIUM_DRIVER_PATH = None  # ChromeDriver 路径，None 则自动查找
HEADLESS_MODE = True  # 无头模式
PAGE_LOAD_TIMEOUT = 10  # 页面加载超时（秒）
DYNAMIC_WAIT_TIME = 3  # 动态内容等待时间（秒）


# ==================== 核心功能 ====================

def get_domain_from_url(url):
    """从 URL 中提取域名"""
    parsed = urlparse(url)
    return parsed.netloc


def get_main_domain(domain):
    """提取主域名（如 1295.marcopolo.com.cn -> marcopolo.com.cn）"""
    parts = domain.split('.')
    if len(parts) >= 2:
        if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net']:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return domain


def is_external_link(link_url, start_url):
    """判断是否为外部链接（排除目标域名及所有子域名）"""
    link_parsed = urlparse(link_url)
    start_parsed = urlparse(start_url)

    if not link_parsed.netloc:
        return False

    link_domain = link_parsed.netloc
    start_domain = start_parsed.netloc

    if link_domain == start_domain:
        return False

    main_domain = get_main_domain(start_domain)

    if link_domain.endswith('.' + main_domain) or link_domain == main_domain:
        return False

    return True


def get_file_hash(content):
    """计算文件内容的 MD5"""
    return hashlib.md5(content).hexdigest()


def clean_directory(base_dir):
    """清空目录"""
    if os.path.exists(base_dir):
        logger.info(f"清空旧目录: {base_dir}/")
        shutil.rmtree(base_dir)
    os.makedirs(base_dir, exist_ok=True)


def download_js_file(url, save_dir, existing_hashes, existing_filenames):
    """下载 JS 文件，支持去重"""
    try:
        parsed = urlparse(url)
        path = parsed.path
        if not path or path.endswith('/'):
            filename = 'index.js'
        else:
            filename = os.path.basename(path)
            if not filename.endswith('.js'):
                filename += '.js'

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        resp = requests.get(url, timeout=30, headers=headers)

        if resp.status_code == 200:
            content = resp.content
            file_hash = get_file_hash(content)

            if filename in existing_filenames:
                existing_hash = existing_filenames[filename]
                if existing_hash == file_hash:
                    logger.info(f"    内容重复，已跳过（与 {filename} 相同）")
                    return True, filename, True

            if filename in existing_filenames:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
                base_name, ext = os.path.splitext(filename)
                final_filename = f"{base_name}_{timestamp}{ext}"
                logger.info(f"    文件名冲突，使用时间戳: {final_filename}")
            else:
                final_filename = filename

            counter = 1
            while os.path.exists(os.path.join(save_dir, final_filename)):
                base_name, ext = os.path.splitext(final_filename)
                if '_' in base_name and re.search(r'\d{8}_\d{6}_\d{3}$', base_name):
                    final_filename = f"{base_name}_{counter}{ext}"
                else:
                    final_filename = f"{base_name}_{counter}{ext}"
                counter += 1

            filepath = os.path.join(save_dir, final_filename)
            with open(filepath, 'wb') as f:
                f.write(content)

            if filename not in existing_filenames:
                existing_filenames[filename] = file_hash
            else:
                existing_filenames[filename] = file_hash

            if file_hash not in existing_hashes:
                existing_hashes[file_hash] = final_filename

            return True, final_filename, False
        else:
            return False, f"HTTP {resp.status_code}", False

    except Exception as e:
        return False, str(e), False


# ==================== Selenium 动态渲染 ====================

def get_selenium_driver():
    """获取 Selenium WebDriver，使用 webdriver-manager 自动管理驱动"""
    chrome_options = Options()
    if HEADLESS_MODE:
        chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-blink-features=AutomationControlled')
    chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])
    chrome_options.add_experimental_option('useAutomationExtension', False)

    # 禁用图片加载加速
    prefs = {
        'profile.default_content_setting_values': {
            'images': 2,
            'stylesheets': 2
        }
    }
    chrome_options.add_experimental_option('prefs', prefs)

    # 使用 webdriver-manager 自动管理 ChromeDriver
    if SELENIUM_DRIVER_PATH:
        service = Service(SELENIUM_DRIVER_PATH)
        driver = webdriver.Chrome(service=service, options=chrome_options)
    else:
        # 自动下载并管理 ChromeDriver
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

    driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)

    return driver


def render_page_with_selenium(url, driver):
    """
    使用 Selenium 渲染页面，获取动态生成的内容
    返回: (渲染后的 HTML, 页面中的 JS URL 列表, 外部链接列表)
    """
    try:
        logger.info(f"  [Selenium] 渲染页面: {url}")
        driver.get(url)

        # 等待页面加载完成
        WebDriverWait(driver, PAGE_LOAD_TIMEOUT).until(
            EC.presence_of_element_located((By.TAG_NAME, 'body'))
        )

        # 额外等待动态内容加载
        time.sleep(DYNAMIC_WAIT_TIME)

        # 滚动页面触发懒加载
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(1)
        driver.execute_script("window.scrollTo(0, 0);")
        time.sleep(0.5)

        # 获取渲染后的 HTML
        html = driver.page_source

        # 提取所有外部链接（包括动态创建的）
        external_links = extract_external_links_from_driver(driver, url)

        # 提取所有 script src
        js_urls = extract_js_urls_from_driver(driver, url)

        # 提取事件属性中的 URL（onclick, onload, onmouseover 等）
        event_urls = extract_event_urls_from_driver(driver, url)
        external_links.extend(event_urls)

        # 提取动态注入的恶意代码（document.write, innerHTML）
        dynamic_injections = extract_dynamic_injections(driver)
        external_links.extend(dynamic_injections)

        # 提取 window.location / top.location 跳转
        location_redirects = extract_location_redirects(driver, url)
        external_links.extend(location_redirects)

        return html, js_urls, external_links

    except TimeoutException:
        logger.warning(f"  [Selenium] 页面加载超时: {url}")
        return None, [], []
    except Exception as e:
        logger.warning(f"  [Selenium] 渲染失败: {e}")
        return None, [], []


def extract_external_links_from_driver(driver, start_url):
    """从 Selenium 驱动中提取所有外部链接（包括动态生成的）"""
    external_links = []

    try:
        # 提取所有 a 标签
        elements = driver.find_elements(By.TAG_NAME, 'a')
        for elem in elements:
            try:
                href = elem.get_attribute('href')
                if href and is_external_link(href, start_url):
                    tag_html = elem.get_attribute('outerHTML')
                    external_links.append((href, tag_html))
            except:
                pass

        # 提取所有 iframe
        elements = driver.find_elements(By.TAG_NAME, 'iframe')
        for elem in elements:
            try:
                src = elem.get_attribute('src')
                if src and is_external_link(src, start_url):
                    tag_html = elem.get_attribute('outerHTML')
                    external_links.append((src, tag_html))
            except:
                pass

        # 提取所有 link
        elements = driver.find_elements(By.TAG_NAME, 'link')
        for elem in elements:
            try:
                href = elem.get_attribute('href')
                if href and is_external_link(href, start_url):
                    tag_html = elem.get_attribute('outerHTML')
                    external_links.append((href, tag_html))
            except:
                pass

        # 提取所有 img
        elements = driver.find_elements(By.TAG_NAME, 'img')
        for elem in elements:
            try:
                src = elem.get_attribute('src')
                if src and is_external_link(src, start_url):
                    tag_html = elem.get_attribute('outerHTML')
                    external_links.append((src, tag_html))
            except:
                pass

        # 提取所有 script
        elements = driver.find_elements(By.TAG_NAME, 'script')
        for elem in elements:
            try:
                src = elem.get_attribute('src')
                if src and is_external_link(src, start_url):
                    tag_html = elem.get_attribute('outerHTML')
                    external_links.append((src, tag_html))
            except:
                pass

    except Exception as e:
        logger.warning(f"  [Selenium] 提取外部链接失败: {e}")

    return external_links


def extract_js_urls_from_driver(driver, start_url):
    """从 Selenium 驱动中提取所有 JS URL"""
    js_urls = []

    try:
        elements = driver.find_elements(By.TAG_NAME, 'script')
        for elem in elements:
            try:
                src = elem.get_attribute('src')
                if src:
                    full_url = urljoin(start_url, src)
                    js_urls.append(full_url)
            except:
                pass
    except Exception as e:
        logger.warning(f"  [Selenium] 提取 JS URL 失败: {e}")

    return js_urls


def extract_event_urls_from_driver(driver, start_url):
    """
    提取事件属性中的 URL
    onclick, onload, onmouseover, ondblclick, oncontextmenu 等
    """
    external_links = []

    # 事件属性列表
    event_attrs = [
        'onclick', 'ondblclick', 'onmousedown', 'onmouseup',
        'onmouseover', 'onmouseout', 'onmousemove',
        'onload', 'onunload', 'onresize', 'onscroll',
        'onfocus', 'onblur', 'onchange', 'onsubmit',
        'onkeydown', 'onkeyup', 'onkeypress',
        'oncontextmenu', 'onerror', 'onabort'
    ]

    try:
        # 使用 JavaScript 提取所有包含事件属性的元素
        script = """
        var results = [];
        var elements = document.querySelectorAll('*');
        var eventAttrs = ['onclick', 'ondblclick', 'onmousedown', 'onmouseup', 
            'onmouseover', 'onmouseout', 'onmousemove', 'onload', 'onunload', 
            'onresize', 'onscroll', 'onfocus', 'onblur', 'onchange', 'onsubmit',
            'onkeydown', 'onkeyup', 'onkeypress', 'oncontextmenu', 'onerror', 'onabort'];

        elements.forEach(function(el) {
            eventAttrs.forEach(function(attr) {
                var value = el.getAttribute(attr);
                if (value) {
                    results.push({
                        tag: el.tagName.toLowerCase(),
                        attr: attr,
                        value: value,
                        html: el.outerHTML
                    });
                }
            });
        });
        return results;
        """

        event_results = driver.execute_script(script)

        for result in event_results:
            attr_value = result['value']
            # 提取 URL
            urls = re.findall(r'https?://[^\s"\'<>]+', attr_value)
            for url in urls:
                if is_external_link(url, start_url):
                    tag_html = result['html']
                    external_links.append((url, tag_html))

            # 提取 open() 调用
            open_matches = re.findall(r'open\([\'"]?([^\)\'"]+)[\'"]?\)', attr_value)
            for match in open_matches:
                if match.startswith(('http://', 'https://')):
                    if is_external_link(match, start_url):
                        tag_html = result['html']
                        external_links.append((match, tag_html))

            # 提取 window.location 跳转
            location_matches = re.findall(r'location\.(?:href|replace) *= *[\'"]?([^\'";]+)[\'"]?', attr_value)
            for match in location_matches:
                if match.startswith(('http://', 'https://')):
                    if is_external_link(match, start_url):
                        tag_html = result['html']
                        external_links.append((match, tag_html))

    except Exception as e:
        logger.warning(f"  [Selenium] 提取事件属性 URL 失败: {e}")

    return external_links


def extract_dynamic_injections(driver):
    """
    提取动态注入的恶意代码
    document.write, innerHTML, insertAdjacentHTML 等
    """
    external_links = []

    try:
        # 检查页面中现有的通过 innerHTML 插入的链接
        script2 = """
        var results = [];
        var elements = document.querySelectorAll('*');
        elements.forEach(function(el) {
            if (el.innerHTML) {
                var urls = el.innerHTML.match(/https?:\\/\\/[^\\s"'<>]+/g);
                if (urls) {
                    urls.forEach(function(url) {
                        results.push({
                            type: 'innerHTML',
                            url: url,
                            tag: el.tagName.toLowerCase(),
                            html: el.outerHTML.substring(0, 300)
                        });
                    });
                }
            }
        });
        return results;
        """

        injection_results = driver.execute_script(script2)

        for result in injection_results:
            url = result['url']
            tag_html = result['html']
            external_links.append((url, tag_html))

    except Exception as e:
        logger.warning(f"  [Selenium] 提取动态注入失败: {e}")

    return external_links


def extract_location_redirects(driver, start_url):
    """
    提取 window.location / top.location 跳转
    """
    external_links = []

    try:
        # 获取当前页面 URL
        current_url = driver.current_url

        # 检查是否有 location 跳转
        script = """
        var results = [];

        // 检查 window.location.href
        if (window.location.href) {
            results.push({type: 'location.href', url: window.location.href});
        }

        // 检查 document.URL
        if (document.URL) {
            results.push({type: 'document.URL', url: document.URL});
        }

        return results;
        """

        location_results = driver.execute_script(script)

        for result in location_results:
            url = result['url']
            if url != start_url and url != current_url:
                if is_external_link(url, start_url):
                    external_links.append((url, f"[location] {result['type']} = {url}"))

    except Exception as e:
        logger.warning(f"  [Selenium] 提取 location 跳转失败: {e}")

    return external_links


# ==================== 静态解析（BeautifulSoup 增强版） ====================

def extract_all_external_links_static(soup, current_url, start_url):
    """
    静态解析外部链接（增强版）
    支持更多标签和属性
    """
    external_links = []

    # 标签映射：标签名 -> 属性名
    tag_attr_map = {
        'a': 'href',
        'link': 'href',
        'iframe': 'src',
        'frame': 'src',
        'img': 'src',
        'script': 'src',
        'embed': 'src',
        'object': ['src', 'data'],
        'meta': 'http-equiv',
        'form': 'action',
        'area': 'href',
        'base': 'href',
        'audio': 'src',
        'video': 'src',
        'source': 'src',
        'track': 'src',
        'input': 'src',  # input 图片按钮
    }

    for tag_name, attrs in tag_attr_map.items():
        if not isinstance(attrs, list):
            attrs = [attrs]

        for attr in attrs:
            for tag in soup.find_all(tag_name, **{attr: True}):
                value = tag.get(attr)
                full_url = urljoin(current_url, value)
                if is_external_link(full_url, start_url):
                    external_links.append((full_url, str(tag)))

    # 提取 style 属性中的背景图片
    for tag in soup.find_all(style=True):
        style = tag['style']
        urls = re.findall(r'url\([\'"]?([^\'"\)]+)[\'"]?\)', style)
        for url in urls:
            full_url = urljoin(current_url, url)
            if is_external_link(full_url, start_url):
                external_links.append((full_url, str(tag)))

    # 提取 meta refresh
    for tag in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
        content = tag.get('content', '')
        if 'url=' in content.lower():
            url_part = content.lower().split('url=')[-1]
            full_url = urljoin(current_url, url_part)
            if is_external_link(full_url, start_url):
                external_links.append((full_url, str(tag)))

    # 提取注释中的链接
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        urls = re.findall(r'https?://[^\s<>"\']+', comment)
        for url in urls:
            if is_external_link(url, start_url):
                comment_preview = f'<!--{comment[:100]}...-->' if len(comment) > 100 else f'<!--{comment}-->'
                external_links.append((url, comment_preview))

    # 提取内联脚本中的 URL
    for script in soup.find_all('script'):
        if script.string:
            script_text = script.string

            # 提取所有 URL
            urls = re.findall(r'https?://[^\s"\'>]+', script_text)
            for url in urls:
                if is_external_link(url, start_url):
                    tag_preview = f'<script>...{script_text[:100]}...</script>' if len(
                        script_text) > 100 else f'<script>{script_text}</script>'
                    external_links.append((url, tag_preview))

            # 提取 window.location / top.location
            location_matches = re.findall(r'location\.(?:href|replace) *= *[\'"]?([^\'";]+)[\'"]?', script_text)
            for match in location_matches:
                if match.startswith(('http://', 'https://')):
                    if is_external_link(match, start_url):
                        tag_preview = f'<script>...{script_text[:100]}...</script>' if len(
                            script_text) > 100 else f'<script>{script_text}</script>'
                        external_links.append((match, tag_preview))

            # 提取 open() 调用
            open_matches = re.findall(r'open\([\'"]?([^\)\'"]+)[\'"]?\)', script_text)
            for match in open_matches:
                if match.startswith(('http://', 'https://')):
                    if is_external_link(match, start_url):
                        tag_preview = f'<script>...{script_text[:100]}...</script>' if len(
                            script_text) > 100 else f'<script>{script_text}</script>'
                        external_links.append((match, tag_preview))

            # 提取 fetch / XMLHttpRequest
            fetch_matches = re.findall(r'fetch\([\'"]?([^\'"]+)[\'"]?\)', script_text)
            for match in fetch_matches:
                if match.startswith(('http://', 'https://')):
                    if is_external_link(match, start_url):
                        tag_preview = f'<script>...{script_text[:100]}...</script>' if len(
                            script_text) > 100 else f'<script>{script_text}</script>'
                        external_links.append((match, tag_preview))

            # 提取 document.write / innerHTML
            docwrite_matches = re.findall(r'(?:document\.write|innerHTML)\s*=\s*[\'"]?[^\'"]*?(https?://[^\s\'"]+)',
                                          script_text)
            for match in docwrite_matches:
                if is_external_link(match, start_url):
                    tag_preview = f'<script>...{script_text[:100]}...</script>' if len(
                        script_text) > 100 else f'<script>{script_text}</script>'
                    external_links.append((match, tag_preview))

    return external_links


# ==================== 主扫描函数 ====================

def scan_and_download_js(start_url):
    """主扫描函数"""
    domain = get_domain_from_url(start_url)
    base_dir = domain

    clean_directory(base_dir)

    logger.info(f"\n创建目录: {base_dir}/")
    logger.info(f"所有 JS 文件将保存到此目录下")

    visited = set()
    js_urls = []
    existing_hashes = {}
    existing_filenames = {}
    external_links_detail = []
    queue = deque([start_url])

    # 初始化 Selenium 驱动
    driver = None
    if USE_SELENIUM:
        try:
            driver = get_selenium_driver()
            logger.info("Selenium 驱动初始化成功")
        except Exception as e:
            logger.warning(f"Selenium 驱动初始化失败: {e}，将仅使用静态解析")
            driver = None

    try:
        while queue:
            url = queue.popleft()

            if url in visited:
                continue

            try:
                logger.info(f"正在扫描: {url}")

                # ========== 获取页面内容 ==========
                html = None
                static_links = []
                dynamic_links = []
                dynamic_js_urls = []

                # 方案1: 使用 Selenium 动态渲染
                if driver:
                    try:
                        html, dynamic_js_urls, dynamic_links = render_page_with_selenium(url, driver)
                    except Exception as e:
                        logger.warning(f"  Selenium 渲染失败: {e}")

                # 方案2: 使用 requests 静态获取
                if not html:
                    try:
                        resp = requests.get(url, timeout=10, headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        })
                        if 'text/html' in resp.headers.get('Content-Type', ''):
                            html = resp.text
                    except Exception as e:
                        logger.warning(f"  requests 请求失败: {e}")

                if not html:
                    visited.add(url)
                    continue

                visited.add(url)
                soup = BeautifulSoup(html, 'html.parser')

                # ========== 提取 JS 文件 ==========
                # 1. 静态 JS
                for script in soup.find_all('script', src=True):
                    src = script.get('src')
                    if src:
                        full_url = urljoin(url, src)
                        if full_url not in js_urls:
                            js_urls.append(full_url)

                # 2. 动态 JS（Selenium 获取）
                for js_url in dynamic_js_urls:
                    if js_url not in js_urls:
                        js_urls.append(js_url)

                # 3. 下载 JS 文件
                for js_url in js_urls:
                    if js_url not in visited:
                        logger.info(f"  下载 JS: {js_url}")
                        success, result, is_duplicate = download_js_file(
                            js_url, base_dir, existing_hashes, existing_filenames
                        )
                        if success:
                            if not is_duplicate:
                                logger.info(f"    下载成功: {result}")
                            else:
                                logger.info(f"    已跳过（重复内容）")
                        else:
                            logger.warning(f"    下载失败: {result}")

                # ========== 提取外部链接 ==========
                # 1. 静态解析
                static_links = extract_all_external_links_static(soup, url, start_url)
                for link_url, tag in static_links:
                    external_links_detail.append((link_url, tag))

                # 2. 动态链接（Selenium 获取）
                for link_url, tag in dynamic_links:
                    external_links_detail.append((link_url, tag))

                # ========== 提取内部链接，继续爬取 ==========
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)

                    if not is_external_link(full_url, start_url):
                        clean_url = urlunparse(urlparse(full_url)._replace(fragment=''))
                        if clean_url not in visited and clean_url not in queue:
                            queue.append(clean_url)

                # 从 Selenium 提取更多内部链接
                if driver:
                    try:
                        elements = driver.find_elements(By.TAG_NAME, 'a')
                        for elem in elements:
                            try:
                                href = elem.get_attribute('href')
                                if href:
                                    full_url = urljoin(url, href)
                                    if not is_external_link(full_url, start_url):
                                        clean_url = urlunparse(urlparse(full_url)._replace(fragment=''))
                                        if clean_url not in visited and clean_url not in queue:
                                            queue.append(clean_url)
                            except:
                                pass
                    except:
                        pass

                time.sleep(0.3)

            except Exception as e:
                logger.warning(f"  扫描页面失败: {e}")
                continue

    finally:
        # 关闭 Selenium 驱动
        if driver:
            try:
                driver.quit()
                logger.info("Selenium 驱动已关闭")
            except:
                pass

    return js_urls, visited, base_dir, external_links_detail


# ==================== 保存报告 ====================

def save_report(js_urls, external_links_detail, visited, base_dir, domain, target):
    """保存报告"""
    report_file = os.path.join(base_dir, f"{domain}.txt")

    # 去重
    link_info = {}
    for link_url, tag in external_links_detail:
        domain_key = get_domain_from_url(link_url)
        if domain_key not in link_info:
            link_info[domain_key] = set()
        link_info[domain_key].add(tag)

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("网站恶意 JS 与黑链扫描报告\n")
        f.write("=" * 70 + "\n")
        f.write(f"扫描目标: {target}\n")
        f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"扫描引擎: {'Selenium 动态渲染' if USE_SELENIUM else '静态解析'}\n")
        f.write("-" * 70 + "\n")
        f.write("📊 统计汇总\n")
        f.write("-" * 70 + "\n")
        f.write(f"  扫描页面数: {len(visited)}\n")
        f.write(f"  下载的 JS 文件数: {len(js_urls)}\n")
        f.write(f"  发现的外部链接数: {len(link_info)}\n")
        f.write("=" * 70 + "\n\n")

        # JS 文件列表
        f.write("=" * 70 + "\n")
        f.write("下载的 JS 文件列表\n")
        f.write("=" * 70 + "\n")
        if js_urls:
            for url in sorted(js_urls):
                f.write(f"{url}\n")
        else:
            f.write("无\n")

        # 外部链接列表
        f.write("\n" + "=" * 70 + "\n")
        f.write("外部链接列表（黑链/可疑外链排查）\n")
        f.write("=" * 70 + "\n\n")

        if link_info:
            for domain_key in sorted(link_info.keys()):
                f.write(f"外部链接: {domain_key}\n")
                for tag in sorted(link_info[domain_key]):
                    f.write(f"  标签: {tag}\n")
                f.write("-" * 50 + "\n")
        else:
            f.write("未发现外部链接\n")

    return report_file


# ==================== 主入口 ====================

if __name__ == "__main__":
    target = input("请输入网站 URL (如 https://www.example.com): ").strip()

    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    domain = get_domain_from_url(target)

    logger.info(f"\n开始全站扫描: {target}")
    logger.info("-" * 70)

    js_urls, pages, base_dir, external_links_detail = scan_and_download_js(target)

    report_file = save_report(js_urls, external_links_detail, pages, base_dir, domain, target)

    logger.info("\n" + "=" * 70)
    logger.info("扫描完成！")
    logger.info("=" * 70)
    logger.info(f"扫描页面数: {len(pages)}")
    logger.info(f"下载的 JS 文件数: {len(js_urls)}")
    logger.info(f"外部链接数: {len(set(url for url, _ in external_links_detail))}")
    logger.info(f"\n目录: {base_dir}/")
    logger.info(f"  ├── {domain}.txt")
    logger.info(f"  └── (JS 文件)")
    logger.info(f"\n报告文件: {report_file}")
    logger.info("=" * 70)