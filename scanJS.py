"""
Malicious JS and External Link Scanner
A modular, extensible web scanner for detecting malicious JavaScript and external links.
"""

import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, urlunparse
import time
from collections import deque
import os
import re
import shutil
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager
import logging
from typing import Optional, Tuple, List, Set, Dict, Any
from dataclasses import dataclass

# ==================== Logging Setup ====================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ==================== Configuration ====================

@dataclass
class ScannerConfig:
    """Configuration for the scanner."""
    use_selenium: bool = True
    selenium_driver_path: Optional[str] = None
    headless_mode: bool = True
    page_load_timeout: int = 10
    dynamic_wait_time: int = 3
    download_timeout: int = 5
    request_timeout: int = 5
    max_file_size: int = 0
    allow_mixed_content: bool = True
    extract_js_from_source: bool = True
    connection_check_timeout: int = 5
    download_js_extensions: tuple = ('.js', '.mjs', '.cjs')


# ==================== URL Pattern Detector ====================

class URLPatternDetector:
    """Detects and manages URL patterns to avoid duplicate scanning."""

    def __init__(self):
        self._patterns: Dict[str, List[str]] = {}
        self._scanned_patterns: Set[str] = set()
        self._pending_patterns: Set[str] = set()
        self._pattern_samples: Dict[str, str] = {}
        self._pending_urls: Set[str] = set()
        self.total_discovered: int = 0
        self.total_scanned: int = 0
        self.total_skipped: int = 0

    def get_pattern(self, url: str) -> Optional[str]:
        """Extract pattern from URL by analyzing path segments."""
        if not url.startswith(('http://', 'https://')):
            return None

        parsed = urlparse(url)
        pattern = self._process_path(parsed.path)
        pattern = self._process_query(parsed.query, pattern)
        pattern = re.sub(r'/{2,}', '/', pattern)
        return pattern if pattern else '/'

    def _process_path(self, path: str) -> str:
        segments = [seg for seg in path.split('/') if seg]
        processed = [self._analyze_segment(seg) for seg in segments]
        return '/' + '/'.join(processed) if processed else '/'

    def _analyze_segment(self, segment: str) -> str:
        if re.match(r'^\d+$', segment):
            return '{id}'
        if re.match(r'^[A-Za-z]+\d+$', segment):
            return '{id}'
        if re.match(r'^[\w-]+[_-]\d+$', segment):
            return '{id}'
        if re.match(r'^[\w-]+_\d+$', segment):
            return '{id}'
        if re.match(r'^[0-9a-fA-F]{32}$', segment) or re.match(r'^[0-9a-fA-F]{40}$', segment):
            return '{hash}'
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment.lower()):
            return '{uuid}'
        if re.match(r'^\d{4}-\d{2}-\d{2}$', segment) or re.match(r'^\d{8}$', segment):
            return '{date}'
        if len(segment) >= 16 and re.match(r'^[A-Za-z0-9]{16,}$', segment):
            return '{token}'
        if re.match(r'^v\d+(\.\d+)*$', segment) or re.match(r'^version\d+$', segment):
            return '{version}'
        if len(segment) == 2 and segment.isalpha() and segment.lower() in ['en', 'zh', 'fr', 'de', 'es', 'ja', 'ko']:
            return segment
        if segment.lower() in ['page', 'p', 'offset', 'limit']:
            return segment
        return segment

    def _process_query(self, query: str, pattern: str) -> str:
        if not query:
            return pattern
        params = []
        for param in query.split('&'):
            if '=' in param:
                name = param.split('=')[0]
                params.append(f'{name}={{value}}')
            else:
                params.append(param)
        return f"{pattern}?{'&'.join(params)}"

    def is_new_pattern(self, url: str) -> bool:
        pattern = self.get_pattern(url)
        if pattern is None:
            return False
        if pattern in self._scanned_patterns or pattern in self._pending_patterns:
            return False
        return True

    def register_pattern(self, url: str) -> bool:
        pattern = self.get_pattern(url)
        if pattern is None:
            return False
        if pattern not in self._patterns:
            self._patterns[pattern] = []
            self._pattern_samples[pattern] = url
        if url not in self._patterns[pattern]:
            self._patterns[pattern].append(url)
            self.total_discovered += 1
        if len(self._patterns[pattern]) == 1:
            self._pending_patterns.add(pattern)
            self._pending_urls.add(url)
            self.total_scanned += 1
            return True
        self.total_skipped += 1
        return False

    def should_scan(self, url: str) -> bool:
        pattern = self.get_pattern(url)
        if pattern is None:
            return False
        return pattern in self._pending_patterns and url in self._pending_urls

    def mark_scanned(self, url: str) -> None:
        pattern = self.get_pattern(url)
        if pattern and url in self._pending_urls:
            self._pending_urls.remove(url)

    def mark_pattern_scanned(self, pattern: str) -> None:
        if pattern and pattern not in self._scanned_patterns:
            self._scanned_patterns.add(pattern)
            if pattern in self._pending_patterns:
                self._pending_patterns.remove(pattern)

    def is_pattern_scanned(self, pattern: str) -> bool:
        return pattern in self._scanned_patterns

    def get_stats(self) -> Dict[str, int]:
        return {
            'total_discovered': self.total_discovered,
            'total_scanned': self.total_scanned,
            'total_skipped': self.total_skipped,
            'total_patterns': len(self._patterns),
            'scanned_patterns': len(self._scanned_patterns)
        }


# ==================== JavaScript Detector ====================

class JavaScriptDetector:
    """Universal JavaScript detector that works for any website."""

    def __init__(self, config: ScannerConfig):
        self.config = config

    def is_js_file(self, url: str, content_type: Optional[str] = None,
                   content: Optional[bytes] = None, filename: Optional[str] = None) -> bool:
        """Determine if a file is JavaScript using multiple methods."""
        # Method 1: URL extension
        if self._check_js_extension(url):
            return True

        # Method 2: Filename extension
        if filename and self._check_js_extension(filename):
            return True

        # Method 3: Content-Type
        if content_type and self._check_content_type(content_type):
            return True

        # Method 4: Content analysis
        if content and self._check_content_patterns(content):
            return True

        # Method 5: LENIENT - URL contains .js
        if '.js' in url.lower():
            return True

        return False

    def _check_js_extension(self, path: str) -> bool:
        """Check if the path has a JavaScript extension."""
        if not path:
            return False

        clean_path = path.split('?')[0].split('#')[0]

        for ext in self.config.download_js_extensions:
            if clean_path.lower().endswith(ext):
                return True

        return False

    def _check_content_type(self, content_type: str) -> bool:
        """Check if Content-Type indicates JavaScript."""
        if not content_type:
            return False

        ct = content_type.lower()
        js_types = ['javascript', 'ecmascript', 'x-javascript', 'x-ecmascript', 'application/json']
        return any(js_type in ct for js_type in js_types)

    def _check_content_patterns(self, content: bytes) -> bool:
        """Check if content contains JavaScript syntax patterns."""
        if not content or len(content) < 10:
            return False

        try:
            sample = content[:4096].decode('utf-8', errors='ignore')
            patterns = [
                r'function\s*\(', r'var\s+\w+\s*=', r'const\s+\w+\s*=', r'let\s+\w+\s*=',
                r'console\.', r'document\.', r'window\.', r'\.prototype\.',
                r'return\s+', r'new\s+\w+\s*\(', r'this\.', r'typeof\s+',
                r'\.addEventListener\s*\(', r'\.getElementById\s*\(', r'\.querySelector\s*\(',
                r'\.innerHTML\s*=', r'\.appendChild\s*\(', r'JSON\.parse\s*\(',
                r'JSON\.stringify\s*\(', r'\.then\s*\(', r'\.catch\s*\(',
                r'async\s+function', r'await\s+', r'export\s+', r'import\s+',
                r'require\s*\(', r'module\.exports',
            ]
            match_count = 0
            for pattern in patterns:
                if re.search(pattern, sample, re.IGNORECASE):
                    match_count += 1
                    if match_count >= 2:
                        return True
        except:
            pass
        return False


# ==================== Network Checker ====================

class NetworkChecker:
    """Check network connectivity before scanning."""

    @staticmethod
    def check_connectivity(url: str, timeout: int = 5) -> Tuple[bool, str]:
        try:
            resp = requests.head(url, timeout=timeout, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            if resp.status_code < 400:
                return True, f"Connected (HTTP {resp.status_code})"

            resp = requests.get(url, timeout=timeout, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }, stream=True)
            if resp.status_code < 400:
                return True, f"Connected (HTTP {resp.status_code})"
            else:
                return False, f"HTTP {resp.status_code} - {resp.reason}"
        except requests.ConnectionError:
            return False, "Connection refused - domain may not exist or DNS resolution failed"
        except requests.Timeout:
            return False, f"Connection timeout after {timeout}s"
        except requests.SSLError:
            return False, "SSL certificate error"
        except Exception as e:
            return False, f"Connection failed: {str(e)[:100]}"


# ==================== Link Analyzer ====================

class LinkAnalyzer:
    """Analyzes links to determine if they are internal or external."""

    @staticmethod
    def get_domain(url: str) -> str:
        return urlparse(url).netloc

    @staticmethod
    def get_base_domain(domain: str) -> str:
        if not domain:
            return domain
        parts = domain.split('.')
        if len(parts) >= 3:
            sld_patterns = ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'ne']
            if parts[-2].lower() in sld_patterns and len(parts[-1]) <= 3:
                return '.'.join(parts[-3:])
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain

    @staticmethod
    def normalize_url(url: str) -> str:
        parsed = urlparse(url)
        normalized = urlunparse(parsed._replace(fragment=''))
        return normalized.rstrip('/')

    @staticmethod
    def is_external(link_url: str, start_url: str) -> bool:
        if not link_url:
            return False
        link_domain = LinkAnalyzer.get_domain(link_url)
        start_domain = LinkAnalyzer.get_domain(start_url)
        if not link_domain:
            return False
        if link_domain == start_domain:
            return False
        link_base = LinkAnalyzer.get_base_domain(link_domain)
        start_base = LinkAnalyzer.get_base_domain(start_domain)
        if link_base == start_base:
            return False
        return True


# ==================== File Handler ====================

class FileHandler:
    """Handles file downloads with filename-based deduplication only."""

    def __init__(self, save_dir: str, config: ScannerConfig):
        self.save_dir = save_dir
        self.config = config
        self._filename_map: Dict[str, bool] = {}  # filename -> exists
        self.downloaded_files: List[str] = []
        self.js_detector = JavaScriptDetector(config)
        self.download_attempts: Set[str] = set()

    def download_js(self, url: str) -> Tuple[bool, str, bool]:
        """
        Download a JavaScript file.
        Deduplication: ONLY by filename.
        If filename differs, download regardless of content.
        """
        if url in self.download_attempts:
            return True, "Already attempted", True
        self.download_attempts.add(url)

        if not self.js_detector.is_js_file(url):
            return True, "Skipped (not JS)", True

        filename = self._extract_filename(url)
        success, content, content_type = self._fetch_file(url)

        if not success:
            if '.js' in url.lower():
                return True, "Download failed (skipped)", True
            return False, "Download failed", False

        if not self.js_detector.is_js_file(url, content_type, content, filename):
            if '.js' in url.lower():
                pass  # Force save if URL has .js
            else:
                return True, "Skipped (not JS content)", True

        # ONLY filename-based deduplication (NO MD5 check)
        if filename in self._filename_map:
            return True, filename, True

        # Save new file (different filename, so download even if MD5 same)
        filepath = self._get_unique_filename(filename)
        with open(filepath, 'wb') as f:
            f.write(content)

        self._filename_map[filename] = True
        self.downloaded_files.append(url)

        logger.info(f"    Downloaded: {os.path.basename(filepath)}")
        return True, os.path.basename(filepath), False

    def _extract_filename(self, url: str) -> str:
        """Extract filename from URL, properly handling query and fragments."""
        # Remove query parameters and fragments
        url_clean = url.split('?')[0].split('#')[0]
        parsed = urlparse(url_clean)
        path = parsed.path

        if not path or path.endswith('/'):
            return 'index.js'

        filename = os.path.basename(path)

        if not any(filename.endswith(ext) for ext in self.config.download_js_extensions):
            filename += '.js'

        return filename

    def _fetch_file(self, url: str) -> Tuple[bool, bytes, Optional[str]]:
        """Fetch file content with timeout."""
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            resp = requests.get(url, timeout=self.config.download_timeout, headers=headers, stream=True)

            if resp.status_code != 200:
                return False, b'', None

            content_type = resp.headers.get('Content-Type', '').lower()

            content = b''
            for chunk in resp.iter_content(chunk_size=8192):
                content += chunk
                if self.config.max_file_size > 0 and len(content) > self.config.max_file_size:
                    return False, b'', content_type

            return True, content, content_type
        except requests.Timeout:
            return False, b'', None
        except requests.ConnectionError:
            return False, b'', None
        except Exception:
            return False, b'', None

    def _get_unique_filename(self, filename: str) -> str:
        """Get a unique filename by adding counter if needed."""
        filepath = os.path.join(self.save_dir, filename)
        counter = 1

        while os.path.exists(filepath):
            base, ext = os.path.splitext(filename)
            filepath = os.path.join(self.save_dir, f"{base}_{counter}{ext}")
            counter += 1

        return filepath


# ==================== Page Fetcher ====================

class PageFetcher:
    """Fetches web pages using Selenium or Requests."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self._driver = None

    def fetch(self, url: str) -> Tuple[Optional[str], List[Tuple[str, str]], List[str]]:
        html = None
        external_links = []
        js_urls = []

        if self.config.use_selenium:
            try:
                html, js_urls, external_links = self._fetch_with_selenium(url)
            except Exception as e:
                logger.warning(f"Selenium rendering failed: {e}")

        if not html:
            try:
                html = self._fetch_with_requests(url)
            except Exception as e:
                logger.warning(f"Requests fetch failed: {e}")

        return html, external_links, js_urls

    def _fetch_with_selenium(self, url: str) -> Tuple[str, List[str], List[Tuple[str, str]]]:
        driver = self._get_driver()
        try:
            driver.get(url)
            WebDriverWait(driver, self.config.page_load_timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, 'body'))
            )
            time.sleep(self.config.dynamic_wait_time)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(1)
            driver.execute_script("window.scrollTo(0, 0);")
            time.sleep(0.5)
            html = driver.page_source
            external_links = self._extract_external_links_from_driver(driver, url)
            js_urls = self._extract_js_urls_from_driver(driver, url)
            return html, js_urls, external_links
        except UnexpectedAlertPresentException:
            logger.warning("Unexpected alert detected, attempting to dismiss...")
            try:
                alert = driver.switch_to.alert
                alert.accept()
                time.sleep(1)
                html = driver.page_source
                external_links = self._extract_external_links_from_driver(driver, url)
                js_urls = self._extract_js_urls_from_driver(driver, url)
                return html, js_urls, external_links
            except:
                return '', [], []
        except TimeoutException:
            logger.warning(f"Page load timeout: {url}")
            return '', [], []

    def _fetch_with_requests(self, url: str) -> Optional[str]:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            resp = requests.get(url, timeout=self.config.request_timeout, headers=headers)
            if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                return resp.text
            return None
        except Exception:
            return None

    def _get_driver(self):
        if self._driver is None:
            self._driver = self._create_driver()
        return self._driver

    def _create_driver(self):
        options = Options()
        if self.config.headless_mode:
            options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-blink-features=AutomationControlled')
        if self.config.allow_mixed_content:
            options.add_argument('--allow-insecure-localhost')
            options.add_argument('--disable-web-security')
            options.add_argument('--allow-running-insecure-content')
        options.add_experimental_option('excludeSwitches', ['enable-automation'])
        options.add_experimental_option('useAutomationExtension', False)
        prefs = {
            'profile.default_content_setting_values': {
                'images': 2, 'stylesheets': 2, 'mixed_script': 1
            },
            'profile.block_third_party_cookies': False
        }
        options.add_experimental_option('prefs', prefs)
        if self.config.selenium_driver_path:
            service = Service(self.config.selenium_driver_path)
            driver = webdriver.Chrome(service=service, options=options)
        else:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        driver.set_page_load_timeout(self.config.page_load_timeout)
        return driver

    def _extract_external_links_from_driver(self, driver, start_url: str) -> List[Tuple[str, str]]:
        external_links = []
        tag_attr_map = {'a': 'href', 'link': 'href', 'iframe': 'src', 'img': 'src', 'script': 'src'}
        for tag, attr in tag_attr_map.items():
            for elem in driver.find_elements(By.TAG_NAME, tag):
                try:
                    value = elem.get_attribute(attr)
                    if value and LinkAnalyzer.is_external(value, start_url):
                        external_links.append((value, tag))
                except:
                    pass
        return external_links

    def _extract_js_urls_from_driver(self, driver, start_url: str) -> List[str]:
        js_urls = set()
        # From script tags
        for elem in driver.find_elements(By.TAG_NAME, 'script'):
            try:
                src = elem.get_attribute('src')
                if src:
                    js_urls.add(urljoin(start_url, src))
            except:
                pass
        # From page source
        if self.config.extract_js_from_source:
            try:
                js_pattern = r'https?://[^\s"\'<>]+\.(?:js|mjs|cjs)[^\s"\'<>]*'
                for url in re.findall(js_pattern, driver.page_source):
                    js_urls.add(url)
            except:
                pass
        return list(js_urls)

    def close(self):
        if self._driver:
            try:
                self._driver.quit()
            except:
                pass


# ==================== Page Parser ====================

class PageParser:
    """Parses HTML pages to extract links and resources."""

    @staticmethod
    def parse(html: str, current_url: str, start_url: str) -> Dict[str, Any]:
        soup = BeautifulSoup(html, 'html.parser')
        return {
            'soup': soup,
            'external_links': PageParser._extract_external_links(soup, current_url, start_url),
            'internal_links': PageParser._extract_internal_links(soup, current_url, start_url),
            'js_urls': PageParser._extract_js_urls(soup, current_url)
        }

    @staticmethod
    def _extract_external_links(soup, current_url: str, start_url: str) -> List[Tuple[str, str]]:
        external_links = []
        tag_attr_map = {
            'a': 'href', 'link': 'href', 'iframe': 'src',
            'img': 'src', 'script': 'src', 'embed': 'src',
            'object': ['src', 'data'], 'form': 'action',
            'area': 'href', 'base': 'href', 'audio': 'src',
            'video': 'src', 'source': 'src', 'track': 'src', 'input': 'src'
        }
        for tag_name, attrs in tag_attr_map.items():
            if not isinstance(attrs, list):
                attrs = [attrs]
            for attr in attrs:
                for tag in soup.find_all(tag_name, **{attr: True}):
                    value = tag.get(attr)
                    full_url = urljoin(current_url, value)
                    if LinkAnalyzer.is_external(full_url, start_url):
                        external_links.append((full_url, tag_name))

        # Style attribute
        for tag in soup.find_all(style=True):
            urls = re.findall(r'url\([\'"]?([^\'"\)]+)[\'"]?\)', tag['style'])
            for url in urls:
                full_url = urljoin(current_url, url)
                if LinkAnalyzer.is_external(full_url, start_url):
                    external_links.append((full_url, 'style'))

        # Meta refresh
        for tag in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
            content = tag.get('content', '')
            if 'url=' in content.lower():
                url_part = content.lower().split('url=')[-1]
                full_url = urljoin(current_url, url_part)
                if LinkAnalyzer.is_external(full_url, start_url):
                    external_links.append((full_url, 'meta_refresh'))

        # Comments
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            urls = re.findall(r'https?://[^\s<>"\']+', comment)
            for url in urls:
                if LinkAnalyzer.is_external(url, start_url):
                    external_links.append((url, 'comment'))

        # Script content
        for script in soup.find_all('script'):
            if script.string:
                urls = re.findall(r'https?://[^\s"\'>]+', script.string)
                for url in urls:
                    if LinkAnalyzer.is_external(url, start_url):
                        external_links.append((url, 'script_url'))
        return external_links

    @staticmethod
    def _extract_internal_links(soup, current_url: str, start_url: str) -> List[str]:
        internal_links = []
        start_domain = LinkAnalyzer.get_domain(start_url)
        start_base = LinkAnalyzer.get_base_domain(start_domain)
        seen = set()
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc == '':
                full_url = urljoin(current_url, href)
                parsed = urlparse(full_url)
                clean_url = LinkAnalyzer.normalize_url(full_url)
                if clean_url.startswith(('http://', 'https://')):
                    if clean_url not in seen:
                        seen.add(clean_url)
                        internal_links.append(clean_url)
            elif parsed.netloc == start_domain:
                clean_url = LinkAnalyzer.normalize_url(full_url)
                if clean_url not in seen:
                    seen.add(clean_url)
                    internal_links.append(clean_url)
            else:
                link_base = LinkAnalyzer.get_base_domain(parsed.netloc)
                if link_base == start_base:
                    clean_url = LinkAnalyzer.normalize_url(full_url)
                    if clean_url not in seen:
                        seen.add(clean_url)
                        internal_links.append(clean_url)
        return internal_links

    @staticmethod
    def _extract_js_urls(soup, current_url: str) -> List[str]:
        js_urls = set()
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                js_urls.add(urljoin(current_url, src))
        return list(js_urls)


# ==================== Scanner ====================

class Scanner:
    """Main scanner orchestrator."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.pattern_detector = URLPatternDetector()
        self.page_fetcher = PageFetcher(config)
        self.visited: Set[str] = set()
        self.js_urls: List[str] = []
        self.external_links: List[Tuple[str, str]] = []
        self.scanned_urls: List[str] = []
        self.file_handler: Optional[FileHandler] = None
        self.queue_history: Set[str] = set()

    def check_connection(self, start_url: str) -> Tuple[bool, str]:
        logger.info(f"Checking connectivity to: {start_url}")
        is_reachable, message = NetworkChecker.check_connectivity(
            start_url, self.config.connection_check_timeout
        )
        if is_reachable:
            logger.info(f"  Connection successful: {message}")
        else:
            logger.error(f"  Connection failed: {message}")
        return is_reachable, message

    def scan(self, start_url: str) -> Optional[Dict[str, Any]]:
        is_reachable, message = self.check_connection(start_url)
        if not is_reachable:
            logger.error("\n" + "=" * 70)
            logger.error("SCAN ABORTED - CONNECTION FAILED")
            logger.error("=" * 70)
            logger.error(f"Target: {start_url}")
            logger.error(f"Reason: {message}")
            logger.error("=" * 70)
            logger.error("No directory or files were created.")
            return None

        domain = LinkAnalyzer.get_domain(start_url)
        save_dir = domain
        if os.path.exists(save_dir):
            logger.info(f"Cleaning old directory: {save_dir}/")
            shutil.rmtree(save_dir)
        os.makedirs(save_dir, exist_ok=True)
        self.file_handler = FileHandler(save_dir, self.config)

        logger.info(f"\nStarting scan: {start_url}")
        logger.info(f"Directory: {save_dir}/")
        logger.info("Pattern deduplication: Enabled")

        queue = deque([start_url])
        self.queue_history.add(start_url)
        self.pattern_detector.register_pattern(start_url)

        try:
            while queue:
                url = queue.popleft()
                if url in self.visited:
                    continue
                if not url.startswith(('http://', 'https://')):
                    self.visited.add(url)
                    continue
                pattern = self.pattern_detector.get_pattern(url)
                if self.pattern_detector.is_pattern_scanned(pattern):
                    self.visited.add(url)
                    continue
                if not self.pattern_detector.should_scan(url):
                    self.visited.add(url)
                    continue
                self._scan_page(url, queue, start_url)
        finally:
            self.page_fetcher.close()

        stats = self.pattern_detector.get_stats()
        report_path = self._generate_report(start_url, stats)
        return {
            'stats': stats,
            'scanned_urls': self.scanned_urls,
            'js_files': self.js_urls,
            'external_links': self.external_links,
            'report_path': report_path
        }

    def _scan_page(self, url: str, queue: deque, start_url: str) -> None:
        try:
            logger.info(f"Scanning: {url}")
            self.scanned_urls.append(url)
            html, dynamic_links, dynamic_js = self.page_fetcher.fetch(url)
            if not html:
                self.visited.add(url)
                return
            self.visited.add(url)
            parsed = PageParser.parse(html, url, start_url)
            pattern = self.pattern_detector.get_pattern(url)
            self.pattern_detector.mark_scanned(url)
            self.pattern_detector.mark_pattern_scanned(pattern)

            # Collect all JS URLs
            all_js_urls = set(parsed['js_urls'] + dynamic_js)
            # Extract from page source
            js_pattern = r'https?://[^\s"\'<>]+\.(?:js|mjs|cjs)[^\s"\'<>]*'
            for js_url in re.findall(js_pattern, html):
                all_js_urls.add(js_url)

            # Download JS files
            for js_url in all_js_urls:
                if js_url not in self.js_urls:
                    logger.info(f"  Downloading JS: {js_url[:100]}...")
                    success, result, is_duplicate = self.file_handler.download_js(js_url)
                    if success and not is_duplicate:
                        self.js_urls.append(js_url)
                    elif success and is_duplicate:
                        logger.info(f"    {result}")
                    else:
                        logger.warning(f"    Download failed: {result}")

            # Record external links
            self.external_links.extend(parsed['external_links'] + dynamic_links)

            # Add internal links to queue
            start_base = LinkAnalyzer.get_base_domain(LinkAnalyzer.get_domain(start_url))
            for link in parsed['internal_links']:
                if link not in self.visited and link not in self.queue_history:
                    link_domain = LinkAnalyzer.get_domain(link)
                    link_base = LinkAnalyzer.get_base_domain(link_domain) if link_domain else start_base
                    if link_base == start_base:
                        if self.pattern_detector.is_new_pattern(link):
                            if self.pattern_detector.register_pattern(link):
                                queue.append(link)
                                self.queue_history.add(link)
                                logger.info(f"  Added to queue: {link}")
            time.sleep(0.3)
        except Exception as e:
            logger.warning(f"  Scan failed: {e}")
            self.visited.add(url)

    def _generate_report(self, start_url: str, stats: Dict[str, int]) -> str:
        domain = LinkAnalyzer.get_domain(start_url)
        report_path = os.path.join(domain, f"{domain}.txt")
        start_base = LinkAnalyzer.get_base_domain(domain)
        external_set = set()
        for link_url, _ in self.external_links:
            link_domain = LinkAnalyzer.get_domain(link_url)
            if link_domain and LinkAnalyzer.get_base_domain(link_domain) != start_base:
                external_set.add(link_url)

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("MALICIOUS JS AND EXTERNAL LINK SCAN REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Target URL: {start_url}\n")
            f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Engine: {'Selenium' if self.config.use_selenium else 'Static'}\n")
            f.write(f"Pattern Deduplication: Enabled\n")
            f.write("-" * 70 + "\n")
            f.write("SCAN STATISTICS\n")
            f.write("-" * 70 + "\n")
            f.write(f"  Total URLs discovered: {stats['total_discovered']}\n")
            f.write(f"  URLs actually scanned: {stats['total_scanned']}\n")
            f.write(f"  URLs skipped (duplicate patterns): {stats['total_skipped']}\n")
            f.write(f"  Unique patterns found: {stats['total_patterns']}\n")
            f.write(f"  JS Files Downloaded: {len(self.js_urls)}\n")
            f.write(f"  External Links Found: {len(external_set)}\n")
            f.write("=" * 70 + "\n\n")

            f.write("=" * 70 + "\n")
            f.write("URLS ACTUALLY SCANNED\n")
            f.write("=" * 70 + "\n")
            if self.scanned_urls:
                for i, url in enumerate(self.scanned_urls, 1):
                    f.write(f"{i}. {url}\n")
            else:
                f.write("None\n")
            f.write("\n")

            f.write("=" * 70 + "\n")
            f.write("DOWNLOADED JS FILES\n")
            f.write("=" * 70 + "\n")
            if self.js_urls:
                for url in sorted(set(self.js_urls)):
                    f.write(f"{url}\n")
            else:
                f.write("None\n")
            f.write("\n")

            f.write("=" * 70 + "\n")
            f.write("EXTERNAL LINKS\n")
            f.write("=" * 70 + "\n\n")
            if external_set:
                for url in sorted(external_set):
                    f.write(f"{url}\n")
            else:
                f.write("No external links found\n")

        return report_path


# ==================== Main Entry ====================

def main():
    target = input("Enter website URL (e.g., https://www.example.com): ").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    config = ScannerConfig()
    scanner = Scanner(config)
    result = scanner.scan(target)

    if result is None:
        return

    stats = result['stats']
    logger.info("\n" + "=" * 70)
    logger.info("SCAN COMPLETED SUCCESSFULLY")
    logger.info("=" * 70)
    logger.info(f"Total URLs discovered: {stats['total_discovered']}")
    logger.info(f"URLs actually scanned: {stats['total_scanned']}")
    logger.info(f"URLs skipped (duplicate patterns): {stats['total_skipped']}")
    logger.info(f"JS Files Downloaded: {len(result['js_files'])}")

    domain = LinkAnalyzer.get_domain(target)
    start_base = LinkAnalyzer.get_base_domain(domain)
    external_count = sum(1 for url, _ in result['external_links']
                        if LinkAnalyzer.get_domain(url) and
                        LinkAnalyzer.get_base_domain(LinkAnalyzer.get_domain(url)) != start_base)

    logger.info(f"External Links: {external_count}")
    logger.info(f"\nDirectory: {LinkAnalyzer.get_domain(target)}/")
    logger.info(f"  Report: {result['report_path']}")
    logger.info(f"  JS Files: (in same directory)")
    logger.info(f"\nReport saved to: {result['report_path']}")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()