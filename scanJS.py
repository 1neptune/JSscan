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


def get_domain_from_url(url):
    """从 URL 中提取域名"""
    parsed = urlparse(url)
    return parsed.netloc


def get_main_domain(domain):
    """提取主域名（如 1295.marcopolo.com.cn -> marcopolo.com.cn）"""
    parts = domain.split('.')
    if len(parts) >= 2:
        # 处理 co.uk 等特殊情况（最后两级是 co.uk）
        if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net']:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return domain


def is_external_link(link_url, start_url):
    """
    判断是否为外部链接
    排除：目标域名本身 和 所有子域名
    例如：目标为 1295.marcopolo.com.cn，则 *.marcopolo.com.cn 都算内部
    """
    link_parsed = urlparse(link_url)
    start_parsed = urlparse(start_url)

    if not link_parsed.netloc:
        return False

    link_domain = link_parsed.netloc
    start_domain = start_parsed.netloc

    # 如果域名完全相同 → 内部
    if link_domain == start_domain:
        return False

    # 获取目标域名的主域名
    main_domain = get_main_domain(start_domain)

    # 检查 link_domain 是否以主域名结尾
    # 如：static.marcopolo.com.cn 以 marcopolo.com.cn 结尾 → 内部
    if link_domain.endswith('.' + main_domain) or link_domain == main_domain:
        return False

    return True


def get_file_hash(content):
    """计算文件内容的 MD5，用于内容级别去重"""
    return hashlib.md5(content).hexdigest()


def clean_directory(base_dir):
    """清空目录，重新开始"""
    if os.path.exists(base_dir):
        print(f"清空旧目录: {base_dir}/")
        shutil.rmtree(base_dir)
    os.makedirs(base_dir, exist_ok=True)


def download_js_file(url, save_dir, existing_hashes, existing_filenames):
    """
    下载 JS 文件到指定目录
    处理逻辑：
    1. 先检查文件名是否已存在
    2. 再检查 MD5 是否已存在
    3. 文件名相同 + MD5 相同 → 跳过
    4. 文件名相同 + MD5 不同 → 添加时间戳保存
    5. 文件名不同 + MD5 相同 → 正常保存（保留两份）
    6. 文件名不同 + MD5 不同 → 正常保存
    返回: (是否成功, 文件名, 是否重复)
    """
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

            # 情况1：文件名相同 + MD5 相同 → 跳过
            if filename in existing_filenames:
                existing_hash = existing_filenames[filename]
                if existing_hash == file_hash:
                    print(f"    内容重复，已跳过（与 {filename} 相同）")
                    return True, filename, True

            # 情况2：文件名相同 + MD5 不同 → 添加时间戳
            if filename in existing_filenames:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
                base_name, ext = os.path.splitext(filename)
                final_filename = f"{base_name}_{timestamp}{ext}"
                print(f"    文件名冲突，MD5 不同，使用时间戳命名: {final_filename}")
            else:
                final_filename = filename

            # 处理文件名冲突（确保保存时不会覆盖）
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

            # 记录：文件名 -> MD5（用于文件名冲突检测）
            if filename not in existing_filenames:
                existing_filenames[filename] = file_hash
            else:
                existing_filenames[filename] = file_hash

            # 记录：MD5 -> 文件名
            if file_hash not in existing_hashes:
                existing_hashes[file_hash] = final_filename

            return True, final_filename, False
        else:
            return False, f"HTTP {resp.status_code}", False

    except Exception as e:
        return False, str(e), False


def extract_domain(url):
    """从 URL 中提取域名（不含协议）"""
    parsed = urlparse(url)
    return parsed.netloc


def extract_all_external_links(soup, current_url, start_url, external_links_detail):
    """
    从页面中提取所有可能的外部链接，并记录完整标签
    external_links_detail: 列表，每个元素为 (外部链接域名, 完整标签代码)
    """

    # 1. 提取 <a> 标签
    for tag in soup.find_all('a', href=True):
        full_url = urljoin(current_url, tag['href'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))

    # 2. 提取 <link> 标签
    for tag in soup.find_all('link', href=True):
        full_url = urljoin(current_url, tag['href'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))

    # 3. 提取 <iframe> 和 <frame> 标签
    for tag in soup.find_all(['iframe', 'frame'], src=True):
        full_url = urljoin(current_url, tag['src'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))

    # 4. 提取 <img> 标签
    for tag in soup.find_all('img', src=True):
        full_url = urljoin(current_url, tag['src'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))

    # 5. 提取 <script> 标签的 src 属性
    for tag in soup.find_all('script', src=True):
        full_url = urljoin(current_url, tag['src'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))

    # 6. 提取 <embed> 和 <object> 标签
    for tag in soup.find_all(['embed', 'object'], src=True):
        full_url = urljoin(current_url, tag['src'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))

    for tag in soup.find_all('object', data=True):
        full_url = urljoin(current_url, tag['data'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))

    # 7. 提取 <meta> refresh 跳转
    for tag in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
        content = tag.get('content', '')
        if 'url=' in content.lower():
            url_part = content.lower().split('url=')[-1]
            full_url = urljoin(current_url, url_part)
            if is_external_link(full_url, start_url):
                domain = extract_domain(full_url)
                external_links_detail.append((domain, str(tag)))

    # 8. 检查内联脚本中动态创建的链接
    for script in soup.find_all('script'):
        if script.string:
            script_text = script.string
            urls = re.findall(r'https?://[^\s"\'>]+', script_text)
            for url in urls:
                if is_external_link(url, start_url):
                    domain = extract_domain(url)
                    tag_preview = f'<script>...{script_text[:100]}...</script>' if len(
                        script_text) > 100 else f'<script>{script_text}</script>'
                    external_links_detail.append((domain, tag_preview))

    # 9. 检查 style 属性或标签中的背景图片
    for tag in soup.find_all(style=True):
        style = tag['style']
        urls = re.findall(r'url\([\'"]?([^\'"\)]+)[\'"]?\)', style)
        for url in urls:
            full_url = urljoin(current_url, url)
            if is_external_link(full_url, start_url):
                domain = extract_domain(full_url)
                external_links_detail.append((domain, str(tag)))

    # 10. 检查注释中的链接
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        urls = re.findall(r'https?://[^\s<>"\']+', comment)
        for url in urls:
            if is_external_link(url, start_url):
                domain = extract_domain(url)
                comment_preview = f'<!--{comment[:100]}...-->' if len(comment) > 100 else f'<!--{comment}-->'
                external_links_detail.append((domain, comment_preview))

    # 11. 提取 <form> 标签的 action 属性
    for tag in soup.find_all('form', action=True):
        full_url = urljoin(current_url, tag['action'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))

    # 12. 提取 <area> 标签
    for tag in soup.find_all('area', href=True):
        full_url = urljoin(current_url, tag['href'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))

    # 13. 提取 <base> 标签
    for tag in soup.find_all('base', href=True):
        full_url = urljoin(current_url, tag['href'])
        if is_external_link(full_url, start_url):
            domain = extract_domain(full_url)
            external_links_detail.append((domain, str(tag)))


def scan_and_download_js(start_url):
    """
    自动爬取全站页面，收集并下载所有 JS 文件，同时记录外部链接
    """
    domain = get_domain_from_url(start_url)
    base_dir = domain

    clean_directory(base_dir)

    print(f"\n创建目录: {base_dir}/")
    print(f"所有 JS 文件将保存到此目录下\n")

    visited = set()
    js_urls = []  # 存储完整的 JS URL
    existing_hashes = {}  # MD5 -> 文件名
    existing_filenames = {}  # 文件名 -> MD5
    external_links_detail = []  # 存储 (外部链接域名, 完整标签)
    queue = deque([start_url])

    while queue:
        url = queue.popleft()

        if url in visited:
            continue

        try:
            print(f"正在扫描: {url}")

            resp = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

            if 'text/html' not in resp.headers.get('Content-Type', ''):
                visited.add(url)
                continue

            visited.add(url)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # 1. 提取所有 script 标签并下载 JS 文件
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    full_url = urljoin(url, src)
                    print(f"  找到 JS: {full_url}")

                    print(f"    正在下载...")
                    success, result, is_duplicate = download_js_file(
                        full_url, base_dir, existing_hashes, existing_filenames
                    )

                    if success:
                        if not is_duplicate:
                            js_urls.append(full_url)
                            print(f"    下载成功: {result}")
                        else:
                            print(f"    已跳过（重复内容）")
                    else:
                        print(f"    下载失败: {result}")

            # 2. 提取所有外部链接
            extract_all_external_links(soup, url, start_url, external_links_detail)

            # 3. 提取内部链接，继续爬取
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)

                # 只保留内部链接（同域名或子域名）继续爬取
                if not is_external_link(full_url, start_url):
                    clean_url = urlunparse(urlparse(full_url)._replace(fragment=''))
                    if clean_url not in visited and clean_url not in queue:
                        queue.append(clean_url)

            time.sleep(0.5)

        except Exception as e:
            print(f"  错误: {e}")
            continue

    return js_urls, visited, base_dir, external_links_detail


def save_report(js_urls, external_links_detail, visited, base_dir, domain, target):
    """保存报告文件"""
    report_file = os.path.join(base_dir, f"{domain}.txt")

    # 去重：外部链接域名 -> 标签列表
    link_info = {}
    for link_domain, tag in external_links_detail:
        if link_domain not in link_info:
            link_info[link_domain] = set()
        link_info[link_domain].add(tag)

    with open(report_file, 'w', encoding='utf-8') as f:
        # 统计汇总
        f.write("=" * 70 + "\n")
        f.write("扫描统计汇总\n")
        f.write("=" * 70 + "\n")
        f.write(f"扫描目标: {target}\n")
        f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"扫描页面数: {len(visited)}\n")
        f.write(f"下载的 JS 文件数: {len(js_urls)}\n")
        f.write(f"外部链接数: {len(link_info)}\n")
        f.write("=" * 70 + "\n\n")

        # 下载的 JS 文件列表
        f.write("=" * 70 + "\n")
        f.write("下载的 JS 文件列表\n")
        f.write("=" * 70 + "\n")
        if js_urls:
            for url in sorted(js_urls):
                f.write(f"{url}\n")
        else:
            f.write("无\n")

        # 外部链接列表（域名 + 标签）
        f.write("\n" + "=" * 70 + "\n")
        f.write("外部链接列表\n")
        f.write("=" * 70 + "\n\n")

        if link_info:
            for link_domain in sorted(link_info.keys()):
                f.write(f"外部链接: {link_domain}\n")
                for tag in sorted(link_info[link_domain]):
                    f.write(f"  标签: {tag}\n")
                f.write("-" * 50 + "\n")
        else:
            f.write("无\n")

    return report_file


if __name__ == "__main__":
    target = input("请输入网站 URL (如 https://www.example.com): ").strip()

    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    domain = get_domain_from_url(target)

    print(f"\n开始全站扫描: {target}")
    print("-" * 70)

    js_urls, pages, base_dir, external_links_detail = scan_and_download_js(target)

    report_file = save_report(js_urls, external_links_detail, pages, base_dir, domain, target)

    print("\n" + "=" * 70)
    print("扫描完成！")
    print("=" * 70)
    print(f"扫描页面数: {len(pages)}")
    print(f"下载的 JS 文件数: {len(js_urls)}")
    print(f"外部链接数: {len(set(domain for domain, _ in external_links_detail))}")
    print(f"\n目录: {base_dir}/")
    print(f"  ├── {domain}.txt")
    print(f"  └── (JS 文件)")
    print(f"\n报告文件: {report_file}")
    print("=" * 70)