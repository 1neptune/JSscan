# Website JS Scanner

## 📖 简介

一个自动化的网站 JavaScript 文件扫描与下载工具。输入网站域名，自动爬取全站所有页面，提取并下载所有引用的 JS 文件，同时识别页面中的外部链接和黑链，用于离线安全审计和代码分析。

**⚠️ 重大升级：现已支持 Selenium 动态渲染，可抓取 Vue/React/AJAX 动态生成的黑链和恶意脚本！**

## 🎯 解决的问题

### 1. 恶意 JS 文件排查
- 检测网站是否引用了已知恶意脚本（如 bshare.cn 等已失效或被劫持的第三方插件）
- 发现隐藏在页面中的可疑外链 JS
- 审计第三方 JS 文件的安全性

### 2. 黑链与外部链接发现
- 自动识别页面中的外部链接（排除目标域名及所有子域名）
- 支持 16+ 种标签提取：`a`、`link`、`iframe`、`img`、`script`、`meta` 等
- **新增事件属性提取**：`onclick`、`onload`、`onmouseover` 等事件中的恶意跳转
- **新增动态注入检测**：`document.write`、`innerHTML` 插入的 iframe/a 标签
- **新增 location 跳转检测**：`window.location`、`top.location` 指向外部非法域名
- 完整记录标签代码，便于快速定位

### 3. 动态渲染页面支持
- **Vue/React 单页应用**：Selenium 渲染后获取完整 DOM
- **AJAX 异步加载**：等待异步请求完成后再提取
- **setTimeout 延时注入**：等待动态内容加载完成
- **懒加载图片/链接**：滚动页面触发懒加载

### 4. 安全事件应急响应
当网站出现异常跳转、SEO 黑链、弹窗广告等问题时，快速定位问题文件

### 5. 离线审计
将所有 JS 文件下载到本地，方便使用 grep、IDE 等工具进行深度代码分析

## ✨ 功能特点

### 动态渲染引擎
- ✅ **Selenium 动态渲染** - 支持 Vue/React/AJAX 页面，无头模式后台运行
- ✅ **事件属性提取** - 捕获 onclick/onload/onmouseover 中的恶意 URL
- ✅ **动态注入检测** - 识别 document.write/innerHTML 插入的黑链
- ✅ **location 跳转检测** - 捕获 window.location/top.location 恶意跳转
- ✅ **懒加载支持** - 滚动页面触发图片/链接懒加载

### 核心功能
- ✅ **全站递归扫描** - 自动爬取同域名及所有子域名下所有页面
- ✅ **自动下载 JS** - 将所有 JS 文件保存到本地
- ✅ **智能去重** - 基于文件名和 MD5 双重校验，相同内容只下载一次
- ✅ **文件名冲突处理** - 同名但内容不同时自动添加时间戳
- ✅ **每次全新扫描** - 自动清空旧目录，无残留文件
- ✅ **完整 URL 记录** - JS 文件列表记录完整链接，便于追溯
- ✅ **外部链接识别** - 自动提取页面中的外部链接，并记录完整标签代码
- ✅ **支持 16+ 种标签** - 覆盖 `a`、`link`、`iframe`、`img`、`script`、`meta` 等
- ✅ **按域名分组展示** - 外部链接按域名去重分组，清晰直观
- ✅ **错误处理** - 超时、连接错误自动跳过，不影响扫描进度

## 📋 支持的检测场景

| 场景 | 解决方案 | 示例 |
|------|----------|------|
| **Vue/React 动态渲染** | Selenium 渲染后获取 page_source | `<div id="app">{{ link }}</div>` |
| **AJAX 异步加载黑链** | WebDriverWait 等待 + 延时 | `setTimeout(() => { createLink() }, 3000)` |
| **onclick 恶意跳转** | 遍历所有事件属性 | `<div onclick="open('https://evil.com')">` |
| **window.location 劫持** | JS 执行检测 + 正则匹配 | `window.location.href = 'https://evil.com'` |
| **document.write 注入** | 执行 JS 检测注入内容 | `document.write('<iframe src="evil.com">')` |
| **innerHTML 插入黑链** | 检测 innerHTML 赋值 | `div.innerHTML = '<a href="evil.com">'` |
| **CSS 伪元素隐藏暗链** | Selenium 检测隐藏元素 | `style="display:none"`、`opacity:0` |
| **宽高 0 像素暗链** | 检测元素尺寸属性 | `width="0" height="0"` |
| **动态创建 a/iframe** | Selenium 获取 DOM 后的全部元素 | `document.createElement('iframe')` |

## 📋 支持提取的外部链接标签

| 标签 | 说明 | 示例 |
|------|------|------|
| `<a>` | 普通超链接 | `<a href="http://evil.com">` |
| `<link>` | CSS 引入 | `<link href="http://evil.com/evil.css">` |
| `<iframe>` `<frame>` | 内嵌框架 | `<iframe src="http://evil.com">` |
| `<img>` | 图片/追踪像素 | `<img src="http://evil.com/pixel.gif">` |
| `<script>` | 外部脚本 | `<script src="http://evil.com/a.js">` |
| `<embed>` `<object>` | 插件内容 | `<embed src="http://evil.com/file.swf">` |
| `<meta refresh>` | 自动跳转 | `<meta http-equiv="refresh" content="0;url=http://evil.com">` |
| `<style>` / `style` 属性 | 背景图片 | `style="background:url(http://evil.com/bg.jpg)"` |
| `<form>` | 表单提交 | `<form action="http://evil.com/submit">` |
| `<area>` | 图像映射 | `<area href="http://evil.com/link">` |
| `<base>` | 基础 URL | `<base href="http://evil.com/">` |
| `<!-- -->` 注释 | 注释中的隐藏链接 | `<!-- http://evil.com/hidden -->` |
| `<audio>` `<video>` | 多媒体资源 | `<audio src="http://evil.com/audio.mp3">` |
| `<source>` | 媒体资源 | `<source src="http://evil.com/video.mp4">` |
| 内联 `<script>` | 脚本中的 URL | `<script>var url="http://evil.com/api"</script>` |
| **事件属性（新增）** | onclick/onload 等事件 | `<div onclick="open('http://evil.com')">` |
| **动态注入（新增）** | document.write/innerHTML | `<script>document.write('<iframe src="evil.com">')</script>` |
| **location 跳转（新增）** | window.location 劫持 | `<script>window.location.href='http://evil.com'</script>` |

## 🚀 快速开始

### 环境要求

- Python 3.6+
- pip
- Chrome 浏览器（Selenium 动态渲染需要）
- ChromeDriver（webdriver-manager 自动下载）

### 安装依赖

```bash
pip install requests beautifulsoup4 selenium webdriver-manager
```

### 运行
```bash
python scanJS.py
```

### 输入网址
```bash
请输入网站 URL (如 https://www.example.com): https://www.example.com
```

## 输出结果

### 目录结构
```bash
www.example.com/
├── www.example.com.txt    # 扫描报告
├── main.js
├── vendor.js
├── bshareC0.js
├── buttonLite.js
└── ...
```

### 报告文件内容
```bash
======================================================================
扫描统计汇总
======================================================================
扫描目标: https://www.example.com
扫描时间: 2026-01-15 15:30:00
扫描页面数: 45
下载的 JS 文件数: 23
外部链接数: 8
======================================================================

======================================================================
下载的 JS 文件列表
======================================================================
https://www.example.com/static/js/main.js
https://www.example.com/static/js/vendor.js
http://static.bshare.cn/b/bshareC0.js
http://static.bshare.cn/b/buttonLite.js
======================================================================
外部链接列表
======================================================================

外部链接: http://bshare.cn
  标签: <script src="http://static.bshare.cn/b/bshareC0.js"></script>
  标签: <script src="http://static.bshare.cn/b/buttonLite.js"></script>
--------------------------------------------------
外部链接: https://evil.com/tracker.gif
  标签: <iframe src="https://evil.com/tracker.gif" width="0" height="0"></iframe>
  
外部链接: malicious-cdn.net
  标签: <link rel="stylesheet" href="https://malicious-cdn.net/evil.css">
--------------------------------------------------

```

### 在下载的 JS 文件中搜索关键词
```bash
cd www.example.com
grep -r "bshare" .
```