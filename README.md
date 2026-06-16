# Website JS Scanner

## 📖 简介

一个自动化的网站 JavaScript 文件扫描与下载工具。输入网站域名，自动爬取全站所有页面，提取并下载所有引用的 JS 文件，同时识别页面中的外部链接，用于离线安全审计和代码分析。

## 🎯 解决的问题

### 1. 恶意 JS 文件排查
- 检测网站是否引用了已知恶意脚本（如 bshare.cn 等已失效或被劫持的第三方插件）
- 发现隐藏在页面中的可疑外链 JS
- 审计第三方 JS 文件的安全性

### 2. 黑链与外部链接发现
- 自动识别页面中的外部链接（排除目标域名及所有子域名）
- 支持多种标签提取：`a`、`link`、`iframe`、`img`、`script`、`meta` 等
- 完整记录标签代码，便于快速定位

### 3. 安全事件应急响应
当网站出现异常跳转、SEO 黑链、弹窗广告等问题时，快速定位问题文件

### 4. 离线审计
将所有 JS 文件下载到本地，方便使用 grep、IDE 等工具进行深度代码分析

## ✨ 功能特点

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

## 🚀 快速开始

### 环境要求

- Python 3.6+
- pip

### 安装依赖

```bash
pip install requests beautifulsoup4
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