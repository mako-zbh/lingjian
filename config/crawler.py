#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# 过滤静态资源、二进制下载、协议伪链接，避免误爬取导致误报。
FILE_TYPE_BLACKLIST = [
    '.css', '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.ico', '.svg',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tar.gz', '.tar.bz2',
    '.exe', '.msi', '.dmg', '.deb', '.rpm', '.app', '.apk',
    '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ppt', '.pptx', '.odt', '.ods', '.odp',
    '.mp3', '.mp4', '.wmv', '.avi', '.mov', '.mkv', '.flv', '.webm', '.m4v', '.3gp',
    '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a',
    '.ttf', '.tiff', '.tif', '.psd', '.raw', '.cr2', '.nef', '.webp', '.otf', '.woff', '.woff2', '.eot',
    '.db', '.sqlite', '.mdb', '.accdb', '.iso', '.bin', '.img', '.vmdk', '.log', '.bak', '.tmp',
]

SCHEME_BLACKLIST = ['mailto:', 'javascript:', 'data:image']

REQUEST_TIMEOUT = 10
MAX_WORKERS = 20
MAX_ALLSITE_PAGES = 300
MAX_SECONDPAGE_PAGES = 80
