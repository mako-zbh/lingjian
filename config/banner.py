#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import datetime

VERSION = 'v1.0.0'

BANNER = f'''
 _     _             _ _             
| |   (_)_ __   __ _(_) |_ ___  _ __ 
| |   | | '_ \\ / _` | | __/ _ \\| '__|
| |___| | | | | (_| | | || (_) | |   
|_____|_|_| |_|\\__, |_|\\__\\___/|_|   
                |___/                  

lingjian | 网站安全监测工具
Version: {VERSION}
'''


def print_banner():
    print(BANNER)


def print_report_banner():
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    print('```')
    print(BANNER.strip())
    print(f'Report Date: {today}')
    print('```')
