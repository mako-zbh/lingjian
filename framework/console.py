#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import argparse

from config.banner import print_banner, print_report_banner
from modules.task_console import run_task


SCAN_TYPES = ['HomePage_Scan', 'SecondPage_Scan', 'AllSite_Scan', 'CustomPage_Scan']


def run_console():
    parser = argparse.ArgumentParser(description='lingjian 网站安全监测工具')
    parser.add_argument('-u', dest='task_url', help='目标 URL，例如 https://example.com')
    parser.add_argument('-t', dest='task_type', default='HomePage_Scan', choices=SCAN_TYPES, help='扫描类型')
    args = parser.parse_args()

    if not args.task_url:
        print_banner()
        return

    print_report_banner()
    run_task(args.task_url, args.task_type)
