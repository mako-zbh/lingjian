#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import random

UA_POOL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
]

RANDOM_UA = random.choice(UA_POOL)

BAIDU_SPIDER_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
    'Referer': 'http://www.baidu.com',
}

NORMAL_HEADERS = {
    'User-Agent': RANDOM_UA,
    'Referer': 'http://www.baidu.com',
    'Accept-Language': 'zh-CN,zh;q=0.9',
}
