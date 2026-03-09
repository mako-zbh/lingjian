#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import datetime


def now_str():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
