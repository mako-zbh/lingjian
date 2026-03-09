#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# 输出阈值：low / medium / high
MIN_CONFIDENCE = 'medium'

# 当违规规则命中项都很短（例如 1~2 字）时，至少满足该命中数才报警。
MIN_SHORT_TOKEN_HITS = 2

# 后门路径探测上限，避免路径库膨胀后单任务请求失控。
MAX_BACKDOOR_PROBES = 30

# 二次验证请求总数上限，只对最可疑的命中做复检。
MAX_BACKDOOR_SECONDARY_CHECKS = 5
