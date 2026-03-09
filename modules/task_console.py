#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from collections import defaultdict, deque
from urllib.parse import urlparse

from config.crawler import MAX_ALLSITE_PAGES, MAX_SECONDPAGE_PAGES
from config.db import init_db
from modules.crawler import crawl_links, collect_web_data
from modules.response import build_response
from orm.rules import get_rule_snapshot


def run_task(task_url, task_type='HomePage_Scan'):
    task_url = task_url.rstrip('/')
    print(f'* [INFO] 任务开始 目标站点：{task_url}\t任务类型：{task_type}')

    init_db()
    rule_snapshot = get_rule_snapshot()

    try:
        if task_type == 'HomePage_Scan':
            return _task_homepage(task_url, rule_snapshot)
        if task_type == 'SecondPage_Scan':
            return _task_secondpage(task_url, rule_snapshot)
        if task_type == 'AllSite_Scan':
            return _task_allsite(task_url, rule_snapshot)
        if task_type == 'CustomPage_Scan':
            return _task_custompage(task_url, rule_snapshot)
        return {'taskurl': task_url, 'tasktype': task_type, 'status': 'Tasktype Is Incorrect'}
    except Exception as exc:
        return {'taskurl': task_url, 'tasktype': task_type, 'status': f'error: {exc}'}


def _task_homepage(task_url, rule_snapshot):
    res_out, _ = crawl_links(task_url, task_url, white_domains=rule_snapshot['white_domains'])
    print(f'* [INFO] 主页扫描 外链总数：{len(res_out)}')
    webdata = collect_web_data(res_out + [[task_url, [task_url]]])
    return build_response(webdata, task_url, 'HomePage_Scan', rule_snapshot=rule_snapshot)


def _task_secondpage(task_url, rule_snapshot):
    res_out_home, res_in_home = crawl_links(task_url, task_url, white_domains=rule_snapshot['white_domains'])

    combined_out = list(res_out_home)
    combined_in = []
    visited = set()

    for item in res_in_home:
        in_url = item[0]
        if in_url in visited:
            continue
        visited.add(in_url)
        out_l, in_l = crawl_links(in_url, task_url, white_domains=rule_snapshot['white_domains'])
        combined_out.extend(out_l)
        combined_in.extend(in_l)
        if len(visited) >= MAX_SECONDPAGE_PAGES:
            break

    merged = _merge_link_sources(combined_out + combined_in)
    print(f'* [INFO] 二级扫描 页面总数：{len(merged)}')
    webdata = collect_web_data(merged)
    return build_response(webdata, task_url, 'SecondPage_Scan', rule_snapshot=rule_snapshot)


def _task_allsite(task_url, rule_snapshot):
    task_host = (urlparse(task_url).hostname or '').lower()
    queue = deque([task_url])
    visited = set()
    links_for_fetch = []

    while queue and len(visited) < MAX_ALLSITE_PAGES:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        out_l, in_l = crawl_links(current, task_url, white_domains=rule_snapshot['white_domains'])
        links_for_fetch.extend(out_l)
        links_for_fetch.extend(in_l)

        for in_item in in_l:
            in_url = in_item[0]
            in_host = (urlparse(in_url).hostname or '').lower()
            if in_host == task_host and in_url not in visited:
                queue.append(in_url)

    merged = _merge_link_sources(links_for_fetch)
    print(f'* [INFO] 全站扫描 页面总数：{len(merged)} (上限 {MAX_ALLSITE_PAGES})')
    webdata = collect_web_data(merged)
    return build_response(webdata, task_url, 'AllSite_Scan', rule_snapshot=rule_snapshot)


def _task_custompage(task_url, rule_snapshot):
    tmp = task_url.split('//', 1)
    if len(tmp) != 2:
        return {'taskurl': task_url, 'tasktype': 'CustomPage_Scan', 'status': 'error: invalid url'}

    base_url = tmp[0] + '//' + tmp[1].split('/', 1)[0]
    res_out, _ = crawl_links(task_url, base_url, white_domains=rule_snapshot['white_domains'])
    print(f'* [INFO] 自定义页面扫描 外链总数：{len(res_out)}')
    webdata = collect_web_data(res_out + [[task_url, [task_url]]])
    return build_response(webdata, task_url, 'CustomPage_Scan', rule_snapshot=rule_snapshot)


def _merge_link_sources(link_items):
    agg = defaultdict(set)
    for url, masters in link_items:
        for src in masters:
            agg[url].add(src)
    return [[url, sorted(srcs)] for url, srcs in agg.items()]
