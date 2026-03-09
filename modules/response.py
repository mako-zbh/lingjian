#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import json
import hashlib
from pathlib import Path

from config.logging import log_data
from config.detection import MIN_CONFIDENCE
from modules.rule_engine import blacklink_find, violative_find, backdoor_find
from orm.rules import get_rule_snapshot
from tools.common import now_str


def _format_hits(hits):
    return [f'【{h["mark"]}|S{h["severity"]}】 {h["snippet"]}' for h in hits]


def _finding_fingerprint(finding_type, url, confidence, evidence):
    payload = '|'.join([
        finding_type or '',
        url or '',
        confidence or '',
        '||'.join(sorted(evidence or [])),
    ])
    return hashlib.md5(payload.encode('utf-8', errors='ignore')).hexdigest()[:16]


def _conf_ge(conf, min_conf):
    level = {'low': 1, 'medium': 2, 'high': 3}
    return level.get(conf, 1) >= level.get(min_conf, 2)


def _uniq_urls(items):
    return len({item.get('url', '') for item in items if item.get('url')})


def _count_conf(items, level_name):
    return sum(1 for item in items if item.get('confidence') == level_name)


def _top_issue_urls(data, topn=5):
    counters = {}
    for key in ('blacklink_list', 'violativelink_list', 'backdoor_list', 'diedlink_list'):
        for item in data.get(key, []):
            url = item.get('url')
            if not url:
                continue
            counters[url] = counters.get(url, 0) + 1
    ranked = sorted(counters.items(), key=lambda x: x[1], reverse=True)
    return ranked[:topn]


def _overall_risk(data):
    high_cnt = _count_conf(data['blacklink_list'], 'high') + _count_conf(data['violativelink_list'], 'high') + _count_conf(data['backdoor_list'], 'high')
    medium_cnt = _count_conf(data['blacklink_list'], 'medium') + _count_conf(data['violativelink_list'], 'medium') + _count_conf(data['backdoor_list'], 'medium')
    if high_cnt > 0 or len(data['backdoor_list']) > 0:
        return 'high'
    if medium_cnt > 0:
        return 'medium'
    if data['diedlink_list']:
        return 'low'
    return 'info'


def _summary_lines(data):
    lines = []
    lines.append('### 检测汇总\n')
    lines.append('```')
    lines.append('任务类型：' + data['tasktype'])
    lines.append('检测时间：' + data['datetime'])
    lines.append('总体风险：' + _overall_risk(data))
    lines.append('黑链告警：{} (高:{} 中:{} URL:{})'.format(
        len(data['blacklink_list']),
        _count_conf(data['blacklink_list'], 'high'),
        _count_conf(data['blacklink_list'], 'medium'),
        _uniq_urls(data['blacklink_list']),
    ))
    lines.append('违规告警：{} (高:{} 中:{} URL:{})'.format(
        len(data['violativelink_list']),
        _count_conf(data['violativelink_list'], 'high'),
        _count_conf(data['violativelink_list'], 'medium'),
        _uniq_urls(data['violativelink_list']),
    ))
    lines.append('后门告警：{} (高:{} 中:{} URL:{})'.format(
        len(data['backdoor_list']),
        _count_conf(data['backdoor_list'], 'high'),
        _count_conf(data['backdoor_list'], 'medium'),
        _uniq_urls(data['backdoor_list']),
    ))
    lines.append('死链数量：{} (URL:{})'.format(len(data['diedlink_list']), _uniq_urls(data['diedlink_list'])))
    top_urls = _top_issue_urls(data)
    if top_urls:
        lines.append('问题URL Top{}:'.format(len(top_urls)))
        for url, score in top_urls:
            lines.append('- {} ({})'.format(url, score))
    else:
        lines.append('问题URL Top0: 无')
    lines.append('```')
    return lines


def _detail_lines(data):
    lines = []
    lines.append('------------------------------------------------------------')
    lines.append('# 检测地址：' + data['taskurl'])
    lines.append('------------------------------------------------------------')

    if data['blacklink_list']:
        lines.append('### 黑链检测结果\n')
        lines.append('```')
        for item in data['blacklink_list']:
            lines.append('问题地址：\n' + item['url'])
            lines.append('置信度：' + item['confidence'])
            lines.append('黑链信息：')
            for hit in item['blacklinkres']:
                lines.append(hit)
            lines.append('来源地址：')
            for src in item['master']:
                lines.append(src)
            lines.append('')
        lines.append('```')

    if data['violativelink_list']:
        lines.append('### 违规检测结果\n')
        lines.append('```')
        for item in data['violativelink_list']:
            lines.append('问题地址：\n' + item['url'])
            lines.append('置信度：' + item['confidence'])
            lines.append('违规内容：')
            for hit in item['violativelinkres']:
                lines.append(hit)
            lines.append('来源地址：')
            for src in item['master']:
                lines.append(src)
            lines.append('')
        lines.append('```')

    if data['backdoor_list']:
        lines.append('### 后门检测结果\n')
        lines.append('```')
        for item in data['backdoor_list']:
            lines.append('问题地址：\n' + item['url'])
            lines.append('置信度：' + item['confidence'])
            lines.append('后门特征：')
            for hit in item['backdoorres']:
                lines.append(hit)
            lines.append('来源地址：')
            for src in item['master']:
                lines.append(src)
            lines.append('')
        lines.append('```')

    if data['diedlink_list']:
        lines.append('### 死链检测结果\n')
        lines.append('```')
        for item in data['diedlink_list']:
            lines.append('问题地址：\n' + item['url'])
            lines.append('访问状态：\n' + str(item['status_code']))
            lines.append('来源地址：')
            for src in item['master']:
                lines.append(src)
            lines.append('')
        lines.append('```')

    lines.extend(_summary_lines(data))
    lines.append('------------------------------------------------------------')
    return lines


def _safe_name(url):
    return ''.join(ch if ch.isalnum() or ch in ('-', '_') else '_' for ch in url)[:80]


def _merge_source_lists(items):
    merged = []
    by_fp = {}
    for item in items:
        fp = item['fingerprint']
        existing = by_fp.get(fp)
        if existing is None:
            cloned = dict(item)
            cloned['master'] = sorted(set(item.get('master', [])))
            by_fp[fp] = cloned
            merged.append(cloned)
            continue
        existing['master'] = sorted(set(existing.get('master', [])) | set(item.get('master', [])))
    return merged


def _json_report_data(data):
    export = dict(data)
    export['report_files'] = dict(data.get('report_files', {}))
    return export


def _write_reports(data):
    reports_dir = Path(__file__).resolve().parent.parent / 'reports'
    reports_dir.mkdir(parents=True, exist_ok=True)
    run_id = data['datetime'].replace(':', '').replace('-', '').replace(' ', '_')
    target = _safe_name(data['taskurl'])
    base_name = f'{run_id}_{target}'
    md_path = reports_dir / f'{base_name}.md'
    json_path = reports_dir / f'{base_name}.json'

    detail = '\n'.join(_detail_lines(data)) + '\n'
    md_path.write_text(detail, encoding='utf-8')
    json_path.write_text(json.dumps(_json_report_data(data), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return {'markdown': str(md_path), 'json': str(json_path)}


def _resolve_rule_snapshot(rule_snapshot=None):
    if rule_snapshot is not None:
        return rule_snapshot
    return get_rule_snapshot()


def build_response(webdata, task_url, task_type, rule_snapshot=None):
    dead_links = []
    violative_list = []
    backdoor_list = []
    blacklink_list = []

    rule_snapshot = _resolve_rule_snapshot(rule_snapshot)
    violative_rules = rule_snapshot['violative_rules']
    blacklink_rules = rule_snapshot['blacklink_rules']
    backdoor_rules = rule_snapshot['backdoor_rules']
    backdoor_paths = rule_snapshot['backdoor_paths']

    backdoor_hits, backdoor_conf = backdoor_find(task_url, backdoor_rules, backdoor_paths)
    if backdoor_hits:
        backdoor_list.append({
            'type': 'backdoor',
            'url': task_url,
            'confidence': backdoor_conf,
            'backdoorres': _format_hits(backdoor_hits),
            'master': [task_url],
            'fingerprint': _finding_fingerprint('backdoor', task_url, backdoor_conf, _format_hits(backdoor_hits)),
        })

    for page in webdata:
        if page['status_code'] != 200:
            dead_links.append({
                'type': 'deadlink',
                'url': page['url'],
                'status_code': page['status_code'],
                'master': page['master'],
                'fingerprint': _finding_fingerprint('deadlink', page['url'], str(page['status_code']), [str(page['status_code'])]),
            })

        violative_hits, violative_conf = violative_find(page['html'], violative_rules)
        blacklink_hits, blacklink_conf = blacklink_find(page['html'], blacklink_rules)
        formatted_violative_hits = _format_hits(violative_hits)
        formatted_blacklink_hits = _format_hits(blacklink_hits)

        if violative_hits and _conf_ge(violative_conf, MIN_CONFIDENCE):
            violative_list.append({
                'type': 'violative',
                'url': page['url'],
                'confidence': violative_conf,
                'violativelinkres': formatted_violative_hits,
                'master': page['master'],
                'fingerprint': _finding_fingerprint('violative', page['url'], violative_conf, formatted_violative_hits),
            })

        if blacklink_hits and _conf_ge(blacklink_conf, MIN_CONFIDENCE):
            blacklink_list.append({
                'type': 'blacklink',
                'url': page['url'],
                'confidence': blacklink_conf,
                'blacklinkres': formatted_blacklink_hits,
                'master': page['master'],
                'fingerprint': _finding_fingerprint('blacklink', page['url'], blacklink_conf, formatted_blacklink_hits),
            })

    dead_links = _merge_source_lists(dead_links)
    violative_list = _merge_source_lists(violative_list)
    blacklink_list = _merge_source_lists(blacklink_list)
    backdoor_list = _merge_source_lists(backdoor_list)

    data = {
        'taskurl': task_url,
        'tasktype': task_type,
        'status': 'success',
        'diedlink_list': dead_links,
        'blacklink_list': blacklink_list,
        'violativelink_list': violative_list,
        'backdoor_list': backdoor_list,
        'datetime': now_str(),
    }
    data['summary'] = {
        'overall_risk': _overall_risk(data),
        'blacklink_alerts': len(data['blacklink_list']),
        'violative_alerts': len(data['violativelink_list']),
        'backdoor_alerts': len(data['backdoor_list']),
        'dead_links': len(data['diedlink_list']),
        'top_issue_urls': _top_issue_urls(data),
    }
    data['report_files'] = {}
    data['report_files'] = _write_reports(data)
    _print_terminal_summary(data)
    log_data(json.dumps(data, ensure_ascii=False))
    return data


def _print_terminal_summary(data):
    if data['status'] != 'success':
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    print('------------------------------------------------------------')
    print('# 检测地址：' + data['taskurl'])
    print('------------------------------------------------------------')
    for line in _summary_lines(data):
        print(line)
    print('详细报告(Markdown)：' + data['report_files']['markdown'])
    print('------------------------------------------------------------')
