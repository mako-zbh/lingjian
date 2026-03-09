#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / 'lingjian.db'

HIGH_PREC_BLACKLINK = [
    (
        r'(<a[^>]+href=["\']https?://[^"\']+["\'][^>]*(?:display\\s*:\\s*none|visibility\\s*:\\s*hidden|opacity\\s*:\\s*0)[^>]*>)',
        '隐藏样式外链',
        3,
    ),
    (
        r'(<iframe[^>]+src=["\']https?://[^"\']+["\'][^>]*(?:width=["\']?0["\']?|height=["\']?0["\']?|display\\s*:\\s*none)[^>]*>)',
        '隐藏iframe外链',
        3,
    ),
    (
        r'(<script[\\s\\S]{0,5000}?(?:eval\\(|atob\\(|fromCharCode\\()[\\s\\S]{0,5000}?(?:location\\.|document\\.write|innerHTML)[\\s\\S]{0,5000}?</script>)',
        '高风险脚本混淆跳转',
        3,
    ),
]

HIGH_PREC_VIOLATIVE = [
    (r'(色情直播|约炮|援交|人妻无码|裸聊)', '色情高危词', 3),
    (r'(现金网|博彩平台|六合彩|北京赛车|体育博彩)', '赌博高危词', 3),
    (r'(办证|假证|刻章|代开发票)', '违法交易高危词', 3),
]

HIGH_PREC_BACKDOOR = [
    (r'(?:eval\\(base64_decode|assert\\(\\$_POST|system\\(\\$_GET|passthru\\(|shell_exec\\()', '通用WebShell特征', 3),
]

EXTRA_BACKDOOR_PATHS = [
    '/shell.php',
    '/1.php',
    '/admin/shell.php',
    '/upload/shell.php',
]


def _insert_rule(cur, table, re_txt, mark, severity):
    cur.execute(f'SELECT 1 FROM {table} WHERE re = ? LIMIT 1', (re_txt,))
    if cur.fetchone():
        return 0
    cur.execute(
        f'INSERT INTO {table} (re, mark, severity, enabled) VALUES (?, ?, ?, 1)',
        (re_txt, mark, severity),
    )
    return 1


def _insert_path(cur, path):
    cur.execute('SELECT 1 FROM backdoor_paths WHERE path = ? LIMIT 1', (path,))
    if cur.fetchone():
        return 0
    cur.execute('INSERT INTO backdoor_paths (path) VALUES (?)', (path,))
    return 1


def _create_indexes(cur):
    cur.execute('CREATE INDEX IF NOT EXISTS idx_blacklink_enabled ON blacklink_rules(enabled)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_backdoor_enabled ON backdoor_rules(enabled)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_violative_enabled ON violativelink_rules(enabled)')


def run():
    conn = sqlite3.connect(str(DB))
    cur = conn.cursor()

    added = {
        'blacklink_rules': 0,
        'violativelink_rules': 0,
        'backdoor_rules': 0,
        'backdoor_paths': 0,
    }

    for re_txt, mark, sev in HIGH_PREC_BLACKLINK:
        added['blacklink_rules'] += _insert_rule(cur, 'blacklink_rules', re_txt, mark, sev)

    for re_txt, mark, sev in HIGH_PREC_VIOLATIVE:
        added['violativelink_rules'] += _insert_rule(cur, 'violativelink_rules', re_txt, mark, sev)

    for re_txt, mark, sev in HIGH_PREC_BACKDOOR:
        added['backdoor_rules'] += _insert_rule(cur, 'backdoor_rules', re_txt, mark, sev)

    for path in EXTRA_BACKDOOR_PATHS:
        added['backdoor_paths'] += _insert_path(cur, path)

    _create_indexes(cur)

    conn.commit()
    conn.close()
    return added


if __name__ == '__main__':
    res = run()
    print('enhance done')
    for k, v in res.items():
        print(f'{k}: +{v}')
