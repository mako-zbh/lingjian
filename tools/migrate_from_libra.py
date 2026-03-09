#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_DB = Path('/Users/zbh/Documents/tools/Libra/Libra.db')
DST_DB = ROOT / 'lingjian.db'


def _severity_from_mark(mark: str, default: int) -> int:
    mark = (mark or '').lower()
    if any(k in mark for k in ('后门', 'webshell', '恶意代码', '黑链')):
        return 3
    if any(k in mark for k in ('赌博', '色情', '违规')):
        return 2
    return default


def _fetch_rows(conn: sqlite3.Connection, sql: str):
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()


def migrate():
    src = sqlite3.connect(str(SRC_DB))
    dst = sqlite3.connect(str(DST_DB))

    stats = {
        'blacklink_rules': 0,
        'backdoor_rules': 0,
        'backdoor_paths': 0,
        'violativelink_rules': 0,
        'whiteips': 0,
    }

    # blacklink_rules
    for re_txt, mark in _fetch_rows(src, 'SELECT re, mark FROM blacklink_rules'):
        sev = _severity_from_mark(mark, 2)
        cur = dst.cursor()
        cur.execute('SELECT 1 FROM blacklink_rules WHERE re = ? LIMIT 1', (re_txt,))
        if cur.fetchone():
            continue
        cur.execute(
            'INSERT INTO blacklink_rules (re, mark, severity, enabled) VALUES (?, ?, ?, 1)',
            (re_txt, mark, sev),
        )
        stats['blacklink_rules'] += 1

    # backdoor_rules
    for re_txt, mark in _fetch_rows(src, 'SELECT re, mark FROM backdoor_rules'):
        sev = _severity_from_mark(mark, 3)
        cur = dst.cursor()
        cur.execute('SELECT 1 FROM backdoor_rules WHERE re = ? LIMIT 1', (re_txt,))
        if cur.fetchone():
            continue
        cur.execute(
            'INSERT INTO backdoor_rules (re, mark, severity, enabled) VALUES (?, ?, ?, 1)',
            (re_txt, mark, sev),
        )
        stats['backdoor_rules'] += 1

    # backdoor_paths
    for (path,) in _fetch_rows(src, 'SELECT path FROM backdoor_paths'):
        cur = dst.cursor()
        cur.execute('SELECT 1 FROM backdoor_paths WHERE path = ? LIMIT 1', (path,))
        if cur.fetchone():
            continue
        cur.execute('INSERT INTO backdoor_paths (path) VALUES (?)', (path,))
        stats['backdoor_paths'] += 1

    # violativelink_rules
    for re_txt, mark in _fetch_rows(src, 'SELECT re, mark FROM violativelink_rules'):
        sev = _severity_from_mark(mark, 2)
        cur = dst.cursor()
        cur.execute('SELECT 1 FROM violativelink_rules WHERE re = ? LIMIT 1', (re_txt,))
        if cur.fetchone():
            continue
        cur.execute(
            'INSERT INTO violativelink_rules (re, mark, severity, enabled) VALUES (?, ?, ?, 1)',
            (re_txt, mark, sev),
        )
        stats['violativelink_rules'] += 1

    # whiteips
    for domain, mark in _fetch_rows(src, 'SELECT domain, mark FROM whiteips'):
        dom = (domain or '').strip().lower().lstrip('.')
        if not dom:
            continue
        cur = dst.cursor()
        cur.execute('SELECT 1 FROM whiteips WHERE domain = ? LIMIT 1', (dom,))
        if cur.fetchone():
            continue
        cur.execute('INSERT INTO whiteips (domain, mark) VALUES (?, ?)', (dom, mark))
        stats['whiteips'] += 1

    dst.commit()
    src.close()
    dst.close()

    return stats


if __name__ == '__main__':
    s = migrate()
    print('migrate done')
    for k, v in s.items():
        print(f'{k}: +{v}')
