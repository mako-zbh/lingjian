#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / 'lingjian.db'


DDL_SQL = [
    '''
    CREATE TABLE IF NOT EXISTS blacklink_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        re TEXT NOT NULL,
        mark TEXT,
        severity INTEGER DEFAULT 2,
        enabled INTEGER DEFAULT 1
    );
    ''',
    '''
    CREATE TABLE IF NOT EXISTS backdoor_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        re TEXT NOT NULL,
        mark TEXT,
        severity INTEGER DEFAULT 3,
        enabled INTEGER DEFAULT 1
    );
    ''',
    '''
    CREATE TABLE IF NOT EXISTS backdoor_paths (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT NOT NULL
    );
    ''',
    '''
    CREATE TABLE IF NOT EXISTS violativelink_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        re TEXT NOT NULL,
        mark TEXT,
        severity INTEGER DEFAULT 2,
        enabled INTEGER DEFAULT 1
    );
    ''',
    '''
    CREATE TABLE IF NOT EXISTS whiteips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE,
        mark TEXT
    );
    ''',
]


SEED_BLACKLINK_RULES = [
    (r'(<script[\\s\\S]*?fromCharCode[\\s\\S]*?document[\\s\\S]*?</script>)', '恶意代码混淆', 3, 1),
    (r'(<a[^>]+style=["\']?display\\s*:\\s*none["\']?[^>]*href=["\']https?://[^"\']+["\'])', '隐藏外链', 3, 1),
    (r'(<meta[^>]+content=["\']&#.*?["\'])', 'NCR编码可疑注入', 2, 1),
]

SEED_BACKDOOR_RULES = [
    (r'd99shell', '网站后门', 3, 1),
    (r'www\\.r57\\.biz', '网站后门', 3, 1),
]

SEED_BACKDOOR_PATHS = [
    ('/index_bak.php',),
    ('/.index_bak.php',),
    ('/upload/index_bak.php',),
    ('/core/controller/guowda.php',),
    ('/core/library/guowda.php',),
    ('/news.php',),
    ('/cookie.php',),
]

SEED_VIOLATIVE_RULES = [
    (r'色情直播', '色情', 2, 1),
    (r'做爱|做愛', '色情', 2, 1),
    (r'博彩|赌球|彩票计划群', '赌博', 2, 1),
]

SEED_WHITEIPS = [
    ('cctv.com', '可信媒体'),
    ('gov.cn', '政府域名白名单'),
]


def get_connection():
    return sqlite3.connect(str(DB_PATH))


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    for sql in DDL_SQL:
        cur.execute(sql)

    _seed_if_empty(cur, 'blacklink_rules', 'INSERT INTO blacklink_rules (re, mark, severity, enabled) VALUES (?, ?, ?, ?)', SEED_BLACKLINK_RULES)
    _seed_if_empty(cur, 'backdoor_rules', 'INSERT INTO backdoor_rules (re, mark, severity, enabled) VALUES (?, ?, ?, ?)', SEED_BACKDOOR_RULES)
    _seed_if_empty(cur, 'backdoor_paths', 'INSERT INTO backdoor_paths (path) VALUES (?)', SEED_BACKDOOR_PATHS)
    _seed_if_empty(cur, 'violativelink_rules', 'INSERT INTO violativelink_rules (re, mark, severity, enabled) VALUES (?, ?, ?, ?)', SEED_VIOLATIVE_RULES)
    _seed_if_empty(cur, 'whiteips', 'INSERT INTO whiteips (domain, mark) VALUES (?, ?)', SEED_WHITEIPS)

    conn.commit()
    conn.close()


def _seed_if_empty(cursor, table_name, insert_sql, rows):
    cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
    count = cursor.fetchone()[0]
    if count == 0 and rows:
        cursor.executemany(insert_sql, rows)
