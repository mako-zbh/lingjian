#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from config.db import get_connection


def _fetch(sql, conn=None):
    own_conn = conn is None
    conn = conn or get_connection()
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    if own_conn:
        conn.close()
    return rows


def get_blacklink_rules():
    return _fetch('SELECT re, mark, severity FROM blacklink_rules WHERE enabled = 1;')


def get_backdoor_rules():
    return _fetch('SELECT re, mark, severity FROM backdoor_rules WHERE enabled = 1;')


def get_backdoor_paths():
    return [row[0] for row in _fetch('SELECT path FROM backdoor_paths;')]


def get_violative_rules():
    return _fetch('SELECT re, mark, severity FROM violativelink_rules WHERE enabled = 1;')


def get_white_domains():
    return [row[0].lower().strip() for row in _fetch('SELECT domain FROM whiteips;') if row[0]]


def get_rule_snapshot():
    conn = get_connection()
    try:
        return {
            'blacklink_rules': _fetch('SELECT re, mark, severity FROM blacklink_rules WHERE enabled = 1;', conn=conn),
            'backdoor_rules': _fetch('SELECT re, mark, severity FROM backdoor_rules WHERE enabled = 1;', conn=conn),
            'backdoor_paths': [row[0] for row in _fetch('SELECT path FROM backdoor_paths;', conn=conn)],
            'violative_rules': _fetch('SELECT re, mark, severity FROM violativelink_rules WHERE enabled = 1;', conn=conn),
            'white_domains': [row[0].lower().strip() for row in _fetch('SELECT domain FROM whiteips;', conn=conn) if row[0]],
        }
    finally:
        conn.close()
