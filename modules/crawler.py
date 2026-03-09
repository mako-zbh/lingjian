#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse

from config.crawler import FILE_TYPE_BLACKLIST, SCHEME_BLACKLIST, MAX_WORKERS
from config.requests import BAIDU_SPIDER_HEADERS, NORMAL_HEADERS
from modules.http_client import http_get


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.base_href = ''

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        if tag.lower() == 'base' and attr_map.get('href') and not self.base_href:
            self.base_href = attr_map['href']
            return
        for key in ('href', 'src'):
            value = attr_map.get(key)
            if value:
                self.links.append(value)


def _md5(raw_bytes):
    return hashlib.md5(raw_bytes).hexdigest()


def _normalize_url(url):
    url = (url or '').strip()
    if not url:
        return ''
    parsed = urlparse(url)
    parsed = parsed._replace(fragment='')
    normalized = urlunparse(parsed)
    return normalized.rstrip('/') if parsed.path not in ('', '/') else normalized.rstrip('/')


def _get_html(url):
    try:
        resp = http_get(url, headers=BAIDU_SPIDER_HEADERS)
        if resp.status_code != 200:
            resp = http_get(url, headers=NORMAL_HEADERS)
        return resp.status_code, resp.text, _md5(resp.content)
    except Exception:
        return 'Timeout', 'Timeout', ''


def _is_blacklisted_link(raw_link):
    link = (raw_link or '').strip().lower()
    if not link:
        return True
    if any(link.startswith(scheme) for scheme in SCHEME_BLACKLIST):
        return True
    return any(link.endswith(ext) for ext in FILE_TYPE_BLACKLIST)


def _is_whitelisted_external(url, white_domains):
    host = (urlparse(url).hostname or '').lower()
    if not host:
        return False
    for domain in white_domains:
        d = domain.lower().strip('.')
        if host == d or host.endswith('.' + d):
            return True
    return False


def _extract_raw_links(html_text):
    parser = _LinkParser()
    try:
        parser.feed(html_text or '')
    except Exception:
        parser.links = []
        parser.base_href = ''

    if parser.links:
        return parser.links, parser.base_href

    hrefs = re.findall(r'[\'\"\.]?href[\'\"]?=?[\'\"](.*?)[\'\"]', html_text or '')
    srcs = re.findall(r'[\'\"\.]?src[\'\"]?[:=]?[\'\"](.*?)[\'\"]', html_text or '')
    return [x for x in (hrefs + srcs) if x], ''


def crawl_links(page_url, task_root, white_domains=None):
    out_link = []
    in_link = []

    status_code, html_text, _ = _get_html(page_url)
    if html_text == 'Timeout':
        return [], [[_normalize_url(page_url), [_normalize_url(page_url)]]]

    raw_links, base_href = _extract_raw_links(html_text)

    page_url_norm = _normalize_url(page_url)
    task_root_norm = _normalize_url(task_root)
    task_host = (urlparse(task_root_norm).hostname or '').lower()
    base_url = _normalize_url(urljoin(page_url_norm + '/', base_href)) if base_href else page_url_norm

    in_link.append(page_url_norm)
    for raw in raw_links:
        if _is_blacklisted_link(raw):
            continue
        abs_url = _normalize_url(urljoin(base_url + '/', raw))
        if not abs_url.startswith('http'):
            continue
        host = (urlparse(abs_url).hostname or '').lower()
        if host and host == task_host:
            in_link.append(abs_url)
        else:
            out_link.append(abs_url)

    white_domains = white_domains or []
    res_out, res_in = [], []
    for url in sorted(set(out_link)):
        if url != task_root_norm and not _is_whitelisted_external(url, white_domains):
            res_out.append([url, [page_url_norm]])

    for url in sorted(set(in_link)):
        res_in.append([url, [page_url_norm]])

    return res_out, res_in


def fetch_page_data(url, master):
    url = _normalize_url(url)
    status_code, html_text, hash_val = _get_html(url)
    return {
        'url': url,
        'status_code': status_code,
        'master': master,
        'html': html_text,
        'hash': hash_val,
    }


def collect_web_data(urls):
    if not urls:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(fetch_page_data, item[0], item[1]): item[0]
            for item in urls
        }
        for future in as_completed(future_map):
            try:
                results.append(future.result())
            except Exception:
                results.append({
                    'url': future_map[future],
                    'status_code': 'Timeout',
                    'master': [],
                    'html': 'Timeout',
                    'hash': '',
                })
    return results
