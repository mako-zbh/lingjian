#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import base64
import html
import hashlib
import re
from urllib.parse import unquote
from uuid import uuid4

from config.detection import MIN_SHORT_TOKEN_HITS, MAX_BACKDOOR_PROBES, MAX_BACKDOOR_SECONDARY_CHECKS
from config.requests import NORMAL_HEADERS
from modules.http_client import http_get


def _normalize_text(content):
    txt = content or ''
    txt = html.unescape(txt)
    for _ in range(2):
        txt = unquote(txt)
    try:
        txt = txt.encode('utf-8', errors='ignore').decode('unicode_escape')
    except Exception:
        pass
    return txt


def _decode_fromcharcode(text):
    out = []
    for match in re.findall(r'fromCharCode\\(([^)]{1,5000})\\)', text, re.I):
        nums = re.findall(r'\\d{2,3}', match)
        if not nums:
            continue
        try:
            out.append(''.join(chr(int(n)) for n in nums))
        except Exception:
            continue
    return out


def _decode_base64_chunks(text):
    out = []
    for candidate in re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text):
        try:
            raw = base64.b64decode(candidate, validate=True)
            decoded = raw.decode('utf-8', errors='ignore')
            if decoded and any(k in decoded.lower() for k in ('http', '<script', 'href', 'iframe')):
                out.append(decoded)
        except Exception:
            continue
    return out


def _build_contexts(htmltxt):
    normalized = _normalize_text(htmltxt)
    contexts = [normalized]
    contexts.extend(_decode_fromcharcode(normalized))
    contexts.extend(_decode_base64_chunks(normalized))
    return contexts


def _confidence(hits):
    if not hits:
        return 'low'
    max_sev = max(hit['severity'] for hit in hits)
    if max_sev >= 3 or len(hits) >= 2:
        return 'high'
    return 'medium'


def _backdoor_confidence(score):
    if score >= 7:
        return 'high'
    if score >= 4:
        return 'medium'
    return 'low'


def _is_probably_malicious_script_hit(mark, snippet):
    if mark not in ('恶意代码混淆', '高风险脚本混淆跳转'):
        return True

    txt = (snippet or '').lower()
    has_obfuscation = any(token in txt for token in (
        'fromcharcode',
        'eval(',
        'atob(',
        'unescape(',
        'decodeuricomponent',
        'base64',
    ))
    has_danger_action = any(token in txt for token in (
        'document.write',
        'innerhtml',
        'window.location',
        'location.href',
        '<iframe',
        'display:none',
        'visibility:hidden',
        'opacity:0',
    ))
    has_external_or_encoded = bool(re.search(
        r'https?://|%[0-9a-f]{2}|&#x[0-9a-f]+;|&#\\d+;',
        txt,
        re.I,
    ))
    return has_obfuscation and has_danger_action and has_external_or_encoded


def blacklink_find(htmltxt, rules):
    contexts = _build_contexts(htmltxt)
    hits = []
    seen = set()
    for pattern, mark, severity in rules:
        for ctx in contexts:
            try:
                found = re.findall(pattern, ctx, re.I | re.S)
            except re.error:
                continue
            for item in found:
                snippet = item if isinstance(item, str) else ''.join(item)
                snippet = html.unescape(snippet)
                if len(snippet) > 300:
                    snippet = snippet[:300] + '...'
                if not _is_probably_malicious_script_hit(mark, snippet):
                    continue
                key = (mark, snippet)
                if key in seen:
                    continue
                seen.add(key)
                hits.append({'mark': mark, 'snippet': snippet, 'severity': int(severity or 2)})
    return hits, _confidence(hits)


def violative_find(htmltxt, rules):
    text = _normalize_text(htmltxt)
    hits = []
    seen = set()
    total_occurrences = 0
    for pattern, mark, severity in rules:
        try:
            found = re.findall(pattern, text, re.I | re.S)
            if found:
                key = (mark, pattern)
                if key in seen:
                    continue
                seen.add(key)
                hit_count = len(found)
                total_occurrences += hit_count
                hits.append({
                    'mark': mark,
                    'snippet': pattern,
                    'severity': int(severity or 2),
                    'count': hit_count,
                })
        except re.error:
            continue

    if not hits:
        return hits, 'low'

    only_short_tokens = all(len((hit['snippet'] or '').strip()) <= 2 for hit in hits)
    if only_short_tokens and len(hits) < MIN_SHORT_TOKEN_HITS and total_occurrences < MIN_SHORT_TOKEN_HITS:
        return [], 'low'

    score = sum(hit['severity'] * min(hit.get('count', 1), 3) for hit in hits)
    max_sev = max(hit['severity'] for hit in hits)
    if max_sev >= 3 and score >= 3:
        conf = 'high'
    elif score >= 4 or len(hits) >= 2:
        conf = 'medium'
    else:
        conf = 'low'
    return hits, conf


def _http_get_text(url):
    try:
        resp = http_get(url, headers=NORMAL_HEADERS, allow_redirects=True)
        body = resp.text or ''
        return resp.status_code, body
    except Exception:
        return 0, ''


def _short_title(text):
    m = re.search(r'<title[^>]*>(.*?)</title>', text, re.I | re.S)
    if not m:
        return ''
    return re.sub(r'\s+', ' ', html.unescape(m.group(1))).strip()[:120].lower()


def _page_signature(status_code, body):
    title = _short_title(body)
    body_norm = _normalize_text(body).lower()
    token = re.sub(r'\s+', ' ', body_norm[:3000])
    digest = hashlib.md5(token.encode('utf-8', errors='ignore')).hexdigest()
    length_bucket = len(body_norm) // 200
    return f'{status_code}|{title}|{length_bucket}|{digest[:12]}'


def _backdoor_score(body, status_code, match_count):
    text = _normalize_text(body).lower()
    score = 0
    if status_code == 200:
        score += 1
    if 20 <= len(text) <= 300000:
        score += 1
    score += min(match_count, 3)

    if any(k in text for k in ('<?php', 'asp ', 'aspx', 'jsp')):
        score += 1
    if any(k in text for k in (
        'eval(base64_decode',
        'assert($_post',
        'system($_get',
        'passthru(',
        'shell_exec(',
        'preg_replace("/.*/e"',
        'createfunction(',
        'chr(',
        'gzinflate(',
    )):
        score += 2
    if any(k in text for k in ('cmd=', 'password=', 'execute', 'webshell', 'r57', 'c99', 'd99')):
        score += 2
    if any(k in text for k in ('404', 'not found', '页面不存在', '访问被拒绝', '请先登录')):
        score -= 2
    return score


def _secondary_verify(url, pattern):
    sep = '&' if '?' in url else '?'
    verify_url = f'{url}{sep}_lj_verify={uuid4().hex[:8]}'
    code, body = _http_get_text(verify_url)
    if code == 0 or not body:
        return 0
    try:
        matched = re.findall(pattern, body, re.I | re.S)
        return 2 if matched else -1
    except re.error:
        return 0


def _should_probe_status(status_code, body):
    if status_code in (200, 401, 403, 500):
        return True
    if status_code in (301, 302, 307, 308):
        return 'login' in (body or '').lower()
    return False


def backdoor_find(base_url, rules, paths):
    hits = []
    seen = set()
    template_signatures = {}
    page_cache = {}
    secondary_checks = 0

    # 单路径单请求，避免旧逻辑对每条规则重复请求同一路径造成噪声和性能浪费。
    for path in paths[:MAX_BACKDOOR_PROBES]:
        probe_url = f'{base_url.rstrip("/")}{path}'
        status_code, body = _http_get_text(probe_url)
        if status_code == 0 or not body or not _should_probe_status(status_code, body):
            continue
        sig = _page_signature(status_code, body)
        template_signatures[sig] = template_signatures.get(sig, 0) + 1
        page_cache[probe_url] = (status_code, body, sig)

    for probe_url, (status_code, body, sig) in page_cache.items():
        for pattern, mark, severity in rules:
            try:
                found = re.findall(pattern, body, re.I | re.S)
            except re.error:
                continue
            if not found:
                continue

            # 同一模板页在大量路径重复出现通常是拦截页/错误页，优先降噪。
            if template_signatures.get(sig, 0) >= 3:
                continue

            score = _backdoor_score(body, status_code, len(found))
            if secondary_checks < MAX_BACKDOOR_SECONDARY_CHECKS:
                score += _secondary_verify(probe_url, pattern)
                secondary_checks += 1
            conf = _backdoor_confidence(score)
            if conf == 'low':
                continue

            key = (mark, probe_url)
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                'mark': mark,
                'snippet': f'{probe_url} (score={score},conf={conf})',
                'severity': int(severity or 3),
                'confidence': conf,
            })

    if not hits:
        return [], 'low'
    if any(hit.get('confidence') == 'high' for hit in hits):
        return hits, 'high'
    return hits, 'medium'
