#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import base64
import html
import hashlib
import re
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from uuid import uuid4

from config.detection import MIN_SHORT_TOKEN_HITS, MAX_BACKDOOR_PROBES, MAX_BACKDOOR_SECONDARY_CHECKS
from config.crawler import MAX_WORKERS
from config.requests import NORMAL_HEADERS
from modules.http_client import http_get


def _decode_js_escapes(text):
    """只解码 JS 风格的 \\uXXXX / \\xNN 转义序列。

    不能对整段文本做 unicode_escape 解码：那会把 UTF-8 中文字节当成
    latin-1 逐字节解释，中文全部变成乱码，敏感词永远匹配不上。
    """
    def _sub(m):
        try:
            return m.group(0).encode('ascii').decode('unicode_escape')
        except Exception:
            return m.group(0)

    return re.sub(r'(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})+', _sub, text)


def _normalize_text(content):
    txt = content or ''
    txt = html.unescape(txt)
    for _ in range(2):
        txt = unquote(txt)
    txt = _decode_js_escapes(txt)
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
    """加权打分判定脚本命中是否可信，替代原先的严格 AND 逻辑。"""
    if mark not in ('恶意代码混淆', '高风险脚本混淆跳转'):
        return True

    txt = (snippet or '').lower()
    score = 0

    # 混淆特征
    if any(token in txt for token in (
        'fromcharcode',
        'eval(',
        'atob(',
        'unescape(',
        'decodeuricomponent',
        'base64',
    )):
        score += 2

    # 危险操作
    if any(token in txt for token in (
        'document.write',
        'innerhtml',
        'window.location',
        'location.href',
        '<iframe',
        'display:none',
        'visibility:hidden',
        'opacity:0',
    )):
        score += 2

    # 外链或编码内容
    if bool(re.search(
        r'https?://|%[0-9a-f]{2}|&#x[0-9a-f]+;|&#\d+;',
        txt,
        re.I,
    )):
        score += 2

    # 总得分 ≥ 3 即可通过，允许只有外链+危险操作但无混淆的情况
    return score >= 3


def _match_rules_in_context(context, rules, seen, hits, max_snippet_len=300):
    """在单个上下文中匹配规则集，去重结果直接追加到 hits 列表。"""
    for pattern, mark, severity in rules:
        try:
            found = re.findall(pattern, context, re.I | re.S)
        except re.error:
            continue
        for item in found:
            snippet = item if isinstance(item, str) else ''.join(item)
            snippet = html.unescape(snippet)
            if len(snippet) > max_snippet_len:
                snippet = snippet[:max_snippet_len] + '...'
            if not _is_probably_malicious_script_hit(mark, snippet):
                continue
            key = (mark, snippet)
            if key in seen:
                continue
            seen.add(key)
            hits.append({'mark': mark, 'snippet': snippet, 'severity': int(severity or 2)})


def blacklink_find(htmltxt, rules):
    if not rules:
        return [], 'low'

    # 规则分流：包含 <script 的规则只匹配 script 标签内部，其余规则全页匹配
    script_rules = [r for r in rules if '<script' in r[0].lower()]
    general_rules = [r for r in rules if '<script' not in r[0].lower()]

    hits = []
    seen = set()

    # --- 全页规则：保持原有逻辑，在整页解码上下文中匹配 ---
    if general_rules:
        contexts = _build_contexts(htmltxt)
        for ctx in contexts:
            _match_rules_in_context(ctx, general_rules, seen, hits)

    # --- Script 类规则：提取所有 <script> 标签，逐标签独立匹配 ---
    if script_rules:
        # 从原始 HTML 中提取所有 script 标签内容
        script_tags = re.findall(r'(<script[\s\S]*?</script>)', htmltxt, re.I | re.S)
        for tag in script_tags:
            # 跳过超长 script 标签（Libra 做法，>9999 字符的多为第三方库而非恶意代码）
            if len(tag) > 9999:
                continue
            # 每个 script 标签独立走解码管道
            script_contexts = _build_contexts(tag)
            for ctx in script_contexts:
                _match_rules_in_context(ctx, script_rules, seen, hits)

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
                # 取第一条实际匹配文本作为 snippet（截断到 120 字符），
                # 比输出正则模式本身对用户更有诊断价值。
                first_match = found[0]
                snippet = first_match if isinstance(first_match, str) else ''.join(first_match)
                snippet = snippet[:120]
                hits.append({
                    'mark': mark,
                    'snippet': snippet,
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
    # 取页面头部 2000 字符 + 尾部 1000 字符做 MD5，
    # 比仅取前 3000 字符更好地区分同模板但内容不同的页面。
    head = re.sub(r'\s+', ' ', body_norm[:2000])
    tail = re.sub(r'\s+', ' ', body_norm[-1000:]) if len(body_norm) > 2000 else ''
    combined = f'{head}|{tail}'
    digest = hashlib.md5(combined.encode('utf-8', errors='ignore')).hexdigest()
    return f'{status_code}|{title}|{digest}'


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
    error_signals = ('404', 'not found', '页面不存在', '访问被拒绝', '请先登录',
                     'forbidden', 'access denied', 'unauthorized', '无权限')
    if any(k in text for k in error_signals):
        if score < 5:           # 强后门特征（score≥5）不受错误页误报影响
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

    # 并发探测所有后门路径，大幅缩短串行等待时间。
    probe_targets = [f'{base_url.rstrip("/")}{path}' for path in paths[:MAX_BACKDOOR_PROBES]]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(_http_get_text, url): url for url in probe_targets}
        for future in as_completed(future_map):
            probe_url = future_map[future]
            try:
                status_code, body = future.result()
            except Exception:
                continue
            if status_code == 0 or not body or not _should_probe_status(status_code, body):
                continue
            sig = _page_signature(status_code, body)
            template_signatures[sig] = template_signatures.get(sig, 0) + 1
            page_cache[probe_url] = (status_code, body, sig)

    # 第一遍：收集所有命中及其 score，不带二次验证
    raw_candidates = []
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
            conf = _backdoor_confidence(score)
            if conf == 'low':
                continue

            raw_candidates.append({
                'probe_url': probe_url,
                'pattern': pattern,
                'mark': mark,
                'severity': int(severity or 3),
                'score': score,
                'conf': conf,
            })

    # 按 score 降序排序，将最可疑的条目排在前面
    raw_candidates.sort(key=lambda x: x['score'], reverse=True)

    # 第二遍：对高分条目优先做二次验证 (上限 MAX_BACKDOOR_SECONDARY_CHECKS)
    for cand in raw_candidates:
        key = (cand['mark'], cand['probe_url'])
        if key in seen:
            continue
        seen.add(key)

        final_score = cand['score']
        if secondary_checks < MAX_BACKDOOR_SECONDARY_CHECKS:
            delta = _secondary_verify(cand['probe_url'], cand['pattern'])
            final_score += delta
            secondary_checks += 1

        final_conf = _backdoor_confidence(final_score)
        if final_conf == 'low':
            continue

        hits.append({
            'mark': cand['mark'],
            'snippet': f'{cand["probe_url"]} (score={final_score},conf={final_conf})',
            'severity': cand['severity'],
            'confidence': final_conf,
        })

    if not hits:
        return [], 'low'
    if any(hit.get('confidence') == 'high' for hit in hits):
        return hits, 'high'
    return hits, 'medium'
