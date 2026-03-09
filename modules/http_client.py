#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from threading import local

import requests
from requests.adapters import HTTPAdapter

from config.crawler import MAX_WORKERS, REQUEST_TIMEOUT
from config.proxies import PROXIES

requests.packages.urllib3.disable_warnings()

_thread_local = local()


def _build_session():
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=MAX_WORKERS, pool_maxsize=MAX_WORKERS * 2)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def _get_session():
    session = getattr(_thread_local, 'session', None)
    if session is None:
        session = _build_session()
        _thread_local.session = session
    return session


def http_get(url, headers=None, allow_redirects=True):
    session = _get_session()
    return session.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        verify=False,
        proxies=PROXIES,
        allow_redirects=allow_redirects,
    )
