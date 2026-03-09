#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import logging
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parent.parent / 'lingjian.log'

logging.basicConfig(
    filename=str(LOG_FILE),
    format='%(asctime)s %(levelname)s %(message)s',
    filemode='a',
    level=logging.INFO,
)


def log_data(log_obj):
    logging.info(log_obj)
