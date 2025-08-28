# app/core/logger.py
from __future__ import annotations

"""
MoviesNow — Logging (Loguru, production-grade)
----------------------------------------------
- Pretty console logs by default; optional JSON logs via `LOG_JSON=1`
- Request correlation: supports `request_id` (from RequestIDMiddleware)
- Intercepts stdlib/uvicorn/fastapi/starlette logs into Loguru
- Optional file sink with rotation

Env
---
LOG_LEVEL=INFO|DEBUG|WARNING|ERROR (default: INFO)
LOG_JSON=1 (enable JSON logs; pretty logs otherwise)
LOG_TO_FILE=1 (write logs/logs/app.log with rotation; default: 1)
LOG_DIR=logs
LOG_FILE=app.log
LOG_ROTATION=10 MB
APP_DEBUG=1 (enables backtrace/diagnose in console sink)
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv
from loguru import logger

# ─────────────────────────────────────────────────────────────
# ⚙️ Env
# ─────────────────────────────────────────────────────────────
load_dotenv()

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_JSON = os.getenv("LOG_JSON", "0").lower() in {"1", "true", "yes"}
APP_DEBUG = os.getenv("APP_DEBUG", "0").lower() in {"1", "true", "yes"}

LOG_TO_FILE = os.getenv("LOG_TO_FILE", "1").lower() in {"1", "true", "yes"}
LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
LOG_FILE = os.getenv("LOG_FILE", "app.log")
LOG_ROTATION = os.getenv("LOG_ROTATION", "10 MB")

# Ensure directory if file logging enabled
if LOG_TO_FILE:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    FILE_PATH = LOG_DIR / LOG_FILE

# Remove default handler
logger.remove()

# ─────────────────────────────────────────────────────────────
# 🧾 Formatters
# ─────────────────────────────────────────────────────────────
def _fmt_pretty(record):
    """
    Colorized single-line formatter with request_id support.
    """
    record["extra"]["request_id"] = record["extra"].get("request_id", "N/A")
    safe_name = record["name"].replace("<", "[").replace(">", "]")
    safe_func = record["function"].replace("<", "[").replace(">", "]")
    return (
        f"<green>{record['time']:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        f"<level>{record['level']:<8}</level> | "
        f"<cyan>{safe_name}</cyan>:<cyan>{safe_func}</cyan>:<cyan>{record['line']}</cyan> - "
        f"<level>{record['message']}</level> | request_id={record['extra']['request_id']}"
    )

def _fmt_json(record):
    """
    Structured JSON logs, safe for ingestion (Datadog, Loki, ELK).
    """
    payload: Dict[str, Any] = {
        "ts": record["time"].timestamp(),
        "time": record["time"].strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        "level": record["level"].name,
        "logger": record["name"],
        "func": record["function"],
        "line": record["line"],
        "message": record["message"],
        "request_id": record["extra"].get("request_id", "N/A"),
    }
    # Merge extra (without clobbering known keys)
    for k, v in record["extra"].items():
        if k not in payload:
            payload[k] = v
    return json.dumps(payload, ensure_ascii=False)

CONSOLE_FORMAT = _fmt_json if LOG_JSON else _fmt_pretty

# ─────────────────────────────────────────────────────────────
# 📤 Sinks
# ─────────────────────────────────────────────────────────────
# Console (application logs)
logger.add(
    sys.stdout,
    level=LOG_LEVEL,
    format=CONSOLE_FORMAT,
    enqueue=True,
    backtrace=APP_DEBUG,
    diagnose=APP_DEBUG,
)

# File sink (optional)
if LOG_TO_FILE:
    logger.add(
        str(FILE_PATH),
        rotation=LOG_ROTATION,
        level=LOG_LEVEL,
        format=_fmt_json if LOG_JSON else _fmt_pretty,
        enqueue=True,
        backtrace=False,
        diagnose=False,
    )

# Uvicorn access logs: keep simple message (already formatted by uvicorn)
logger.add(
    sys.stdout,
    format="{message}",
    level="INFO",
    filter="uvicorn.access",
    enqueue=True,
)

# ─────────────────────────────────────────────────────────────
# 🔁 Intercept stdlib logging → Loguru
# ─────────────────────────────────────────────────────────────
class InterceptHandler(logging.Handler):
    """Route standard logging records into Loguru with request_id support."""
    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        # Ensure we always have a request_id in context
        logger.bind(request_id="N/A").opt(
            depth=6, exception=record.exc_info
        ).log(level, record.getMessage())

# Patch common loggers
for name in ("uvicorn", "uvicorn.error", "fastapi", "starlette"):
    std_logger = logging.getLogger(name)
    std_logger.handlers = [InterceptHandler()]
    std_logger.setLevel(LOG_LEVEL)
    std_logger.propagate = False
