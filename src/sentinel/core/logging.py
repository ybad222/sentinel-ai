"""Structured JSON logging with per-alert correlation (trace_id)."""

from __future__ import annotations

import logging
import sys

import structlog


def bind_trace(trace_id: str) -> None:
    structlog.contextvars.bind_contextvars(trace_id=trace_id)


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    lvl = getattr(logging, level.upper())
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=lvl)
    renderer = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=True)
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(lvl),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
