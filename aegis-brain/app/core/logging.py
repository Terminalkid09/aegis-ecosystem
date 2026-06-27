import logging
import sys
import json
import uuid
import time
from contextvars import ContextVar
from typing import Any, Dict, Optional
from pythonjsonlogger import jsonlogger

correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")
request_id_var: ContextVar[str] = ContextVar("request_id", default="")

class StructuredFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        super().add_fields(log_record, record, message_dict)
        log_record["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())
        log_record["level"] = record.levelname
        log_record["logger"] = record.name
        log_record["correlation_id"] = correlation_id_var.get("")
        log_record["request_id"] = request_id_var.get("")
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = StructuredFormatter(
            "%(timestamp)s %(level)s %(logger)s %(correlation_id)s %(request_id)s %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger

def set_correlation_id(cid: str = "") -> str:
    if not cid:
        cid = str(uuid.uuid4())[:8]
    correlation_id_var.set(cid)
    return cid

def get_correlation_id() -> str:
    return correlation_id_var.get("")

def set_request_id(rid: str = "") -> str:
    if not rid:
        rid = str(uuid.uuid4())[:8]
    request_id_var.set(rid)
    return rid

def get_request_id() -> str:
    return request_id_var.get()

class LogContext:
    def __init__(self, correlation_id: str = "", request_id: str = "", **extra):
        self.correlation_id = correlation_id or str(uuid.uuid4())[:8]
        self.request_id = request_id or str(uuid.uuid4())[:8]
        self.extra = extra
        self._tokens = []

    def __enter__(self):
        self._tokens.append(correlation_id_var.set(self.correlation_id))
        self._tokens.append(request_id_var.set(self.request_id))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for token in reversed(self._tokens):
            if token:
                correlation_id_var.reset(token) if token == self._tokens[0] else request_id_var.reset(token)