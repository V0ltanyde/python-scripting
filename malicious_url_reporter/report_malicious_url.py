#!/usr/bin/env python3
"""
Malicious URL Reporter — SOC Edition
Submits malicious URLs to multiple security vendor reporting endpoints.
Produces structured audit logs and multi-format reports for SIEM ingestion.
"""

import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import re
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from string import Template

import aiohttp
from aiohttp import ClientResponseError, ClientConnectorError, ServerTimeoutError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPORT_DIR = Path("reports")
LOG_DIR = Path("logs")
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)


# ---------------------------------------------------------------------------
# Enums & Dataclasses
# ---------------------------------------------------------------------------

class ThreatType(str, Enum):
    PHISHING        = "phishing"
    MALWARE         = "malware"
    SPAM            = "spam"
    UNWANTED_SOFTWARE = "unwanted_software"
    RANSOMWARE      = "ransomware"
    C2              = "command_and_control"


class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


THREAT_SEVERITY_MAP = {
    ThreatType.PHISHING:          Severity.HIGH,
    ThreatType.MALWARE:           Severity.CRITICAL,
    ThreatType.SPAM:              Severity.LOW,
    ThreatType.UNWANTED_SOFTWARE: Severity.MEDIUM,
    ThreatType.RANSOMWARE:        Severity.CRITICAL,
    ThreatType.C2:                Severity.CRITICAL,
}


dataclass
class ReportRequest:
    url: str
    description: str
    threat_type: ThreatType
    reporter_email: str | None = None
    analyst: str | None = None
    case_id: str | None = None
    severity: Severity = Severity.HIGH
    tags: list[str] = field(default_factory=list)
    ioc_hash: str = field(init=False)
    submission_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    submitted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self):
        self.ioc_hash = hashlib.sha256(self.url.encode()).hexdigest()
        if not self.severity:
            self.severity = THREAT_SEVERITY_MAP.get(self.threat_type, Severity.HIGH)


dataclass
class ReportResult:
    vendor: str
    success: bool
    message: str
    status_code: int | None = None
    attempts: int = 1
    duration_ms: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Structured JSON Logger (SIEM-compatible)
# ---------------------------------------------------------------------------

class SIEMJsonFormatter(logging.Formatter):
    """Emits log records as newline-delimited JSON for SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "level":       record.levelname,
            "logger":      record.name,
            "message":     record.getMessage(),
            "module":      record.module,
            "function":    record.funcName,
            "line":        record.lineno,
        }
        for key, val in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            }:
                log_entry[key] = val
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def setup_logging(log_dir: Path, submission_id: str) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("url_reporter")
    logger.setLevel(logging.DEBUG)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(
        logging.Formatter("%(__class__.__name__) - __main__ - %(asctime)s - [%(levelname)s] %(message)s")
    )

    log_file = log_dir / f"submission_{submission_id}.jsonl"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(SIEMJsonFormatter())

    audit_handler = logging.FileHandler(log_dir / "audit.jsonl")
    audit_handler.setLevel(logging.INFO)
    audit_handler.setFormatter(SIEMJsonFormatter())

    logger.addHandler(console)
    logger.addHandler(file_handler)
    logger.addHandler(audit_handler)
    return logger

# **[TRUNCATED FOR BREVITY]**
