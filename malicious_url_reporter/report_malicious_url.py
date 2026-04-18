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

REPORT_DIR = Path("reports")
LOG_DIR = Path("logs")
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)


class ThreatType(str, Enum):
    PHISHING          = "phishing"
    MALWARE           = "malware"
    SPAM              = "spam"
    UNWANTED_SOFTWARE = "unwanted_software"
    RANSOMWARE        = "ransomware"
    C2                = "command_and_control"


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


@dataclass
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
    submitted_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        self.ioc_hash = hashlib.sha256(self.url.encode()).hexdigest()
        if not self.severity:
            self.severity = THREAT_SEVERITY_MAP.get(self.threat_type, Severity.HIGH)


@dataclass
class ReportResult:
    vendor: str
    success: bool
    message: str
    status_code: int | None = None
    attempts: int = 1
    duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SIEMJsonFormatter(logging.Formatter):
    """Emits log records as newline-delimited JSON for SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.getMessage(),
            "module":    record.module,
            "function":  record.funcName,
            "line":      record.lineno,
        }
        for key, val in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message", "taskName",
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
    console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%dT%H:%M:%SZ"))

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


URL_REGEX = re.compile(
    r"^(https?://)?"
    r"(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})"
    r"(:\d+)?"
    r"(/[^"]*)?$"
)


def validate_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not URL_REGEX.match(url):
        raise ValueError(f"Invalid URL format: {url!r}")
    return url


async def with_retry(coro_fn, vendor: str, logger: logging.Logger, max_retries: int = MAX_RETRIES):
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            return await coro_fn(), attempt
        except (ClientResponseError, ClientConnectorError, ServerTimeoutError, asyncio.TimeoutError) as e:
            last_exc = e
            wait = RETRY_BACKOFF_BASE ** attempt
            logger.warning(f"{vendor} attempt {attempt}/{max_retries} failed — retrying in {wait}s",
                           extra={"vendor": vendor, "attempt": attempt, "error": str(e)})
            await asyncio.sleep(wait)
        except Exception as e:
            raise e
    raise last_exc


async def _timed_result(vendor: str, coro, attempts: int) -> ReportResult:
    start = asyncio.get_event_loop().time()
    result: ReportResult = await coro
    result.duration_ms = round((asyncio.get_event_loop().time() - start) * 1000, 2)
    result.attempts = attempts
    return result


async def report_google_safe_browsing(session, req, api_key, logger):
    vendor = "Google Safe Browsing"
    async def _call():
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "soc-url-reporter", "clientVersion": "2.0.0"},
            "threatInfo": {
                "threatTypes": [req.threat_type.value.upper()],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": req.url}],
            },
        }
        async with session.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT) as resp:
            body = await resp.json()
            if resp.status == 200:
                return ReportResult(vendor, True, "Submitted successfully", resp.status)
            return ReportResult(vendor, False, str(body), resp.status)
    try:
        result, attempts = await with_retry(_call, vendor, logger)
        return await _timed_result(vendor, asyncio.coroutine(lambda: result)(), attempts)
    except Exception as e:
        return ReportResult(vendor, False, str(e))


async def report_phishtank(session, req, api_key, logger):
    vendor = "PhishTank"
    async def _call():
        endpoint = "https://www.phishtank.com/api/submit-phish/"
        payload = {"url": req.url, "app_key": api_key, "description": req.description}
        async with session.post(endpoint, data=payload, timeout=REQUEST_TIMEOUT) as resp:
            text = await resp.text()
            return ReportResult(vendor, resp.status in (200, 201), text[:200], resp.status)
    try:
        result, attempts = await with_retry(_call, vendor, logger)
        return await _timed_result(vendor, asyncio.coroutine(lambda: result)(), attempts)
    except Exception as e:
        return ReportResult(vendor, False, str(e))


async def report_virustotal(session, req, api_key, logger):
    vendor = "VirusTotal"
    async def _call():
        headers = {"x-apikey": api_key}
        async with session.post("https://www.virustotal.com/api/v3/urls", data={"url": req.url},
                                headers=headers, timeout=REQUEST_TIMEOUT) as resp:
            body = await resp.json()
            success = resp.status in (200, 201)
            analysis_id = body.get("data", {}).get("id", "")
            return ReportResult(vendor, success, f"Analysis ID: {analysis_id}" if success else str(body), resp.status)
    try:
        result, attempts = await with_retry(_call, vendor, logger)
        return await _timed_result(vendor, asyncio.coroutine(lambda: result)(), attempts)
    except Exception as e:
        return ReportResult(vendor, False, str(e))


async def report_microsoft_defender(session, req, api_key, logger):
    vendor = "Microsoft Defender"
    async def _call():
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "indicatorValue": req.url, "indicatorType": "Url", "action": "Block",
            "title": f"[SOC] Malicious URL: {req.url[:60]}", "description": req.description,
            "severity": req.severity.value, "recommendedActions": "Block and investigate",
            "externalId": req.submission_id,
        }
        async with session.post("https://api.securitycenter.microsoft.com/api/indicators",
                                json=payload, headers=headers, timeout=REQUEST_TIMEOUT) as resp:
            body = await resp.json()
            return ReportResult(vendor, resp.status in (200, 201), str(body)[:200], resp.status)
    try:
        result, attempts = await with_retry(_call, vendor, logger)
        return await _timed_result(vendor, asyncio.coroutine(lambda: result)(), attempts)
    except Exception as e:
        return ReportResult(vendor, False, str(e))


async def report_netcraft(session, req, logger):
    vendor = "Netcraft"
    async def _call():
        payload = {"urls": [{"url": req.url, "comment": req.description}], "email": req.reporter_email or ""}
        async with session.post("https://report.netcraft.com/api/v3/report/urls",
                                json=payload, timeout=REQUEST_TIMEOUT) as resp:
            body = await resp.json()
            return ReportResult(vendor, resp.status in (200, 201, 202), str(body)[:200], resp.status)
    try:
        result, attempts = await with_retry(_call, vendor, logger)
        return await _timed_result(vendor, asyncio.coroutine(lambda: result)(), attempts)
    except Exception as e:
        return ReportResult(vendor, False, str(e))


async def report_abuse_ch(session, req, api_key, logger):
    vendor = "abuse.ch URLhaus"
    async def _call():
        headers = {"Auth-Key": api_key}
        payload = {"url": req.url, "threat": req.threat_type.value, "tags": req.tags or ["malicious"]}
        async with session.post("https://urlhaus-api.abuse.ch/v1/host/",
                                json=payload, headers=headers, timeout=REQUEST_TIMEOUT) as resp:
            body = await resp.json()
            return ReportResult(vendor, resp.status == 200, str(body)[:200], resp.status)
    try:
        result, attempts = await with_retry(_call, vendor, logger)
        return await _timed_result(vendor, asyncio.coroutine(lambda: result)(), attempts)
    except Exception as e:
        return ReportResult(vendor, False, str(e))


async def report_openphish(session, req, api_key, logger):
    vendor = "OpenPhish"
    async def _call():
        headers = {"Authorization": f"Bearer {api_key}"}
        async with session.post("https://openphish.com/feed.txt",
                                json={"url": req.url, "comment": req.description},
                                headers=headers, timeout=REQUEST_TIMEOUT) as resp:
            text = await resp.text()
            return ReportResult(vendor, resp.status in (200, 201, 202), text[:200], resp.status)
    try:
        result, attempts = await with_retry(_call, vendor, logger)
        return await _timed_result(vendor, asyncio.coroutine(lambda: result)(), attempts)
    except Exception as e:
        return ReportResult(vendor, False, str(e))


async def report_to_all_vendors(req, config, logger):
    tasks = []
    async with aiohttp.ClientSession() as session:
        if key := config.get("GOOGLE_SAFE_BROWSING_API_KEY"):
            tasks.append(report_google_safe_browsing(session, req, key, logger))
        if key := config.get("PHISHTANK_API_KEY"):
            tasks.append(report_phishtank(session, req, key, logger))
        if key := config.get("VIRUSTOTAL_API_KEY"):
            tasks.append(report_virustotal(session, req, key, logger))
        if key := config.get("MICROSOFT_DEFENDER_API_KEY"):
            tasks.append(report_microsoft_defender(session, req, key, logger))
        if key := config.get("ABUSECH_API_KEY"):
            tasks.append(report_abuse_ch(session, req, key, logger))
        if key := config.get("OPENPHISH_API_KEY"):
            tasks.append(report_openphish(session, req, key, logger))
        tasks.append(report_netcraft(session, req, logger))
        if not tasks:
            logger.warning("No vendors configured.")
            return []
        raw = await asyncio.gather(*tasks, return_exceptions=True)
    return [r if not isinstance(r, Exception) else ReportResult("Unknown", False, str(r)) for r in raw]


def build_json_report(req, results):
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    avg_ms = round(sum(r.duration_ms for r in results) / len(results), 2) if results else 0
    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "submission_id": req.submission_id,
            "case_id": req.case_id,
            "analyst": req.analyst,
            "tool": "soc-url-reporter v2.0",
        },
        "ioc": {
            "url": req.url, "sha256": req.ioc_hash, "threat_type": req.threat_type.value,
            "severity": req.severity.value, "description": req.description,
            "tags": req.tags, "submitted_at": req.submitted_at,
        },
        "summary": {
            "total_vendors": len(results), "successful": len(successful), "failed": len(failed),
            "success_rate_pct": round(len(successful) / len(results) * 100, 1) if results else 0,
            "avg_response_ms": avg_ms,
        },
        "vendor_results": [asdict(r) for r in results],
    }


def write_json_report(report, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def write_csv_report(report, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["submission_id", "case_id", "analyst", "url", "sha256_ioc",
                         "threat_type", "severity", "vendor", "success",
                         "status_code", "attempts", "duration_ms", "message", "timestamp"])
        for vr in report["vendor_results"]:
            writer.writerow([
                report["report_metadata"]["submission_id"], report["report_metadata"]["case_id"],
                report["report_metadata"]["analyst"], report["ioc"]["url"], report["ioc"]["sha256"],
                report["ioc"]["threat_type"], report["ioc"]["severity"],
                vr["vendor"], vr["success"], vr["status_code"], vr["attempts"],
                vr["duration_ms"], vr["message"].replace("\n", " ")[:120], vr["timestamp"],
            ])


HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>SOC Malicious URL Report - $submission_id</title>
  <style>
    :root{--ok:#16a34a;--fail:#dc2626;--warn:#d97706;--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--border:#334155}
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}
    h1{font-size:1.6rem;font-weight:700;margin-bottom:.25rem}
    .subtitle{color:var(--muted);font-size:.9rem;margin-bottom:2rem}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:2rem}
    .card{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1.25rem}
    .card .label{font-size:.75rem;text-transform:uppercase;color:var(--muted);margin-bottom:.4rem}
    .card .value{font-size:1.5rem;font-weight:700}
    .card .value.ok{color:var(--ok)} .card .value.fail{color:var(--fail)} .card .value.warn{color:var(--warn)}
    .section{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1.5rem;margin-bottom:2rem}
    .section h2{font-size:1rem;font-weight:600;margin-bottom:1rem;color:var(--muted);text-transform:uppercase}
    .meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.75rem}
    .meta-item .key{font-size:.75rem;color:var(--muted)} .meta-item .val{font-size:.9rem;word-break:break-all}
    table{width:100%;border-collapse:collapse;font-size:.875rem}
    th{text-align:left;padding:.6rem 1rem;border-bottom:1px solid var(--border);color:var(--muted);font-size:.75rem;text-transform:uppercase}
    td{padding:.65rem 1rem;border-bottom:1px solid var(--border);vertical-align:top}
    tr:last-child td{border-bottom:none}
    .badge{display:inline-block;padding:.2rem .6rem;border-radius:.375rem;font-size:.75rem;font-weight:600}
    .badge.ok{background:#14532d;color:#86efac} .badge.fail{background:#7f1d1d;color:#fca5a5}
    .badge.sev-CRITICAL{background:#7f1d1d;color:#fca5a5} .badge.sev-HIGH{background:#78350f;color:#fcd34d}
    .badge.sev-MEDIUM{background:#1e3a5f;color:#93c5fd} .badge.sev-LOW{background:#1a2e05;color:#86efac}
    .msg{color:var(--muted);font-family:monospace;font-size:.8rem;max-width:35ch;overflow-wrap:break-word}
    footer{text-align:center;color:var(--muted);font-size:.8rem;margin-top:2rem}
    .hash{font-family:monospace;font-size:.8rem;color:var(--muted)}
  </style>
</head>
<body>
<h1>SOC Malicious URL Report</h1>
<div class="subtitle">Submission ID: $submission_id &nbsp;&middot;&nbsp; Generated: $generated_at</div>
<div class="grid">
  <div class="card"><div class="label">Vendors Reported</div><div class="value">$total_vendors</div></div>
  <div class="card"><div class="label">Successful</div><div class="value ok">$successful</div></div>
  <div class="card"><div class="label">Failed</div><div class="value $fail_class">$failed</div></div>
  <div class="card"><div class="label">Success Rate</div><div class="value $rate_class">$success_rate%</div></div>
  <div class="card"><div class="label">Avg Response</div><div class="value">$avg_ms ms</div></div>
  <div class="card"><div class="label">Severity</div><div class="value"><span class="badge sev-$severity">$severity</span></div></div>
</div>
<div class="section">
  <h2>IOC Details</h2>
  <div class="meta-grid">
    <div class="meta-item"><div class="key">Malicious URL</div><div class="val">$url</div></div>
    <div class="meta-item"><div class="key">SHA-256 (URL)</div><div class="val hash">$sha256</div></div>
    <div class="meta-item"><div class="key">Threat Type</div><div class="val">$threat_type</div></div>
    <div class="meta-item"><div class="key">Description</div><div class="val">$description</div></div>
    <div class="meta-item"><div class="key">Tags</div><div class="val">$tags</div></div>
    <div class="meta-item"><div class="key">Submitted At (UTC)</div><div class="val">$submitted_at</div></div>
  </div>
</div>
<div class="section">
  <h2>Case Metadata</h2>
  <div class="meta-grid">
    <div class="meta-item"><div class="key">Case ID</div><div class="val">$case_id</div></div>
    <div class="meta-item"><div class="key">Analyst</div><div class="val">$analyst</div></div>
    <div class="meta-item"><div class="key">Reporter Email</div><div class="val">$reporter_email</div></div>
  </div>
</div>
<div class="section">
  <h2>Vendor Results</h2>
  <table>
    <thead><tr><th>Vendor</th><th>Status</th><th>HTTP</th><th>Attempts</th><th>Duration</th><th>Message</th><th>Timestamp</th></tr></thead>
    <tbody>$vendor_rows</tbody>
  </table>
</div>
<footer>Generated by soc-url-reporter v2.0 &nbsp;&middot;&nbsp; All times UTC</footer>
</body>
</html>""")


def _vendor_row(vr):
    badge = "ok" if vr["success"] else "fail"
    label = "SUCCESS" if vr["success"] else "FAILED"
    http = vr["status_code"] or "-"
    ts = vr["timestamp"][:19].replace("T", " ")
    return (f"<tr><td>{vr['vendor']}</td>"
            f"<td><span class='badge {badge}'>{label}</span></td>"
            f"<td>{http}</td><td>{vr['attempts']}</td>"
            f"<td>{vr['duration_ms']} ms</td>"
            f"<td class='msg'>{vr['message'][:100]}</td>"
            f"<td>{ts}</td></tr>")


def write_html_report(report, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    meta = report["report_metadata"]
    ioc = report["ioc"]
    summary = report["summary"]
    failed = summary["failed"]
    rate = summary["success_rate_pct"]
    html = HTML_TEMPLATE.substitute(
        submission_id=meta["submission_id"],
        generated_at=meta["generated_at"][:19].replace("T", " ") + " UTC",
        total_vendors=summary["total_vendors"], successful=summary["successful"],
        failed=failed, fail_class="fail" if failed else "ok",
        success_rate=rate, rate_class="ok" if rate >= 80 else ("warn" if rate >= 50 else "fail"),
        avg_ms=summary["avg_response_ms"], severity=ioc["severity"],
        url=ioc["url"], sha256=ioc["sha256"], threat_type=ioc["threat_type"],
        description=ioc["description"], tags=", ".join(ioc["tags"]) or "-",
        submitted_at=ioc["submitted_at"][:19].replace("T", " ") + " UTC",
        case_id=meta.get("case_id") or "-", analyst=meta.get("analyst") or "-",
        reporter_email="-",
        vendor_rows="\n".join(_vendor_row(vr) for vr in report["vendor_results"]),
    )
    path.write_text(html, encoding="utf-8")


def print_console_summary(report):
    ioc = report["ioc"]
    summary = report["summary"]
    results = report["vendor_results"]
    meta = report["report_metadata"]
    sep = "=" * 70
    print(f"\n{sep}")
    print("  SOC MALICIOUS URL REPORT")
    print(f"  Submission : {meta['submission_id']}")
    print(f"  Case ID    : {meta.get('case_id') or '-'}")
    print(f"  Analyst    : {meta.get('analyst') or '-'}")
    print(f"  IOC        : {ioc['url']}")
    print(f"  SHA-256    : {ioc['sha256']}")
    print(f"  Threat     : {ioc['threat_type'].upper()}  |  Severity: {ioc['severity']}")
    print(sep)
    print(f"  {'VENDOR':<28} {'STATUS':<12} {'HTTP':<6} {'RETRIES':<8} {'MS'}")
    print("-" * 70)
    for r in results:
        status = "OK      " if r["success"] else "FAILED  "
        http = str(r["status_code"]) if r["status_code"] else "-"
        retries = str(r["attempts"] - 1)
        ms = f"{r['duration_ms']}ms"
        print(f"  {r['vendor']:<28} {status:<12} {http:<6} {retries:<8} {ms}")
    print(sep)
    rate = summary["success_rate_pct"]
    print(f"  Result: {summary['successful']}/{summary['total_vendors']} vendors  |  Success rate: {rate}%")
    print(sep + "\n")


def load_config(config_file=None):
    keys = [
        "GOOGLE_SAFE_BROWSING_API_KEY", "PHISHTANK_API_KEY",
        "MICROSOFT_DEFENDER_API_KEY", "VIRUSTOTAL_API_KEY",
        "ABUSECH_API_KEY", "OPENPHISH_API_KEY",
    ]
    config = {k: os.environ[k] for k in keys if k in os.environ}
    if config_file and Path(config_file).exists():
        with open(config_file) as f:
            file_cfg = json.load(f)
        config.update({k: v for k, v in file_cfg.items() if k in keys})
    return config


def main():
    parser = argparse.ArgumentParser(
        description="SOC-ready malicious URL reporter with structured logging and multi-format reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python report_malicious_url.py "https://phish.example.com" "Bank phishing page" \
      --threat-type phishing --analyst jdoe --case-id INC-2026-0042

  python report_malicious_url.py "https://malware.example.com/payload.exe" "Drops ransomware" \
      --threat-type ransomware --severity CRITICAL --tags ransomware dropper
        """,
    )
    parser.add_argument("url", help="The malicious URL to report")
    parser.add_argument("description", help="Threat description")
    parser.add_argument("--threat-type", choices=[t.value for t in ThreatType], default=ThreatType.PHISHING.value)
    parser.add_argument("--severity", choices=[s.value for s in Severity], default=None)
    parser.add_argument("--analyst", help="SOC analyst name/ID")
    parser.add_argument("--case-id", help="Incident/case ID")
    parser.add_argument("--tags", nargs="*", default=[])\
    parser.add_argument("--reporter-email")
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument("--log-dir", default="logs")
    parser.add_argument("--config", help="Path to JSON config file with API keys")
    parser.add_argument("--no-html", action="store_true")
    parser.add_argument("--no-csv", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        clean_url = validate_url(args.url)
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    threat_type = ThreatType(args.threat_type)
    severity = Severity(args.severity) if args.severity else THREAT_SEVERITY_MAP.get(threat_type, Severity.HIGH)

    req = ReportRequest(
        url=clean_url, description=args.description, threat_type=threat_type,
        severity=severity, analyst=args.analyst, case_id=args.case_id,
        tags=args.tags, reporter_email=args.reporter_email,
    )

    logger = setup_logging(Path(args.log_dir), req.submission_id)
    logger.info("Submission started", extra={
        "submission_id": req.submission_id, "case_id": req.case_id, "analyst": req.analyst,
        "url": req.url, "ioc_sha256": req.ioc_hash,
        "threat_type": req.threat_type.value, "severity": req.severity.value,
    })

    if args.dry_run:
        print(f"[DRY RUN] URL validated: {req.url}")
        print(f"[DRY RUN] Submission ID: {req.submission_id}")
        print("[DRY RUN] No submissions were made.")
        sys.exit(0)

    config = load_config(args.config)
    if not config:
        logger.warning("No API keys found - only keyless vendors (Netcraft) will run.")

    results = asyncio.run(report_to_all_vendors(req, config, logger))
    report = build_json_report(req, results)
    output_dir = Path(args.output_dir)
    ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"report_{req.submission_id[:8]}_{ts_slug}"

    json_path = output_dir / f"{base_name}.json"
    write_json_report(report, json_path)
    logger.info(f"JSON report written -> {json_path}")

    if not args.no_csv:
        csv_path = output_dir / f"{base_name}.csv"
        write_csv_report(report, csv_path)
        logger.info(f"CSV report written -> {csv_path}")

    if not args.no_html:
        html_path = output_dir / f"{base_name}.html"
        write_html_report(report, html_path)
        logger.info(f"HTML report written -> {html_path}")

    print_console_summary(report)
    logger.info("Submission complete", extra={
        "submission_id": req.submission_id,
        "total_vendors": report["summary"]["total_vendors"],
        "successful": report["summary"]["successful"],
        "success_rate_pct": report["summary"]["success_rate_pct"],
    })

    sys.exit(0 if report["summary"]["failed"] == 0 else 2)


if __name__ == "__main__":
    main()