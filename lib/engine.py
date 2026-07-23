"""Core SQL injection detection engine."""

import asyncio
import logging
import os
import random
import time
import uuid
from datetime import datetime

import httpx

from lib.payloads import ALL_PAYLOADS
from lib.crawler import Crawler

log = logging.getLogger("sqli-predator")
DEBUG = os.getenv('DEBUG_SQLI') == '1'

SQL_ERROR_PATTERNS = {
    "MySQL": [
        "you have an error in your sql syntax", "mysql_fetch_array",
        "mysql_fetch_assoc", "mysql_num_rows", "mysql_query",
        "mysql_error", "near '", "at line 1", "duplicate entry",
        "extractvalue", "updatexml", "unknown column",
    ],
    "MSSQL": [
        "unclosed quotation mark", "incorrect syntax near",
        "microsoft ole db", "microsoft sql server",
        "conversion failed", "invalid column name",
    ],
    "Oracle": [
        "ora-", "oracle error", "oci_", "pls-", "sp2-",
        "missing keyword", "missing expression",
    ],
    "PostgreSQL": [
        "pg_query", "invalid input syntax", "relation does not exist",
        "column not found", "division by zero",
    ],
    "SQLite": [
        "unrecognized token", "no such table", "no such column",
        "sql logic error", "constraint failed",
    ],
    "Generic": [
        "sql syntax", "database error", "unclosed quote",
        "syntax error", "query failed", "warning: mysql",
        "invalid query", "odbc_",
    ],
}


def check_errors(text: str):
    lower = text.lower()
    found = []
    db_hint = "Unknown"
    for db_type, patterns in SQL_ERROR_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in lower:
                found.append(pattern)
                if db_type != "Generic" and db_hint == "Unknown":
                    db_hint = db_type
    return len(found) > 0, found, db_hint


def calc_confidence(has_err: bool, diff: float, is_time: bool):
    c = 0.0
    if has_err: c += 0.50
    if diff > 80: c += 0.30
    elif diff > 40: c += 0.20
    elif diff > 15: c += 0.10
    if is_time: c += 0.45
    return min(c, 1.0)


def severity(conf: float, has_err: bool, is_time: bool):
    if has_err and conf >= 0.7: return "Critical"
    if has_err: return "High"
    if is_time and conf >= 0.6: return "High"
    if conf >= 0.8: return "Critical"
    if conf >= 0.6: return "High"
    if conf >= 0.4: return "Medium"
    if conf >= 0.2: return "Low"
    return "Info"


def remediation():
    return [
        "Use parameterized queries (prepared statements)",
        "Implement strict input validation",
        "Disable detailed database error messages",
        "Apply least-privilege database accounts",
        "Deploy WAF with SQLi rulesets",
    ]


async def run_scan(client: httpx.AsyncClient, target_url: str, config: dict,
                   progress_callback=None):
    """Run full scan pipeline. Returns list of findings dicts."""
    findings = []

    def progress(phase: str, pct: int):
        if progress_callback:
            progress_callback(phase, pct)

    progress("Crawling target", 5)
    crawler = Crawler(client, max_depth=config.get("crawl_depth", 1))
    forms, params = await crawler.crawl(target_url)
    progress(f"Found {len(forms)} forms, {len(params)} params", 15)

    if forms:
        progress(f"Testing {len(forms)} forms", 20)
        for i, form in enumerate(forms):
            p = 20 + int((i / len(forms)) * 40)
            progress(f"Form {i+1}/{len(forms)}: {form['action'][:50]}", p)

            form_findings = await test_form(client, form, config)
            findings.extend(form_findings)

    if params and len(findings) < 20:
        progress(f"Testing {len(params)} URL parameters", 65)
        param_findings = await test_params(client, params, config)
        findings.extend(param_findings)

    if config.get("test_all_headers"):
        progress("Testing HTTP headers", 80)
        header_findings = await test_headers(client, target_url, config)
        findings.extend(header_findings)

    seen = set()
    unique = []
    for f in findings:
        key = (f.get("url", ""), f.get("parameter", ""), f.get("payload_used", "")[:40])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    progress("Complete", 100)
    return unique


async def test_form(client: httpx.AsyncClient, form: dict, config: dict) -> list:
    findings = []
    url = form["action"]
    method = form["method"]
    inputs = form["inputs"]

    if not inputs:
        return []

    try:
        if method == "POST":
            data = {i["name"]: i.get("value", "test") for i in inputs}
            resp = await client.post(url, data=data, timeout=15)
        else:
            resp = await client.get(url, timeout=15)
        if not resp:
            return []
        baseline_len = len(resp.text)
        if DEBUG:
            print(f"[DEBUG] Form test - URL: {url}, Method: {method}, Baseline length: {baseline_len}")
    except Exception as e:
        if DEBUG:
            print(f"[DEBUG] Error getting baseline for form {url}: {e}")
        return []

    for inp in inputs:
        if inp["type"] in ("submit", "button", "hidden", "file", "image"):
            continue

        param = inp["name"]
        test_payloads = ALL_PAYLOADS[:25]
        random.shuffle(test_payloads)

        if DEBUG:
            print(f"[DEBUG] Testing parameter '{param}' with {len(test_payloads)} payloads")
        threshold = float(config.get("boolean_threshold", 10.0))

        for payload in test_payloads:
            try:
                req_data = {}
                for i in inputs:
                    req_data[i["name"]] = payload["value"] if i["name"] == param else i.get("value", "test")

                start = time.time()
                if method == "POST":
                    resp = await client.post(url, data=req_data, timeout=15)
                else:
                    resp = await client.get(url, params=req_data, timeout=15)
                duration = time.time() - start

                if not resp:
                    continue

                text = resp.text
                test_len = len(text)

                has_err, sigs, db = check_errors(text)
                diff = abs(test_len - baseline_len) / max(baseline_len, 1) * 100
                is_time = payload["category"] == "time_based" and duration > 3

                if DEBUG:
                    print(f"[DEBUG] Param '{param}' | Payload: {payload['value'][:30]}... | Len: {test_len} | Diff: {diff:.2f}% | Err: {has_err} | Time: {is_time} ({duration:.2f}s) | Trigger: {has_err or diff > threshold or is_time}")

                trigger = has_err or diff > threshold or is_time
                if DEBUG:
                    print(f"[DEBUG] Param '{param}' | Payload: {payload['value'][:30]}... | Len: {test_len} | Diff: {diff:.2f}% | Err: {has_err} | Time: {is_time} ({duration:.2f}s) | Trigger: {trigger}")

                if trigger:
                    conf = calc_confidence(has_err, diff, is_time)
                    findings.append({
                        "id": uuid.uuid4().hex[:8],
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "url": url,
                        "parameter": param,
                        "vector": method,
                        "detection_method": "ERROR_BASED" if has_err else ("TIME_BASED" if is_time else "BOOLEAN_BASED"),
                        "payload_used": payload["value"],
                        "db_type_hint": db,
                        "confidence": round(conf, 4),
                        "severity": severity(conf, has_err, is_time),
                        "cvss_score": round(conf * 10, 2),
                        "has_sql_errors": has_err,
                        "error_signatures": sigs[:5],
                        "response_difference_pct": round(diff, 2),
                        "description": f"SQLi via parameter '{param}' ({payload['category']})",
                        "remediation": remediation(),
                    })
                    if DEBUG:
                        print(f"[DETECTED] SQLi found for param '{param}' with payload '{payload['value'][:30]}...'")

                await asyncio.sleep(config.get("request_delay", 0.3))
            except Exception as e:
                if DEBUG:
                    print(f"[DEBUG] Error testing payload {payload['value']}: {e}")
                continue

    return findings


async def test_params(client: httpx.AsyncClient, params: list, config: dict) -> list:
    findings = []
    threshold = float(config.get("boolean_threshold", 10.0))
    for param in params:
        url = param["base_url"]
        name = param["name"]
        value = param["value"]

        try:
            resp = await client.get(url, params={name: value}, timeout=15)
            if not resp:
                continue
            bl = len(resp.text)
            if DEBUG:
                print(f"[DEBUG] Param test - URL: {url}, Param: {name}, Baseline length: {bl}")
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] Error getting baseline for param {name} at {url}: {e}")
            continue

        for payload in ALL_PAYLOADS[:15]:
            try:
                resp = await client.get(url, params={name: payload["value"]}, timeout=15)
                if not resp:
                    continue

                tl = len(resp.text)
                dur = resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0
                has_err, sigs, db = check_errors(resp.text)
                diff = abs(tl - bl) / max(bl, 1) * 100
                is_time = payload["category"] == "time_based" and dur > 3

                if DEBUG:
                    print(f"[DEBUG] Param '{name}' | Payload: {payload['value'][:30]}... | Len: {tl} | Diff: {diff:.2f}% | Err: {has_err} | Time: {is_time} ({dur:.2f}s) | Trigger: {has_err or diff > threshold or is_time}")

                trigger = has_err or diff > threshold or is_time
                if DEBUG:
                    print(f"[DEBUG] Param '{name}' | Payload: {payload['value'][:30]}... | Len: {tl} | Diff: {diff:.2f}% | Err: {has_err} | Time: {is_time} ({dur:.2f}s) | Trigger: {trigger}")

                if trigger:
                    conf = calc_confidence(has_err, diff, is_time)
                    findings.append({
                        "id": uuid.uuid4().hex[:8],
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "url": url, "parameter": name, "vector": "GET",
                        "detection_method": "ERROR_BASED" if has_err else ("TIME_BASED" if is_time else "BOOLEAN_BASED"),
                        "payload_used": payload["value"], "db_type_hint": db,
                        "confidence": round(conf, 4),
                        "severity": severity(conf, has_err, is_time),
                        "cvss_score": round(conf * 10, 2),
                        "has_sql_errors": has_err, "error_signatures": sigs[:5],
                        "response_difference_pct": round(diff, 2),
                        "description": f"SQLi via URL parameter '{name}'",
                        "remediation": remediation(),
                    })
                    if DEBUG:
                        print(f"[DETECTED] SQLi found for param '{name}' with payload '{payload['value'][:30]}...'")

                await asyncio.sleep(config.get("request_delay", 0.3))
            except Exception as e:
                if DEBUG:
                    print(f"[DEBUG] Error testing payload {payload['value']} for param {name}: {e}")
                continue

    return findings


async def test_headers(client: httpx.AsyncClient, target_url: str, config: dict) -> list:
    findings = []
    tests = {
        "User-Agent": ["' OR SLEEP(3) -- ", "' OR 1=1 -- "],
        "Referer": ["' OR SLEEP(3) -- ", "' OR 1=1 -- "],
        "X-Forwarded-For": ["' OR SLEEP(3) -- ", "' OR 1=1 -- "],
    }

    try:
        resp = await client.get(target_url, timeout=10)
        bl = len(resp.text) if resp else 0
    except:
        bl = 0

    threshold = float(config.get("boolean_threshold", 10.0))

    for header, payloads in tests.items():
        for payload in payloads:
            try:
                resp = await client.get(target_url, headers={header: payload}, timeout=10)
                if not resp: continue
                tl = len(resp.text)
                diff = abs(tl - bl) / max(bl, 1) * 100
                has_err, sigs, db = check_errors(resp.text)
                if has_err or diff > threshold:
                    findings.append({
                        "id": uuid.uuid4().hex[:8],
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "url": target_url, "parameter": header, "vector": "HEADER",
                        "detection_method": "HEADER_INJECTION",
                        "payload_used": payload, "db_type_hint": db,
                        "confidence": 0.5, "severity": "Medium", "cvss_score": 5.0,
                        "has_sql_errors": has_err, "error_signatures": sigs[:5],
                        "response_difference_pct": round(diff, 2),
                        "description": f"SQLi via HTTP header '{header}'",
                        "remediation": remediation(),
                    })
                await asyncio.sleep(0.2)
            except:
                continue

    return findings