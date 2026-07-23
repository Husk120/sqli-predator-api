"""POST /api/scan — Start a new scan"""

import logging
import uuid
from datetime import datetime
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, Field

from lib.store import create_scan, update_scan
from lib.engine import run_scan

router = APIRouter()
log = logging.getLogger("sqli-predator")


class ScanRequest(BaseModel):
    target_url: str = Field(..., description="Target URL to scan")
    crawl_depth: int = Field(default=1, ge=0, le=2)
    request_delay: float = Field(default=0.3, ge=0.1, le=5.0)
    timeout: int = Field(default=30, ge=5, le=60)
    test_all_headers: bool = Field(default=False)
    test_second_order: bool = Field(default=False)
    auth_cookie: str = Field(default="")
    auth_creds: str = Field(default="")


@router.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not request.target_url.startswith(("http://", "https://")):
        request.target_url = "http://" + request.target_url

    try:
        result = urlparse(request.target_url)
        if not result.netloc:
            return {"error": "Invalid target URL"}
    except:
        return {"error": "Invalid URL"}

    scan_id = uuid.uuid4().hex[:12]

    create_scan(scan_id, {
        "id": scan_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target": request.target_url,
        "status": "running",
        "progress": 0,
        "current_phase": "Starting...",
        "findings": [],
        "findings_count": 0,
        "duration_seconds": 0,
        "error": None,
        "severity_summary": {},
    })

    background_tasks.add_task(run_scan_task, scan_id, request)

    return {"id": scan_id, "status": "running"}


async def run_scan_task(scan_id: str, request: ScanRequest):
    start_time = datetime.utcnow()

    def progress(phase: str, pct: int):
        update_scan(scan_id, {"current_phase": phase, "progress": pct})

    headers = {"User-Agent": "SQLi-PREDATOR/5.0"}
    if request.auth_cookie:
        headers["Cookie"] = request.auth_cookie

    auth = None
    if request.auth_creds and ":" in request.auth_creds:
        u, p = request.auth_creds.split(":", 1)
        auth = (u, p)

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(request.timeout),
            headers=headers,
            auth=auth,
            verify=False,
            follow_redirects=True,
        ) as client:

            findings = await run_scan(client, request.target_url, {
                "crawl_depth": request.crawl_depth,
                "request_delay": request.request_delay,
                "test_all_headers": request.test_all_headers,
                "test_second_order": request.test_second_order,
            }, progress_callback=progress)

        duration = (datetime.utcnow() - start_time).total_seconds()

        severity_summary = {
            "Critical": sum(1 for f in findings if f["severity"] == "Critical"),
            "High": sum(1 for f in findings if f["severity"] == "High"),
            "Medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "Low": sum(1 for f in findings if f["severity"] == "Low"),
            "Info": sum(1 for f in findings if f["severity"] == "Info"),
        }

        update_scan(scan_id, {
            "status": "completed",
            "progress": 100,
            "current_phase": "Complete",
            "findings": findings,
            "findings_count": len(findings),
            "duration_seconds": round(duration, 2),
            "severity_summary": severity_summary,
        })

        log.info(f"Scan {scan_id}: {len(findings)} findings in {duration:.1f}s")

    except Exception as e:
        log.error(f"Scan {scan_id} failed: {e}")
        update_scan(scan_id, {"status": "failed", "error": str(e)})