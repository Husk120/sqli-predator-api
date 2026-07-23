"""GET /api/scan/[id]/report"""

from fastapi import APIRouter
from lib.store import get_scan

router = APIRouter()


@router.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return {"error": "Scan not found"}

    if scan["status"] not in ("completed", "failed"):
        return {"error": "Scan not yet completed"}

    return scan