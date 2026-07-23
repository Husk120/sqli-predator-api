"""GET /api/scan/[id]/status"""

from fastapi import APIRouter
from lib.store import get_scan

router = APIRouter()


@router.get("/api/scan/{scan_id}/status")
async def get_status(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return {"error": "Scan not found"}

    return {
        "id": scan["id"],
        "status": scan["status"],
        "progress": scan["progress"],
        "current_phase": scan["current_phase"],
        "findings_count": scan.get("findings_count", 0),
        "error": scan.get("error"),
    }