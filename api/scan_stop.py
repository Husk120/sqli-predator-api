"""Stop a scan"""

from fastapi import APIRouter
from lib.store import update_scan

router = APIRouter()

@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    # Mark scan as stopped
    update_scan(scan_id, {"status": "stopped", "current_phase": "Stopped by user"})
    return {"status": "stopped"}