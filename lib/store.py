"""In-memory scan store. Safe on Render since the process stays alive."""

scans: dict = {}

def create_scan(scan_id: str, data: dict):
    scans[scan_id] = data

def get_scan(scan_id: str):
    return scans.get(scan_id)

def update_scan(scan_id: str, updates: dict):
    if scan_id in scans:
        scans[scan_id].update(updates)

def list_scans() -> list:
    return sorted(scans.values(), key=lambda s: s.get("timestamp", ""), reverse=True)

def delete_scan(scan_id: str) -> bool:
    return scans.pop(scan_id, None) is not None
