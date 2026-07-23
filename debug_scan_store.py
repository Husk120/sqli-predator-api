import asyncio
import sys
sys.path.insert(0, '.')

from lib.store import scans

print("=== SCAN STORE DEBUG ===")
print(f"Number of scans in store: {len(scans)}")
for scan_id, scan_data in scans.items():
    print(f"\nScan ID: {scan_id}")
    print(f"  Target: {scan_data.get('target')}")
    print(f"  Status: {scan_data.get('status')}")
    print(f"  Progress: {scan_data.get('progress')}%")
    print(f"  Current Phase: {scan_data.get('current_phase')}")
    findings = scan_data.get('findings', [])
    print(f"  Findings Count: {len(findings)}")

    if findings:
        print(f"  First few findings:")
        for i, f in enumerate(findings[:3]):  # Show first 3
            print(f"    [{i}] {f.get('parameter')} via {f.get('vector')} - {f.get('detection_method')} ({f.get('severity')})")
    else:
        print("  No findings found")

    if scan_data.get('error'):
        print(f"  Error: {scan_data.get('error')}")

print("\n=== END DEBUG ===")