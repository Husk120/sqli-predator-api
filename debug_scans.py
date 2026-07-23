import sys
sys.path.insert(0, '.')
from lib.store import scans

print(f"Number of scans: {len(scans)}")
for sid, s in scans.items():
    print(f"ID: {sid}")
    print(f"  target: {s.get('target')}")
    print(f"  status: {s.get('status')}")
    print(f"  progress: {s.get('progress')}")
    findings = s.get('findings', [])
    print(f"  findings count: {len(findings)}")
    if findings:
        print(f"  first finding: {findings[0]}")
    print()