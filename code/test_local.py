"""Run offline tests and retain an iwatobi input example. No Cloudflare calls."""
from pathlib import Path
import subprocess
import sys
import uuid

import bridge


def main():
    root = Path(__file__).resolve().parent
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=root)
    if result.returncode:
        return result.returncode
    output = root / "data" / ("local-test-" + uuid.uuid4().hex)
    database = output / "events.sqlite"
    key = "fixture-only-key-32-characters-long-not-for-production"
    source = root / "fixtures" / "workers.jsonl"
    first = bridge.import_logs(source, database, key)
    second = bridge.import_logs(source, database, key)
    result = bridge.export(database, output / "export")
    if first != 2 or second != 0 or result["http_events"] != 2:
        raise bridge.BridgeError("Offline smoke test failed")
    print("PASS: tests, normalization, redaction, deduplication, export")
    print(f"iwatobi input: {output / 'export' / 'access.log'}")
    print("Live Cloudflare access and iwatobi execution were not tested.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
