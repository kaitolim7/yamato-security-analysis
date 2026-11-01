"""Check exported TSV, then run a synthetic parser probe and a real-log scan."""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from bridge import BridgeError, safe_path

ROOT = Path(__file__).resolve().parent
PROBE_ID = "b7525c7a-e2cb-4997-97d3-3e717a3bcb8f"
LINE = re.compile(r"^(?P<timestamp>[^\t]+)\t(?P<client_hash>[^\t]+)\t(?P<request_method>[^\t]+)\t(?P<request_uri>[^\t]+)\t(?P<status>\d{3})$")


def preflight(filename: Path) -> dict:
    valid = invalid = unknown_clients = 0
    with safe_path(filename).open(encoding="utf-8-sig") as handle:
        for raw in handle:
            match = LINE.fullmatch(raw.rstrip("\r\n"))
            if not match:
                invalid += 1
                continue
            try:
                when = datetime.fromisoformat(match["timestamp"].replace("Z", "+00:00"))
                if when.tzinfo is None or not 100 <= int(match["status"]) <= 599:
                    raise ValueError
                if not match["request_uri"].startswith("/"):
                    raise ValueError
            except ValueError:
                invalid += 1
                continue
            valid += 1
            unknown_clients += int(match["client_hash"] == "-")
    return {"valid_lines": valid, "invalid_lines": invalid, "unknown_client_lines": unknown_clients}


def engine(exe: Path, source: Path, rules: Path, destination: Path) -> int:
    # Capture CLI output: timeline details may contain real request paths.
    args = [str(exe), "dfir-timeline", "-f", str(source), "-r", str(rules),
            "--custom-formats", str(ROOT / "iwatobi-formats.yaml"), "--log-format", "cloudflare-bridge",
            "-U", "-s", "-p", "verbose", "-o", str(destination), "-t", "jsonl", "-q", "-K"]
    try:
        result = subprocess.run(args, cwd=exe.parent, capture_output=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise BridgeError("iwatobi timed out after 300 seconds") from None
    return result.returncode


def timeline(filename: Path) -> list[dict]:
    if not filename.is_file():
        raise BridgeError("iwatobi did not create the expected JSONL output")
    with filename.open(encoding="utf-8-sig") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise BridgeError("Unexpected iwatobi JSONL structure")
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--iwatobi", help="Full path to the official Windows executable")
    parser.add_argument("--rules", help="Default: rules folder beside the executable")
    args = parser.parse_args(argv)
    report = {"iwatobi_verified": False, "real_log_scan_completed": False}
    try:
        source = safe_path(args.input).resolve()
        report.update(preflight(source))
        if not report["valid_lines"] or report["invalid_lines"]:
            raise BridgeError("Input must contain valid lines and zero invalid lines")
        candidate = args.iwatobi or shutil.which("iwatobi")
        if not candidate:
            report["status"] = "input_format_checked_iwatobi_not_installed"
            print(json.dumps(report, indent=2))
            return 2
        exe = safe_path(candidate).resolve()
        if not exe.is_file():
            raise BridgeError("iwatobi executable not found")
        rules = safe_path(args.rules).resolve() if args.rules else exe.parent / "rules"
        if not rules.is_dir():
            raise BridgeError("Rules folder missing; extract the full official release package")
        run = ROOT / "data" / ("iwatobi-check-" + uuid.uuid4().hex)
        probe = run / "probe"
        probe.mkdir(parents=True)
        probe_input = probe / "access.log"
        probe_input.write_text("2026-10-31T00:00:00.000Z\tfixture-client\tPOST\t/bridge-parser-probe\t401\n", encoding="utf-8")
        probe_rules = probe / "rules"
        probe_rules.mkdir()
        (probe_rules / "parser-probe.yml").write_text(
            f"title: Bridge Parser Probe - Synthetic Test Only\nid: {PROBE_ID}\nstatus: test\n"
            "description: Confirms field mapping using synthetic data, not an attack detection.\n"
            "author: KADAI INFO\ndate: 2026-10-31\nlogsource:\n  category: webserver\n"
            "detection:\n  selection:\n    cs-method: POST\n    cs-uri-stem: /bridge-parser-probe\n"
            "    sc-status: 401\n  condition: selection\nlevel: informational\n", encoding="utf-8")
        report["probe_exit_code"] = engine(exe, probe_input, probe_rules, probe / "timeline")
        if report["probe_exit_code"] != 0:
            raise BridgeError("iwatobi parser probe failed; check CLI version/custom format compatibility")
        probe_rows = timeline(probe / "timeline.jsonl")
        if not any(row.get("RuleID") == PROBE_ID for row in probe_rows):
            raise BridgeError("Synthetic probe rule did not match; parser compatibility is not verified")
        report["iwatobi_verified"] = True
        # A second scan with a broad test-only rule checks that every real line maps correctly.
        coverage = run / "coverage-rules"
        coverage.mkdir()
        (coverage / "coverage.yml").write_text(
            "title: Bridge HTTP Coverage - Not An Attack Alert\n"
            "id: e9e65e18-c088-4807-b324-a6ea9bc48cb2\nstatus: test\n"
            "logsource:\n  category: webserver\ndetection:\n  selection:\n"
            "    sc-status|re: '^[1-5][0-9]{2}$'\n  condition: selection\nlevel: informational\n", encoding="utf-8")
        report["coverage_exit_code"] = engine(exe, source, coverage, run / "coverage")
        if report["coverage_exit_code"] != 0:
            raise BridgeError("Real-log coverage scan failed")
        coverage_rows = timeline(run / "coverage.jsonl")
        report["coverage_matched_lines"] = sum(row.get("RuleID") == "e9e65e18-c088-4807-b324-a6ea9bc48cb2" for row in coverage_rows)
        if report["coverage_matched_lines"] != report["valid_lines"]:
            raise BridgeError("iwatobi did not match every input line; investigate skipped lines")
        report["scan_exit_code"] = engine(exe, source, rules, run / "detections")
        if report["scan_exit_code"] != 0:
            raise BridgeError("iwatobi real-log rule scan failed")
        report["detection_rows"] = len(timeline(run / "detections.jsonl"))
        report.update(status="iwatobi_input_verified", real_log_scan_completed=True, output=str(run),
                      note="Probe/coverage matches are test-only. Detection matches are not proof of compromise.")
        (run / "verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0
    except (BridgeError, OSError, ValueError) as exc:
        report["status"] = "verification_failed"
        report["error"] = str(exc) if isinstance(exc, BridgeError) else type(exc).__name__
        print(json.dumps(report, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
