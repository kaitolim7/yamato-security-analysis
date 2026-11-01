"""Cloudflare Workers API -> sanitized SQLite -> iwatobi input (stdlib only)."""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

UTC = timezone.utc
SCHEMA = "kadaiinfo-workers-v1"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


class BridgeError(Exception):
    """Safe message to display; never include raw API bodies or secret values."""


def safe_path(value: str | Path) -> Path:
    path = Path(value)
    # Check both lexical and resolved components so a symlink cannot target dotenv.
    if any(p.lower() == ".env" or p.lower().startswith(".env.") for p in path.parts):
        raise BridgeError("Protected dotenv path")
    for candidate in (path.resolve(),):
        if any(p.lower() == ".env" or p.lower().startswith(".env.") for p in candidate.parts):
            raise BridgeError("Protected dotenv path")
    return path


def load_config(filename: str) -> dict:
    with safe_path(filename).open(encoding="utf-8-sig") as handle:
        cfg = json.load(handle)
    required = {"account_id", "worker", "database", "lookback_minutes", "overlap_minutes", "delay_seconds"}
    if not isinstance(cfg, dict) or set(cfg) != required:
        raise BridgeError("Config must contain exactly the keys in config.example.json")
    if not isinstance(cfg["account_id"], str) or not re.fullmatch(r"[0-9a-fA-F]{32}", cfg["account_id"]):
        raise BridgeError("Set a valid 32-character Account ID in config.local.json")
    if not isinstance(cfg["worker"], str) or not cfg["worker"].strip():
        raise BridgeError("Worker name is required")
    for name, low, high in (("lookback_minutes", 1, 1440), ("overlap_minutes", 0, 1440), ("delay_seconds", 0, 86400)):
        if type(cfg[name]) is not int or not low <= cfg[name] <= high:
            raise BridgeError(f"Invalid config field: {name}")
    if not isinstance(cfg["database"], str) or not cfg["database"]:
        raise BridgeError("Database path is required")
    safe_path(cfg["database"])
    return cfg


def secret(name: str, prompt: bool = False) -> str:
    value = os.environ.get(name, "")
    if not value and prompt:
        value = getpass.getpass(f"{name} (not saved): ")
    minimum = 32 if name == "CF_LOG_HMAC_KEY" else 1
    if len(value) < minimum:
        raise BridgeError(f"{name} is required ({minimum}+ characters)")
    return value


def dig(value, *keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def timestamp(value) -> str:
    try:
        if type(value) is int:
            dt = datetime.fromtimestamp(value / 1000, UTC)
        elif isinstance(value, str):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                raise ValueError("Timezone required")
        else:
            raise ValueError("Unsupported timestamp")
        return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        raise BridgeError("Missing or invalid event timestamp") from None


def request_path(value: str) -> str:
    try:
        # urlsplit preserves dot segments and encoded path traversal evidence.
        if any(ord(c) < 32 for c in value):
            raise ValueError("Control character")
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid HTTP URL")
        return parsed.path or "/"
    except (ValueError, TypeError):
        raise BridgeError("Invalid request URL") from None


def normalize(row: dict, key: str) -> dict:
    event_id = dig(row, "$metadata", "id")
    if not isinstance(event_id, str) or not event_id:
        raise BridgeError("Missing $metadata.id")
    when = row.get("timestamp", dig(row, "$metadata", "timestamp"))
    request = (dig(row, "$workers", "event", "request")
               or dig(row, "source", "$workers", "event", "request")
               or dig(row, "source", "request") or {})
    response = (dig(row, "$workers", "event", "response")
                or dig(row, "source", "$workers", "event", "response")
                or dig(row, "source", "response") or {})
    if not isinstance(request, dict) or not isinstance(response, dict):
        raise BridgeError("Invalid HTTP event structure")
    headers = request.get("headers", {})
    ip = next((v for k, v in headers.items() if k.lower() == "cf-connecting-ip"), None) if isinstance(headers, dict) else None
    method = request.get("method")
    status = response.get("status")
    # Invocation metadata can supply HTTP fields even when source is plain text.
    if method is None:
        method = dig(row, "$metadata", "method")
    if status is None:
        status = dig(row, "$metadata", "statusCode")
    url = request.get("url") or dig(row, "$metadata", "url")
    return {
        "schema_version": SCHEMA, "event_id": event_id, "timestamp": timestamp(when),
        "method": method if isinstance(method, str) else None,
        "path": request_path(url) if isinstance(url, str) else None,
        "status": status if type(status) is int and 100 <= status <= 599 else None,
        "client_hash": hmac.new(key.encode(), ip.encode(), hashlib.sha256).hexdigest() if isinstance(ip, str) and ip else None,
    }


def connect(database: str | Path) -> sqlite3.Connection:
    path = safe_path(database)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5)
    db.executescript("""CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, event TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS checkpoints(scope TEXT PRIMARY KEY, until_ms INTEGER NOT NULL);""")
    return db


def save(db: sqlite3.Connection, event: dict) -> int:
    return db.execute("INSERT OR IGNORE INTO events VALUES (?, ?)",
                      (event["event_id"], json.dumps(event, ensure_ascii=False))).rowcount


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post_json(url: str, token: str, payload: dict, *, opener=None, sleep=time.sleep) -> dict:
    opener = opener or build_opener(NoRedirect())
    request = Request(url, data=json.dumps(payload).encode(), method="POST",
                      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    for attempt in range(4):
        try:
            with opener.open(request, timeout=60) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise BridgeError("API response exceeds safety limit; narrow time window")
            result = json.loads(body)
            if not isinstance(result, dict):
                raise BridgeError("Invalid API response structure")
            return result
        except HTTPError as exc:
            status = exc.code
            exc.close()
            if status != 429 and not 500 <= status < 600:
                raise BridgeError(f"Cloudflare HTTP {status}; check token permissions and Account ID") from None
            if attempt == 3:
                raise BridgeError(f"Cloudflare HTTP {status}; retry limit exceeded") from None
        except (URLError, TimeoutError, OSError):
            if attempt == 3:
                raise BridgeError("Cloudflare network request failed; retry limit exceeded") from None
        except (ValueError, UnicodeError):
            raise BridgeError("Invalid API JSON") from None
        sleep(2 ** attempt)
    raise BridgeError("Retry limit exceeded")


def query_events(cfg: dict, token: str, start: int, until: int, *, limit=2000, cursor=None, send=post_json) -> list:
    payload = {
        "queryId": "kadaiinfo-log-bridge", "timeframe": {"from": start, "to": until},
        "view": "events", "dry": True, "limit": limit,
        "parameters": {"datasets": [], "filterCombination": "and", "filters": [
            {"key": "$metadata.service", "operation": "eq", "type": "string", "value": cfg["worker"]}]},
    }
    if cursor:
        payload.update(offset=cursor, offsetDirection="next")
    url = f'https://api.cloudflare.com/client/v4/accounts/{cfg["account_id"]}/workers/observability/telemetry/query'
    envelope = send(url, token, payload)
    if envelope.get("success") is not True:
        raise BridgeError("Cloudflare API reported failure; check Account ID, token permissions and query fields")
    result = envelope.get("result", {})
    if not isinstance(result, dict):
        raise BridgeError("Invalid API result")
    abr = dig(result, "statistics", "abr_level")
    if isinstance(abr, (int, float)) and abr > 1:
        raise BridgeError("Query sampled; narrow time window before retrying")
    state = dig(result, "run", "status")
    if state and state != "COMPLETED":
        raise BridgeError("Query not completed; retry this window")
    rows = dig(result, "events", "events")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise BridgeError("Missing or invalid events array; checkpoint not updated")
    return rows


def diagnose(cfg: dict, token: str, *, send=post_json, now_ms=None) -> dict:
    """One real query, no DB writes and no raw event values in the report."""
    until = (now_ms if now_ms is not None else time.time_ns() // 1_000_000) - cfg["delay_seconds"] * 1000
    start = until - cfg["lookback_minutes"] * 60_000
    rows = query_events(cfg, token, start, until, limit=5, send=send)
    normalized = usable = observed = 0
    missing = {k: 0 for k in ("method", "path", "status", "client_hash")}
    for row in rows:
        names = (dig(row, "$metadata", "service"), dig(row, "$workers", "scriptName"),
                 dig(row, "source", "$workers", "scriptName"))
        observed += int(cfg["worker"] in names)
        try:
            event = normalize(row, "diagnostic-ephemeral-key-not-saved")
        except BridgeError:
            continue
        normalized += 1
        for k in missing:
            missing[k] += int(event.get(k) is None)
        usable += int(all(event.get(k) is not None for k in ("method", "path", "status")))
    if not rows:
        status = "api_reachable_no_events"
    elif usable:
        status = "events_received_http_fields_available"
    else:
        status = "events_received_adapter_or_logging_check_required"
    return {"status": status, "api_response_received": True, "sample_events_received": len(rows),
            "normalizable_events": normalized, "http_events": usable, "worker_name_observed_events": observed,
            "missing_fields_in_normalizable_events": missing, "from_ms": start, "to_ms": until,
            "database_modified": False, "iwatobi_verified": False}


def setup_config(filename: str, account: str, worker: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{32}", account):
        raise BridgeError("Account ID must be 32 hexadecimal characters (not the account name)")
    if not worker.strip():
        raise BridgeError("Worker name is required")
    cfg = {"account_id": account, "worker": worker, "database": "data/events.sqlite",
           "lookback_minutes": 15, "overlap_minutes": 5, "delay_seconds": 60}
    with safe_path(filename).open("x", encoding="utf-8") as handle:
        json.dump(cfg, handle, indent=2)
        handle.write("\n")


def fetch(cfg: dict, token: str, key: str, *, send=post_json, now_ms: int | None = None) -> dict:
    until = (now_ms if now_ms is not None else time.time_ns() // 1_000_000) - cfg["delay_seconds"] * 1000
    scope = f'{cfg["account_id"]}:{cfg["worker"]}'
    with closing(connect(cfg["database"])) as db, db:
        # Serialize collectors sharing this DB, including checkpoint reads.
        db.execute("BEGIN IMMEDIATE")
        previous = db.execute("SELECT until_ms FROM checkpoints WHERE scope=?", (scope,)).fetchone()
        if previous and until <= previous[0]:
            raise BridgeError("No new time window; check clock or polling interval")
        start = previous[0] - cfg["overlap_minutes"] * 60_000 if previous else until - cfg["lookback_minutes"] * 60_000
        # Bound a restart catch-up batch to avoid one unbounded API query.
        until = min(until, start + cfg["lookback_minutes"] * 60_000) if previous else until
        if previous and until <= previous[0]:
            raise BridgeError("lookback_minutes must exceed overlap_minutes")
        cursor = None
        cursors = set()
        stored = received = 0
        for _ in range(10_000):
            rows = query_events(cfg, token, start, until, cursor=cursor, send=send)
            if not rows:
                db.execute("INSERT INTO checkpoints VALUES (?, ?) ON CONFLICT(scope) DO UPDATE SET until_ms=excluded.until_ms", (scope, until))
                return {"received": received, "inserted": stored, "from_ms": start, "to_ms": until}
            for row in rows:
                if not isinstance(row, dict):
                    raise BridgeError("Invalid event object; checkpoint not updated")
                stored += save(db, normalize(row, key))
                received += 1
            cursor = dig(rows[-1], "$metadata", "id")
            if cursor in cursors:
                raise BridgeError("Repeated pagination cursor; transaction rolled back")
            cursors.add(cursor)
        raise BridgeError("Page safety limit reached; checkpoint not updated")


def import_logs(filename: str | Path, database: str | Path, key: str) -> int:
    count = 0
    with safe_path(filename).open(encoding="utf-8-sig") as handle, closing(connect(database)) as db, db:
        for number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise BridgeError("Invalid event object")
                count += save(db, normalize(row, key))
            except (ValueError, BridgeError):
                raise BridgeError(f"Invalid event on line {number}; import rolled back") from None
    return count


def clean(value: str) -> str:
    return "".join("_" if ord(c) < 32 or ord(c) == 127 or c == '"' else c for c in value)


def export(database: str | Path, output: str | Path, *, start_ms=None, end_ms=None) -> dict:
    source, out = safe_path(database), safe_path(output)
    if out.exists():
        raise BridgeError("Output exists; choose a new directory")
    out.parent.mkdir(parents=True, exist_ok=True)
    partial = out.with_name(out.name + ".partial")
    partial.mkdir()  # Exclusive creation; failed outputs remain distinguishable.
    exported = skipped = 0
    with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        with (partial / "events.jsonl").open("x", encoding="utf-8", newline="\n") as jsonl, \
             (partial / "access.log").open("x", encoding="utf-8", newline="\n") as access:
            sql = "SELECT event FROM events"
            values = []
            if start_ms is not None or end_ms is not None:
                if start_ms is None or end_ms is None or start_ms >= end_ms:
                    raise BridgeError("A valid start/end range is required")
                sql += " WHERE json_extract(event,'$.timestamp') >= ? AND json_extract(event,'$.timestamp') < ?"
                values = [timestamp(start_ms), timestamp(end_ms)]
            sql += " ORDER BY json_extract(event,'$.timestamp'), id"
            for (raw,) in db.execute(sql, values):
                event = json.loads(raw)
                jsonl.write(raw + "\n")
                if all(event.get(k) is not None for k in ("method", "path", "status")):
                    fields = (event["timestamp"], event.get("client_hash") or "-", event["method"], event["path"], str(event["status"]))
                    access.write("\t".join(clean(f) for f in fields) + "\n")
                    exported += 1
                else:
                    skipped += 1
            for handle in (jsonl, access):
                handle.flush()
                os.fsync(handle.fileno())
    partial.rename(out)
    return {"http_events": exported, "non_http_events": skipped}


def analysis_paths(executable: str, rules: str | None = None) -> tuple[Path, Path]:
    exe = safe_path(executable).resolve()
    rule_dir = safe_path(rules).resolve() if rules else exe.parent / "rules"
    if not exe.is_file():
        raise BridgeError("iwatobi executable not found")
    if not rule_dir.is_dir():
        raise BridgeError("iwatobi rules directory not found")
    return exe, rule_dir


def analyze(filename: str | Path, executable: str, rules: str | None = None,
            output: str | Path | None = None, timeout: int = 300, *, run=None,
            result_scope="full_snapshot_not_incremental") -> dict:
    """Run iwatobi without forwarding API credentials or printing event details."""
    exe, rule_dir = analysis_paths(executable, rules)
    source = safe_path(filename).resolve()
    if not source.is_file():
        raise BridgeError("Analysis input not found")
    formats = Path(__file__).resolve().parent / "iwatobi-formats.yaml"
    if not formats.is_file():
        raise BridgeError("iwatobi custom format definition not found")
    if timeout <= 0:
        raise BridgeError("Analysis timeout must be positive")
    destination = safe_path(output).resolve() if output else source.parent / ("analysis-" + uuid.uuid4().hex)
    destination.mkdir(parents=True, exist_ok=False)
    report = {"analysis_status": "pending", "input": str(source), "output": str(destination),
              "iwatobi_exit_code": None, "detection_rows": None,
              "result_scope": result_scope}
    report_path = destination / "analysis.json"
    try:
        with source.open(encoding="utf-8-sig") as handle:
            report["input_lines"] = sum(1 for line in handle if line.strip())
        if report["input_lines"] == 0:
            report.update(analysis_status="skipped_no_http_events", detection_rows=0)
            return report
        args = [str(exe), "dfir-timeline", "-f", str(source), "-r", str(rule_dir),
                "--custom-formats", str(formats), "--log-format", "cloudflare-bridge",
                "-U", "-s", "-p", "verbose", "-o", str(destination / "detections"),
                "-t", "jsonl", "-q", "-K"]
        # Authentication is for the collector only, never the child log analyzer.
        env = {name: value for name, value in os.environ.items()
               if name.upper() not in ("CF_API_TOKEN", "CF_LOG_HMAC_KEY")}
        result = (run or subprocess.run)(args, cwd=exe.parent, env=env, capture_output=True, timeout=timeout)
        report["iwatobi_exit_code"] = result.returncode
        if result.returncode != 0:
            raise BridgeError("iwatobi failed; acquisition data retained for analysis retry")
        timeline_file = destination / "detections.jsonl"
        if not timeline_file.is_file():
            raise BridgeError("iwatobi produced no detections.jsonl; analysis is not confirmed")
        count = 0
        with timeline_file.open(encoding="utf-8-sig") as handle:
            for line in handle:
                if not line.strip():
                    continue
                if not isinstance(json.loads(line), dict):
                    raise BridgeError("Unexpected iwatobi timeline structure")
                count += 1
        report.update(analysis_status="completed", detection_rows=count)
        return report
    except subprocess.TimeoutExpired:
        report.update(analysis_status="failed", error="iwatobi timed out; input retained")
        raise BridgeError(report["error"]) from None
    except (BridgeError, OSError, ValueError) as exc:
        report.update(analysis_status="failed", error=str(exc) if isinstance(exc, BridgeError) else type(exc).__name__)
        raise BridgeError(report["error"]) from None
    finally:
        with report_path.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    p = commands.add_parser("setup", help="Create config.local.json interactively (never overwrite)")
    p.add_argument("--config", default="config.local.json")
    p.add_argument("--worker", default="kadaiinfo-web")
    p = commands.add_parser("diagnose", help="Query Cloudflare without storing raw logs or changing checkpoints")
    p.add_argument("--config", required=True)
    p.add_argument("--prompt-secrets", action="store_true")
    for name in ("fetch", "collect"):
        p = commands.add_parser(name)
        p.add_argument("--config", required=True)
        p.add_argument("--prompt-secrets", action="store_true")
        if name == "collect":
            p.add_argument("--output", default="data/iwatobi")
            p.add_argument("--interval-seconds", type=int, default=300)
            p.add_argument("--cycles", type=int, default=1, help="0: keep running until Ctrl+C")
            p.add_argument("--iwatobi", help="Run this executable after every successful export")
            p.add_argument("--rules", help="Default: rules folder beside the iwatobi executable")
            p.add_argument("--analysis-timeout", type=int, default=300)
    p = commands.add_parser("analyze", help="Analyze an existing access.log without calling Cloudflare")
    p.add_argument("--input", required=True)
    p.add_argument("--iwatobi", required=True)
    p.add_argument("--rules")
    p.add_argument("--output")
    p.add_argument("--analysis-timeout", type=int, default=300)
    p = commands.add_parser("import")
    p.add_argument("--input", required=True)
    p.add_argument("--database", required=True)
    p = commands.add_parser("export")
    p.add_argument("--database", required=True)
    p.add_argument("--output", required=True)
    return root


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "setup":
            path = safe_path(args.config)
            if path.exists():
                raise BridgeError("Config already exists; edit it directly or choose another path")
            setup_config(args.config, input("Cloudflare Account ID (32 hex characters): ").strip(), args.worker)
            print("Config created. No API token saved. Live connection has not been tested.")
        elif args.command == "diagnose":
            cfg = load_config(args.config)
            report = diagnose(cfg, secret("CF_API_TOKEN", args.prompt_secrets))
            print(json.dumps(report, indent=2))
            return 0 if report["http_events"] and report["worker_name_observed_events"] else 2
        elif args.command == "import":
            print(json.dumps({"inserted": import_logs(args.input, args.database, secret("CF_LOG_HMAC_KEY"))}))
        elif args.command == "export":
            print(json.dumps(export(args.database, args.output)))
        elif args.command == "analyze":
            print(json.dumps(analyze(args.input, args.iwatobi, args.rules, args.output, args.analysis_timeout)))
        else:
            cfg = load_config(args.config)
            if cfg["lookback_minutes"] <= cfg["overlap_minutes"]:
                raise BridgeError("lookback_minutes must exceed overlap_minutes")
            if args.command == "collect" and (args.interval_seconds < 10 or args.cycles < 0):
                raise BridgeError("interval-seconds must be >=10; cycles must be >=0")
            if args.command == "collect":
                if args.rules and not args.iwatobi:
                    raise BridgeError("--rules requires --iwatobi")
                if args.analysis_timeout <= 0:
                    raise BridgeError("Analysis timeout must be positive")
                if args.iwatobi:
                    analysis_paths(args.iwatobi, args.rules)
            token = secret("CF_API_TOKEN", args.prompt_secrets)
            key = secret("CF_LOG_HMAC_KEY", args.prompt_secrets)
            cycle = 0
            while True:
                result = fetch(cfg, token, key)
                result["status"] = "events_received" if result["received"] else "no_events_received"
                if args.command == "collect":
                    output = safe_path(args.output) / (datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex)
                    result.update(export(cfg["database"], output))
                    result["output"] = str(output)
                    if args.iwatobi:
                        try:
                            result["analysis"] = analyze(output / "access.log", args.iwatobi, args.rules,
                                                          output / "analysis", args.analysis_timeout)
                        except BridgeError as exc:
                            result.update(status="acquired_but_analysis_failed", analysis_error=str(exc))
                            print(json.dumps(result), flush=True)
                            return 1
                print(json.dumps(result), flush=True)
                cycle += 1
                if args.command == "fetch" or (args.cycles and cycle >= args.cycles):
                    break
                time.sleep(args.interval_seconds)
        return 0
    except KeyboardInterrupt:
        print("Stopped", file=sys.stderr)
        return 130
    except (BridgeError, OSError, sqlite3.Error, ValueError) as exc:
        # Raw exceptions can contain request data or configuration fragments.
        print(str(exc) if isinstance(exc, BridgeError) else f"Local processing failed ({type(exc).__name__})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
