"""Fetch the entire outstanding period, then run iwatobi once per day."""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import time
import uuid

import bridge

DAY_MS = 86_400_000
JST = timezone(timedelta(hours=9))


@contextmanager
def job_lock(database):
    """OS releases the lock on crash; lock file contents are not credentials."""
    path = bridge.safe_path(str(database) + ".daily.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if path.stat().st_size == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise bridge.BridgeError("Another daily job is already running for this database") from None
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def write_job(db, scope, job):
    db.execute("INSERT INTO daily_jobs VALUES (?, ?) ON CONFLICT(scope) DO UPDATE SET job=excluded.job",
               (scope, json.dumps(job)))


def run_daily(cfg, token, key, executable, *, rules=None, output="data/daily", initial_hours=24,
              timeout=300, now_ms=None, send=None, analyze_func=None):
    bridge.analysis_paths(executable, rules)
    if not 1 <= initial_hours <= 48 or timeout <= 0:
        raise bridge.BridgeError("initial-hours must be 1..48 and timeout must be positive")
    window_ms = cfg["lookback_minutes"] * 60_000
    overlap_ms = cfg["overlap_minutes"] * 60_000
    if window_ms <= overlap_ms:
        raise bridge.BridgeError("lookback_minutes must exceed overlap_minutes")
    target = (now_ms if now_ms is not None else time.time_ns() // 1_000_000) - cfg["delay_seconds"] * 1000
    scope = cfg["account_id"] + ":" + cfg["worker"]
    base = bridge.safe_path(output)
    with job_lock(cfg["database"]), closing(bridge.connect(cfg["database"])) as db:
        db.execute("CREATE TABLE IF NOT EXISTS daily_jobs(scope TEXT PRIMARY KEY, job TEXT NOT NULL)")
        with db:
            row = db.execute("SELECT job FROM daily_jobs WHERE scope=?", (scope,)).fetchone()
            previous = json.loads(row[0]) if row else None
            if previous and previous["state"] == "completed" and target < previous["to_ms"] + DAY_MS:
                return {"status": "not_due", "next_due_ms": previous["to_ms"] + DAY_MS + cfg["delay_seconds"] * 1000}
            if previous and previous["state"] == "pending":
                # Resume the same fixed period, including logs acquired before failure.
                job = previous
            else:
                checkpoint = db.execute("SELECT until_ms FROM checkpoints WHERE scope=?", (scope,)).fetchone()
                start = previous["to_ms"] - overlap_ms if previous else target - initial_hours * 3_600_000
                if checkpoint and not previous:
                    start = min(start, checkpoint[0] - overlap_ms)
                job = {"id": uuid.uuid4().hex, "state": "pending", "from_ms": start, "to_ms": target,
                       "progress_ms": start, "batches": 0, "received": 0, "inserted": 0}
                write_job(db, scope, job)
        while job["progress_ms"] < job["to_ms"]:
            if job["batches"] >= 10_000:
                raise bridge.BridgeError("Daily batch limit reached; acquisition state retained")
            start = job["progress_ms"] - overlap_ms if job["batches"] else job["from_ms"]
            end = min(start + window_ms, job["to_ms"])
            cursor = None
            cursors = set()
            received = inserted = 0
            with db:
                for _ in range(10_000):
                    kwargs = {"cursor": cursor}
                    if send is not None:
                        kwargs["send"] = send
                    rows = bridge.query_events(cfg, token, start, end, **kwargs)
                    if not rows:
                        break
                    for event in rows:
                        inserted += bridge.save(db, bridge.normalize(event, key))
                        received += 1
                    cursor = bridge.dig(rows[-1], "$metadata", "id")
                    if cursor in cursors:
                        raise bridge.BridgeError("Repeated cursor; current daily batch rolled back")
                    cursors.add(cursor)
                else:
                    raise bridge.BridgeError("Page limit reached; current daily batch rolled back")
                next_job = dict(job, progress_ms=end, batches=job["batches"] + 1,
                                received=job["received"] + received, inserted=job["inserted"] + inserted)
                write_job(db, scope, next_job)
                db.execute("INSERT INTO checkpoints VALUES (?, ?) ON CONFLICT(scope) DO UPDATE SET until_ms=max(until_ms, excluded.until_ms)", (scope, end))
            job = next_job
        day = datetime.fromtimestamp(job["to_ms"] / 1000, JST).date().isoformat()
        destination = base / day / (job["id"] + "-" + uuid.uuid4().hex)
        exported = bridge.export(cfg["database"], destination, start_ms=job["from_ms"], end_ms=job["to_ms"])
        analysis = (analyze_func or bridge.analyze)(destination / "access.log", executable, rules,
                                                  destination / "analysis", timeout,
                                                  result_scope="daily_period_including_boundary_overlap")
        report = {"status": "daily_completed", "from_ms": job["from_ms"], "to_ms": job["to_ms"],
                  "from_jst": datetime.fromtimestamp(job["from_ms"] / 1000, JST).isoformat(),
                  "to_jst": datetime.fromtimestamp(job["to_ms"] / 1000, JST).isoformat(),
                  "received": job["received"], "inserted": job["inserted"], "batches": job["batches"],
                  **exported, "output": str(destination), "analysis": analysis}
        with (destination / "daily.json").open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        with db:
            write_job(db, scope, dict(job, state="completed", output=str(destination)))
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.local.json")
    parser.add_argument("--iwatobi", required=True)
    parser.add_argument("--rules")
    parser.add_argument("--output", default="data/daily")
    parser.add_argument("--initial-hours", type=int, default=24)
    parser.add_argument("--analysis-timeout", type=int, default=300)
    parser.add_argument("--prompt-secrets", action="store_true")
    parser.add_argument("--repeat", action="store_true", help="Keep running; wait 24 hours between successful jobs")
    args = parser.parse_args(argv)
    try:
        cfg = bridge.load_config(args.config)
        bridge.analysis_paths(args.iwatobi, args.rules)
        token = bridge.secret("CF_API_TOKEN", args.prompt_secrets)
        key = bridge.secret("CF_LOG_HMAC_KEY", args.prompt_secrets)
        while True:
            report = run_daily(cfg, token, key, args.iwatobi, rules=args.rules, output=args.output,
                               initial_hours=args.initial_hours, timeout=args.analysis_timeout)
            print(json.dumps(report), flush=True)
            if not args.repeat:
                return 0
            due = report.get("next_due_ms", report.get("to_ms", 0) + DAY_MS + cfg["delay_seconds"] * 1000)
            # A resumed old job is followed immediately by catch-up if already due.
            while time.time_ns() // 1_000_000 < due:
                time.sleep(min(60, max(0.01, (due - time.time_ns() // 1_000_000) / 1000)))
    except KeyboardInterrupt:
        print("Stopped")
        return 130
    except (bridge.BridgeError, OSError, ValueError, bridge.sqlite3.Error) as exc:
        print(json.dumps({"status": "daily_failed_retry_same_command", "error": str(exc) if isinstance(exc, bridge.BridgeError) else type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
