from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import bridge
import daily
from test_bridge import sample, page, KEY


class DailyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bridge-daily-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "iwatobi.exe"
        self.exe.write_text("test stub")
        (self.root / "rules").mkdir()
        self.cfg = {"account_id": "a" * 32, "worker": "kadaiinfo-web", "database": str(self.root / "events.sqlite"),
                    "lookback_minutes": 15, "overlap_minutes": 5, "delay_seconds": 60}
        self.now = 1793449000000
        self.target = self.now - 60_000
        self.rows = []
        for name, when in (("first", self.target - daily.DAY_MS + 1000),
                           ("middle", self.target - daily.DAY_MS // 2), ("last", self.target - 1000)):
            row = sample()
            row["$metadata"]["id"] = name
            row["timestamp"] = when
            self.rows.append(row)
        self.calls = []
        self.analyses = []

    def send(self, url, token, payload):
        span = payload["timeframe"]
        self.assertLessEqual(span["to"] - span["from"], 15 * 60_000)
        self.calls.append(span.copy())
        if payload.get("offset"):
            return page([])
        return page([r for r in self.rows if span["from"] <= r["timestamp"] < span["to"]])

    def analysis(self, source, exe, rules, output, timeout, **kwargs):
        rows = Path(source).read_text().splitlines()
        self.analyses.append(rows)
        Path(output).mkdir()
        return {"analysis_status": "completed", "input_lines": len(rows), "iwatobi_exit_code": 0,
                "result_scope": kwargs["result_scope"]}

    def run_daily(self, **kwargs):
        return daily.run_daily(self.cfg, "fixture", KEY, str(self.exe), output=self.root / "daily",
                               now_ms=kwargs.pop("now_ms", self.now), send=kwargs.pop("send", self.send),
                               analyze_func=kwargs.pop("analyze_func", self.analysis), **kwargs)

    def test_full_24_hours_are_fetched_and_analyzed_once(self):
        report = self.run_daily()
        self.assertEqual(report["to_ms"] - report["from_ms"], daily.DAY_MS)
        self.assertEqual(report["http_events"], 3)
        self.assertEqual(len(self.analyses), 1)
        self.assertGreater(report["batches"], 90)
        self.assertEqual(report["to_ms"], self.target)
        self.assertEqual(report["analysis"]["result_scope"], "daily_period_including_boundary_overlap")

    def test_same_day_rerun_is_not_due_and_has_no_api_call(self):
        first = self.run_daily()
        before = len(self.calls)
        report = self.run_daily(now_ms=self.now + 3_600_000)
        self.assertEqual(report["status"], "not_due")
        self.assertEqual(len(self.calls), before)
        self.assertEqual(len(self.analyses), 1)
        self.assertEqual(report["next_due_ms"], first["to_ms"] + daily.DAY_MS + 60_000)

    def test_second_day_exports_period_not_all_history(self):
        first = self.run_daily()
        next_row = sample()
        next_row["$metadata"]["id"] = "day-two"
        next_row["timestamp"] = self.target + daily.DAY_MS // 2
        self.rows.append(next_row)
        second = self.run_daily(now_ms=self.now + daily.DAY_MS)
        self.assertEqual(second["from_ms"], first["to_ms"] - 300_000)
        self.assertEqual(second["http_events"], 2)  # Boundary context + new day.
        ids = [json.loads(line)["event_id"] for line in (Path(second["output"]) / "events.jsonl").read_text().splitlines()]
        self.assertNotIn("first", ids)
        self.assertIn("day-two", ids)

    def test_failed_acquisition_resumes_saved_window(self):
        def interrupted(*args):
            if len(self.calls) >= 10:
                raise bridge.BridgeError("simulated outage")
            return self.send(*args)
        with self.assertRaises(bridge.BridgeError):
            self.run_daily(send=interrupted)
        self.assertEqual(len(self.analyses), 0)
        with closing(sqlite3.connect(self.cfg["database"])) as db:
            pending = json.loads(db.execute("SELECT job FROM daily_jobs").fetchone()[0])
        self.assertGreater(pending["progress_ms"], pending["from_ms"])
        report = self.run_daily(now_ms=self.now + 3_600_000)
        self.assertEqual(report["to_ms"], self.target)  # Fixed target survives retries.
        self.assertEqual(report["http_events"], 3)

    def test_failed_analysis_retries_without_fetching_again(self):
        def fail(*a, **kw):
            raise bridge.BridgeError("simulated analyzer failure")
        with self.assertRaises(bridge.BridgeError):
            self.run_daily(analyze_func=fail)
        before = len(self.calls)
        report = self.run_daily()
        self.assertEqual(len(self.calls), before)
        self.assertEqual(report["status"], "daily_completed")
        self.assertEqual(report["http_events"], 3)

    def test_old_checkpoint_is_caught_up_not_skipped(self):
        with closing(bridge.connect(self.cfg["database"])) as db, db:
            db.execute("INSERT INTO checkpoints VALUES (?, ?)", ("a" * 32 + ":kadaiinfo-web", self.target - daily.DAY_MS - 60_000))
        report = self.run_daily()
        self.assertLess(report["from_ms"], self.target - daily.DAY_MS)
        self.assertEqual(report["to_ms"], self.target)

    def test_daily_lock_rejects_parallel_run(self):
        with daily.job_lock(self.cfg["database"]):
            with self.assertRaises(bridge.BridgeError):
                with daily.job_lock(self.cfg["database"]):
                    self.fail("Concurrent run acquired lock")
