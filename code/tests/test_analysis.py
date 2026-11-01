from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import bridge
from test_bridge import replace_attribute, sample, page, KEY


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bridge-analysis-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "iwatobi.exe"
        self.exe.write_text("test double, not an executable", encoding="utf-8")
        (self.root / "rules").mkdir()
        self.source = self.root / "access.log"
        self.source.write_text("2026-10-31T00:00:00.000Z\t-\tGET\t/test\t200\n", encoding="utf-8")

    def fake_runner(self, args, **kwargs):
        self.assertNotIn("CF_API_TOKEN", kwargs["env"])
        self.assertNotIn("CF_LOG_HMAC_KEY", kwargs["env"])
        self.assertIn("--custom-formats", args)
        output = Path(args[args.index("-o") + 1] + ".jsonl")
        output.write_text('{"RuleID":"synthetic-test-match"}\n', encoding="utf-8")
        return SimpleNamespace(returncode=0)

    def test_analysis_writes_summary_without_forwarding_secrets(self):
        env = dict(os.environ, CF_API_TOKEN="private-token", CF_LOG_HMAC_KEY=KEY)
        with replace_attribute(os, "environ", env):
            report = bridge.analyze(self.source, str(self.exe), output=self.root / "result", run=self.fake_runner)
        self.assertEqual(report["analysis_status"], "completed")
        self.assertEqual(report["detection_rows"], 1)
        self.assertEqual(report["input_lines"], 1)
        saved = (self.root / "result" / "analysis.json").read_text(encoding="utf-8")
        self.assertNotIn("private-token", saved)
        self.assertNotIn(KEY, saved)

    def test_timeout_records_failure_and_keeps_input(self):
        def timed_out(args, **kwargs):
            raise subprocess.TimeoutExpired(args, 1)
        with self.assertRaises(bridge.BridgeError):
            bridge.analyze(self.source, str(self.exe), output=self.root / "timeout", run=timed_out)
        report = json.loads((self.root / "timeout" / "analysis.json").read_text())
        self.assertEqual(report["analysis_status"], "failed")
        self.assertTrue(self.source.is_file())

    def test_nonzero_and_missing_output_are_not_success(self):
        for label, code in (("nonzero", 1), ("missing", 0)):
            with self.assertRaises(bridge.BridgeError):
                bridge.analyze(self.source, str(self.exe), output=self.root / label,
                               run=lambda *a, **kw: SimpleNamespace(returncode=code))
            report = json.loads((self.root / label / "analysis.json").read_text())
            self.assertEqual(report["analysis_status"], "failed")

    def test_empty_http_input_is_explicit_skip(self):
        self.source.write_text("", encoding="utf-8")
        def should_not_run(*a, **kw):
            self.fail("Do not invoke iwatobi for an empty input")
        report = bridge.analyze(self.source, str(self.exe), run=should_not_run)
        self.assertEqual(report["analysis_status"], "skipped_no_http_events")
        self.assertIsNone(report["iwatobi_exit_code"])

    def pipeline(self, cycles=2, runner=None):
        cfg = {"account_id": "a" * 32, "worker": "kadaiinfo-web", "database": str(self.root / "events.sqlite"),
               "lookback_minutes": 15, "overlap_minutes": 5, "delay_seconds": 60}
        config = self.root / "config.json"
        config.write_text(json.dumps(cfg))
        fetch_original = bridge.fetch
        calls = []
        def fake_api_fetch(cfg, token, key):
            calls.append("fetch")
            rows = iter([page([sample()]), page([])])
            return fetch_original(cfg, token, key, send=lambda *a: next(rows), now_ms=1793449000000 + len(calls) * 300000)
        env = dict(os.environ, CF_API_TOKEN="fixture-token", CF_LOG_HMAC_KEY=KEY)
        output = io.StringIO()
        with replace_attribute(os, "environ", env), replace_attribute(bridge, "fetch", fake_api_fetch), \
             replace_attribute(bridge.subprocess, "run", runner or self.fake_runner), \
             replace_attribute(bridge.time, "sleep", lambda seconds: calls.append("sleep")), redirect_stdout(output):
            code = bridge.main(["collect", "--config", str(config), "--output", str(self.root / "snapshots"),
                                "--iwatobi", str(self.exe), "--cycles", str(cycles)])
        return code, [json.loads(line) for line in output.getvalue().splitlines()], calls

    def test_each_cycle_fetches_exports_and_analyzes(self):
        code, reports, calls = self.pipeline()
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["fetch", "sleep", "fetch"])
        self.assertEqual(len(reports), 2)
        self.assertNotEqual(reports[0]["output"], reports[1]["output"])
        self.assertEqual(reports[0]["inserted"], 1)
        self.assertEqual(reports[1]["inserted"], 0)
        for report in reports:
            self.assertEqual(report["analysis"]["analysis_status"], "completed")
            self.assertTrue((Path(report["output"]) / "analysis" / "detections.jsonl").is_file())

    def test_analysis_failure_stops_loop_but_keeps_acquired_logs(self):
        code, reports, calls = self.pipeline(runner=lambda *a, **kw: SimpleNamespace(returncode=1))
        self.assertEqual(code, 1)
        self.assertEqual(calls, ["fetch"])
        self.assertEqual(reports[0]["status"], "acquired_but_analysis_failed")
        self.assertTrue((Path(reports[0]["output"]) / "access.log").exists())
