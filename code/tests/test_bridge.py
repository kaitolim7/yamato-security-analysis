import copy
from contextlib import contextmanager, closing, redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from urllib.error import HTTPError

import bridge


KEY = "fixture-only-key-32-characters-long-not-for-production"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "workers.jsonl"


@contextmanager
def replace_attribute(target, name, replacement):
    original = getattr(target, name)
    setattr(target, name, replacement)
    try:
        yield
    finally:
        setattr(target, name, original)


def sample():
    return json.loads(FIXTURES.read_text(encoding="utf-8").splitlines()[0])


def page(rows):
    return {"success": True, "result": {"events": {"events": rows}, "run": {"status": "COMPLETED"}}}


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kadaiinfo-bridge-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "test.sqlite"
        self.cfg = {"account_id": "a" * 32, "worker": "kadaiinfo-web", "database": str(self.database),
                    "lookback_minutes": 15, "overlap_minutes": 5, "delay_seconds": 60}

    def counts(self):
        with closing(sqlite3.connect(self.database)) as db:
            return tuple(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                         for table in ("events", "checkpoints"))

    def test_secrets_removed_and_hash_stable(self):
        event = bridge.normalize(sample(), KEY)
        raw = json.dumps(event)
        self.assertNotIn("192.0.2.", raw)
        self.assertNotIn("fixture-only", raw)
        self.assertNotIn("?secret=", raw)
        self.assertRegex(event["client_hash"], r"^[a-f0-9]{64}$")
        self.assertEqual(event["client_hash"], bridge.normalize(sample(), KEY)["client_hash"])
        self.assertNotEqual(event["client_hash"], bridge.normalize(sample(), "other-key")["client_hash"])

    def test_paths_preserve_attack_evidence(self):
        self.assertEqual(bridge.request_path("https://user:secret@example.test/a/../admin?secret=foo#frag"), "/a/../admin")
        self.assertEqual(bridge.request_path("https://example.test/%2e%2e/admin"), "/%2e%2e/admin")
        self.assertEqual(bridge.request_path("https://example.test?secret=foo"), "/")
        for value in ("file:///bad", "https://", "https://example.test/\nbad"):
            with self.assertRaises(bridge.BridgeError):
                bridge.request_path(value)

    def test_nested_source_and_timezone(self):
        value = sample()
        value["source"] = {"$workers": value.pop("$workers")}
        value["timestamp"] = "2026-10-31T12:00:00+09:00"
        event = bridge.normalize(value, KEY)
        self.assertEqual(event["timestamp"], "2026-10-31T03:00:00.000Z")
        self.assertEqual(event["status"], 200)
        with self.assertRaises(bridge.BridgeError):
            bridge.timestamp("2026-10-31T12:00:00")

    def test_export_deduplication_and_format(self):
        self.assertEqual(bridge.import_logs(FIXTURES, self.database, KEY), 2)
        self.assertEqual(bridge.import_logs(FIXTURES, self.database, KEY), 0)
        output = self.root / "out"
        self.assertEqual(bridge.export(self.database, output), {"http_events": 2, "non_http_events": 0})
        lines = (output / "access.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(len(line.split("\t")) == 5 for line in lines))
        self.assertIn("\tPOST\t/api/revalidate\t401", lines[1])
        self.assertFalse(output.with_name("out.partial").exists())
        with self.assertRaises(bridge.BridgeError):
            bridge.export(self.database, output)

    def test_import_rolls_back_on_invalid_row(self):
        source = self.root / "invalid.jsonl"
        source.write_text(json.dumps(sample()) + "\n{}\n", encoding="utf-8")
        with self.assertRaises(bridge.BridgeError):
            bridge.import_logs(source, self.database, KEY)
        self.assertEqual(self.counts(), (0, 0))

    def test_pagination_deduplication_and_checkpoint(self):
        calls = []
        replies = iter([page([sample()]), page([])])
        def send(url, token, body):
            calls.append(copy.deepcopy(body))
            self.assertTrue(url.startswith("https://api.cloudflare.com/"))
            return next(replies)
        result = bridge.fetch(self.cfg, "test-token", KEY, send=send, now_ms=1793449000000)
        self.assertEqual(result["inserted"], 1)
        self.assertEqual(calls[1]["offset"], sample()["$metadata"]["id"])
        self.assertEqual(calls[1]["timeframe"], calls[0]["timeframe"])
        self.assertEqual(self.counts(), (1, 1))
        again = iter([page([sample()]), page([])])
        second = bridge.fetch(self.cfg, "token", KEY, send=lambda *args: next(again), now_ms=1793449300000)
        self.assertEqual(second["inserted"], 0)
        self.assertEqual(second["from_ms"], result["to_ms"] - 300000)

    def test_api_failures_never_advance_checkpoint(self):
        for failure in ({"success": False}, {"success": True, "result": {}},
                        {"success": True, "result": {"statistics": {"abr_level": 2}}}):
            with self.subTest(failure=failure):
                replies = iter([page([sample()]), failure])
                with self.assertRaises(bridge.BridgeError):
                    bridge.fetch(self.cfg, "token", KEY, send=lambda *args: next(replies), now_ms=1793449000000)
                self.assertEqual(self.counts(), (0, 0))

    def test_repeated_cursor_rolls_back(self):
        with self.assertRaisesRegex(bridge.BridgeError, "Repeated"):
            bridge.fetch(self.cfg, "token", KEY, send=lambda *args: page([sample()]), now_ms=1793449000000)
        self.assertEqual(self.counts(), (0, 0))

    def test_console_event_not_in_access_log(self):
        row = {"$metadata": {"id": "console"}, "timestamp": 1793448000000,
               "source": {"message": "do-not-save"}}
        event = bridge.normalize(row, KEY)
        self.assertNotIn("do-not-save", json.dumps(event))
        with closing(bridge.connect(self.database)) as db, db:
            bridge.save(db, event)
        result = bridge.export(self.database, self.root / "console")
        self.assertEqual(result, {"http_events": 0, "non_http_events": 1})

    def test_dotenv_paths_rejected_without_access(self):
        for name in (".env", ".env.local", "folder/.env.test/child"):
            with self.assertRaises(bridge.BridgeError):
                bridge.safe_path(name)

    def test_http_retries_without_secret_leaks(self):
        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                if self.calls < 3:
                    raise HTTPError(request.full_url, 429, "secret-detail", {}, io.BytesIO(b"secret-body"))
                return io.BytesIO(b'{"success":true}')
        opener = Opener()
        sleeps = []
        self.assertEqual(bridge.post_json("https://example.test", "secret-token", {}, opener=opener, sleep=sleeps.append), {"success": True})
        self.assertEqual(sleeps, [1, 2])
        class Denied:
            def open(self, *args, **kwargs):
                raise HTTPError("https://example.test", 403, "secret-detail", {}, io.BytesIO(b"secret-body"))
        with self.assertRaises(bridge.BridgeError) as error:
            bridge.post_json("https://example.test", "secret-token", {}, opener=Denied())
        self.assertNotIn("secret", str(error.exception))

    def test_collect_produces_ready_snapshot(self):
        config = self.root / "config.json"
        config.write_text(json.dumps(self.cfg), encoding="utf-8")
        def fake_fetch(cfg, token, key):
            bridge.import_logs(FIXTURES, cfg["database"], key)
            return {"inserted": 2, "received": 2}
        env = dict(os.environ, CF_API_TOKEN="fixture", CF_LOG_HMAC_KEY=KEY)
        with replace_attribute(os, "environ", env), replace_attribute(bridge, "fetch", fake_fetch), redirect_stdout(io.StringIO()):
            self.assertEqual(bridge.main(["collect", "--config", str(config), "--output", str(self.root / "snapshots")]), 0)
        snapshots = list((self.root / "snapshots").iterdir())
        self.assertEqual(len(snapshots), 1)
        self.assertTrue((snapshots[0] / "access.log").exists())

    def test_setup_creates_non_secret_config_and_never_overwrites(self):
        config = self.root / "config.local.json"
        bridge.setup_config(str(config), "a" * 32, "kadaiinfo-web")
        self.assertEqual(bridge.load_config(str(config))["worker"], "kadaiinfo-web")
        before = config.read_bytes()
        with self.assertRaises(FileExistsError):
            bridge.setup_config(str(config), "b" * 32, "another-worker")
        self.assertEqual(config.read_bytes(), before)
        self.assertNotIn("token", before.decode().lower())

    def test_diagnose_no_events_is_not_log_acquisition_success(self):
        report = bridge.diagnose(self.cfg, "token", send=lambda *a: page([]), now_ms=1793449000000)
        self.assertEqual(report["status"], "api_reachable_no_events")
        self.assertFalse(report["database_modified"])
        self.assertFalse(report["iwatobi_verified"])
        self.assertFalse(self.database.exists())

    def test_diagnose_reports_counts_without_raw_values(self):
        row = sample()
        row["$workers"]["scriptName"] = "kadaiinfo-web"
        payloads = []
        def send(url, token, payload):
            payloads.append(payload)
            return page([row])
        report = bridge.diagnose(self.cfg, "secret-token", send=send, now_ms=1793449000000)
        self.assertEqual(report["http_events"], 1)
        self.assertEqual(report["worker_name_observed_events"], 1)
        self.assertEqual(payloads[0]["limit"], 5)
        raw = json.dumps(report)
        for value in ("secret-token", "192.0.2.1", "/posts/test", "fixture-normal-1"):
            self.assertNotIn(value, raw)
        self.assertFalse(self.database.exists())

    def test_diagnose_rejects_authentication_failure(self):
        with self.assertRaises(bridge.BridgeError):
            bridge.diagnose(self.cfg, "token", send=lambda *a: {"success": False})
        self.assertFalse(self.database.exists())

    def test_metadata_fallback_for_string_source(self):
        row = {"$metadata": {"id": "meta-only", "method": "GET", "url": "https://example.test/a?secret=fixture-only", "statusCode": 200},
               "timestamp": 1793448000000, "source": "private message"}
        event = bridge.normalize(row, KEY)
        self.assertEqual((event["method"], event["path"], event["status"]), ("GET", "/a", 200))
        self.assertNotIn("private", json.dumps(event))

    def test_diagnose_reports_unsupported_event_shape(self):
        report = bridge.diagnose(self.cfg, "token", send=lambda *a: page([{"unexpected": "private"}]))
        self.assertEqual(report["sample_events_received"], 1)
        self.assertEqual(report["normalizable_events"], 0)
        self.assertEqual(report["http_events"], 0)
        self.assertIn("adapter", report["status"])


if __name__ == "__main__":
    unittest.main()
