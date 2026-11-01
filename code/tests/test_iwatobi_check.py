from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

import check_iwatobi


class IwatobiCheckTests(unittest.TestCase):
    def test_preflight_counts_without_showing_paths(self):
        with tempfile.TemporaryDirectory(prefix="bridge-iwatobi-test-") as tmp:
            source = Path(tmp) / "access.log"
            source.write_text("2026-10-31T00:00:00.000Z\t-\tGET\t/private-fixture-path\t200\ninvalid\n", encoding="utf-8")
            result = check_iwatobi.preflight(source)
            self.assertEqual(result, {"valid_lines": 1, "invalid_lines": 1, "unknown_client_lines": 1})
            self.assertNotIn("private-fixture", json.dumps(result))

    def test_missing_binary_never_claims_verification(self):
        with tempfile.TemporaryDirectory(prefix="bridge-iwatobi-test-") as tmp:
            source = Path(tmp) / "access.log"
            source.write_text("2026-10-31T00:00:00.000Z\t-\tGET\t/test\t200\n", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = check_iwatobi.main(["--input", str(source), "--iwatobi", str(Path(tmp) / "missing.exe")])
            result = json.loads(output.getvalue())
            self.assertEqual(code, 1)
            self.assertFalse(result["iwatobi_verified"])
            self.assertFalse(result["real_log_scan_completed"])
