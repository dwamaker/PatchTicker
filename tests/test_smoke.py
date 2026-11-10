"""python -m collector --smoke (2026-11-11: one more required field in the Summary schema made Anthropic reject every
Summary request with "The compiled grammar is too large", which no unit test can see): one small real request of every
shape the collector sends with a schema, before a new image replaces the running one."""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from collector import cve_lines, summaries
from collector.__main__ import smoke, smoke_main
from test_batch_summaries import api_error
from test_summaries import FakeClaude

SHAPES = ["summary", "quick titles", "cve lines"]


def run(fn, *args):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        code = fn(*args)
    return code, out.getvalue()


class SmokeTest(unittest.TestCase):
    def test_every_shape_is_sent_once_with_the_cycles_own_instructions_and_schema(self):
        claude = FakeClaude("{}", "{}", "{}")
        code, out = run(smoke, claude)
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines(), [f"smoke: {s} ok" for s in SHAPES])
        self.assertEqual([p["system"][0]["text"] for p in claude.sent],
                         [summaries.INSTRUCTIONS, summaries.TITLE_INSTRUCTIONS, cve_lines.LINES_INSTRUCTIONS])
        self.assertEqual([p["output_config"]["format"]["schema"] for p in claude.sent],
                         [summaries.SCHEMA, summaries.TITLE_SCHEMA, cve_lines.LINES_SCHEMA])
        self.assertTrue(all(p["max_tokens"] <= 200 for p in claude.sent))

    def test_a_rejected_shape_is_named_with_the_errors_type_and_message_and_exits_1(self):
        claude = FakeClaude("{}", "{}")
        accept = claude.create

        def create(**params):
            if params["output_config"]["format"]["schema"] is summaries.SCHEMA:
                raise api_error(400, "invalid_request_error", "The compiled grammar is too large " + "x" * 300)
            return accept(**params)
        claude.messages.create = create
        code, out = run(smoke, claude)
        self.assertEqual(code, 1)
        failed, *rest = out.splitlines()
        self.assertTrue(failed.startswith("smoke: summary FAILED: APIStatusError: The compiled grammar is too large x"))
        self.assertEqual(len(failed.split(": ", 3)[3]), 200)  # the message, cut
        self.assertEqual(rest, ["smoke: quick titles ok", "smoke: cve lines ok"])  # the others still checked

    def test_main_uses_the_settings_key_and_never_touches_the_store(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ), \
                mock.patch("anthropic.Anthropic", return_value=FakeClaude("{}", "{}", "{}")) as client:
            os.environ.pop("ANTHROPIC_API_KEY", None)
            env = Path(folder, ".env")
            store = Path(folder, "store")
            env.write_text(f"VR_COLLECTOR_ID=t\nVR_CONTACT=t\nVR_STORE_DIR={store}\nANTHROPIC_API_KEY=test-key\n", encoding="utf-8")
            code, _ = run(smoke_main, str(env))
            self.assertEqual(code, 0)
            client.assert_called_once_with(api_key="test-key")
            self.assertFalse(store.exists())

    def test_no_key_exits_1_and_says_so(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ), mock.patch("anthropic.Anthropic") as client:
            os.environ.pop("ANTHROPIC_API_KEY", None)
            env = Path(folder, ".env")
            env.write_text(f"VR_COLLECTOR_ID=t\nVR_CONTACT=t\nVR_STORE_DIR={folder}\n", encoding="utf-8")
            code, out = run(smoke_main, str(env))
        self.assertEqual(code, 1)
        self.assertIn("ANTHROPIC_API_KEY", out)
        client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
