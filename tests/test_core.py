import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sse_wire_audit.cli import main
from sse_wire_audit.core import InputError, audit_bytes, audit_file


def parse(data, **kwargs):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return audit_bytes(data, include_text=True, **kwargs)


def values(report):
    return [
        (e["type"]["text"], e["data"]["text"], e["last_event_id"]["text"])
        for e in report["event_examples"]
    ]


class ParserTests(unittest.TestCase):
    def test_multiline_empty_and_named_events(self):
        report = parse("event: update\nid: 7\ndata: first\ndata: second\n\ndata\n\n")
        self.assertEqual(values(report), [("update", "first\nsecond", "7"), ("message", "", "7")])
        self.assertFalse(report["findings"])

    def test_all_newline_styles(self):
        for sep in ["\n", "\r", "\r\n"]:
            with self.subTest(sep=repr(sep)):
                self.assertEqual(
                    values(parse(sep.join(["id:1", "data:x", "", ""]))), [("message", "x", "1")]
                )

    def test_mixed_newlines(self):
        report = parse(b"data:a\rdata:b\r\n\ndata:c\n\n")
        self.assertEqual([x[1] for x in values(report)], ["a\nb", "c"])

    def test_eof_is_not_dispatch(self):
        for tail in [b"data:lost", b"data:lost\n", b"data:lost\r\n"]:
            report = parse(b"data:ok\n\n" + tail)
            self.assertEqual(report["event_count"], 1)
            self.assertTrue(report["findings"])

    def test_partial_id_is_not_committed(self):
        report = parse("id:1\ndata:ok\n\nid:2\ndata:lost\n")
        self.assertEqual(report["last_event_id"]["text"], "1")
        self.assertEqual(report["pending"]["id_buffer"]["text"], "2")

    def test_unterminated_id_line_not_processed(self):
        report = parse("id:1\n\nid:2")
        self.assertEqual(report["last_event_id"]["text"], "1")
        self.assertEqual(report["pending"]["id_buffer"]["text"], "1")
        self.assertEqual(report["field_counts"]["id"], 1)

    def test_id_only_block_commits_and_resets(self):
        report = parse("id:hello\n\ndata:x\n\nid\n\ndata:y\n\n")
        self.assertEqual(values(report), [("message", "x", "hello"), ("message", "y", "")])
        self.assertFalse(report["would_send_last_event_id"])

    def test_nul_id_ignored(self):
        report = parse("id:ok\n\nid:bad\x00id\ndata:x\n\n")
        self.assertEqual(report["last_event_id"]["text"], "ok")
        self.assertEqual(report["finding_counts"]["nul_id_ignored"], 1)

    def test_retry_uses_ascii_digits_only(self):
        report = parse("retry:0012\nretry: -3\nretry:12ms\nretry:\nretry:１２\n\n")
        self.assertEqual(report["retry"]["decimal_ms"], "12")
        self.assertEqual(report["finding_counts"]["invalid_retry_ignored"], 4)

    def test_retry_immediate_without_blank_line(self):
        report = parse("retry:0\n")
        self.assertEqual(report["retry"]["decimal_ms"], "0")
        self.assertFalse(report["findings"])

    def test_arbitrary_retry_integer_has_bounded_representation(self):
        report = parse("retry:" + "9" * 5000 + "\n")
        self.assertIsNone(report["retry"]["decimal_ms"])
        self.assertEqual(report["retry"]["digits"], 5000)

    def test_one_space_is_removed(self):
        report = parse("data:  x\ndata:\ty\n\n")
        self.assertEqual(values(report)[0][1], " x\n\ty")

    def test_only_first_colon_splits_field(self):
        self.assertEqual(values(parse("data:a:b:c\n\n"))[0][1], "a:b:c")

    def test_bom_once(self):
        report = parse(b"\xef\xbb\xbfdata:x\n\n\xef\xbb\xbfdata:y\n\n")
        self.assertEqual(report["event_count"], 1)
        self.assertEqual(report["finding_counts"]["unknown_field_ignored"], 1)
        self.assertEqual(report["event_examples"][0]["byte_start"], 3)

    def test_invalid_utf8_replaced(self):
        report = parse(b"data:\xff\xe2\x82\n\n")
        self.assertEqual(values(report)[0][1], "\ufffd\ufffd")
        self.assertEqual(report["finding_counts"]["invalid_utf8_line"], 1)

    def test_byte_offsets_not_character_offsets(self):
        body = "data:猫\r\n\r\ndata:🙂\n\n".encode()
        report = parse(body)
        first, second = report["event_examples"]
        self.assertEqual(body[first["byte_start"] : first["byte_end"]], "data:猫\r\n\r\n".encode())
        self.assertEqual(body[second["byte_start"] : second["byte_end"]], "data:🙂\n\n".encode())

    def test_comments_and_blank_lines_do_not_dispatch(self):
        report = parse(":ping\n\n\n:still alive\n")
        self.assertEqual(report["event_count"], 0)
        self.assertEqual(report["comment_lines"], 2)
        self.assertFalse(report["findings"])

    def test_case_sensitive_field_names(self):
        report = parse("Data:x\ndata:y\n\n")
        self.assertEqual(values(report)[0][1], "y")
        self.assertEqual(report["finding_counts"]["unknown_field_ignored"], 1)

    def test_event_type_cleared_by_empty_block(self):
        self.assertEqual(values(parse("event: custom\n\ndata:x\n\n"))[0][0], "message")

    def test_last_type_and_id_wins(self):
        report = parse("event:a\nevent:b\nid:1\nid:2\ndata:x\n\n")
        self.assertEqual(values(report), [("b", "x", "2")])

    def test_non_cr_lf_characters_are_data(self):
        text = "a\u0085b\u2028c\x0bd"
        self.assertEqual(values(parse("data:" + text + "\n\n"))[0][1], text)

    def test_default_output_omits_text(self):
        report = audit_bytes(b"id:private_id\nevent:private_type\ndata:private_body\n\n")
        self.assertNotIn("private", json.dumps(report))
        self.assertEqual(report["event_examples"][0]["data"]["utf8_bytes"], 12)

    def test_capped_samples_keep_exact_counts(self):
        report = parse("data:x\n\n" * 100 + "unknown:x\n" * 80, samples=2)
        self.assertEqual(report["event_count"], 100)
        self.assertEqual(len(report["event_examples"]), 2)
        self.assertEqual(report["examples_omitted"], 98)
        self.assertEqual(report["finding_counts"]["unknown_field_ignored"], 80)
        self.assertEqual(len(report["finding_examples"]), 2)

    def test_limits(self):
        for settings in [{"max_bytes": 1}, {"max_line_bytes": 1}, {"samples": 0}]:
            with self.assertRaises(InputError):
                audit_bytes(b"data:x\n\n", **settings)
        with self.assertRaises(InputError):
            audit_bytes("not bytes")

    def test_empty_and_bom_only(self):
        for raw in [b"", b"\xef\xbb\xbf"]:
            self.assertFalse(parse(raw)["findings"])

    def test_file_and_cli_contract(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "body.sse"
            original = b"data:good\n\n"
            path.write_bytes(original)
            self.assertEqual(audit_file(path)["event_count"], 1)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(main([str(path)]), 0)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(json.loads(out.getvalue())["event_count"], 1)
            with self.assertRaises(InputError):
                audit_file(path, max_bytes=1)
            for raw, expected in [(b"data:good\n\n", 0), (b"data:lost\n", 1)]:
                path.write_bytes(raw)
                run = subprocess.run(
                    [sys.executable, "-m", "sse_wire_audit", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(run.returncode, expected)
                json.loads(run.stdout)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(path), "--max-bytes", "1"]), 2)
                self.assertEqual(main([str(path) + ".absent"]), 2)


if __name__ == "__main__":
    unittest.main()
