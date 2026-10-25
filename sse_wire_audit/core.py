"""WHATWG EventSource interpretation with byte receipts, no network operations."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path


class InputError(ValueError):
    """Input unavailable or an explicit analysis budget exceeded."""


def describe(value, include_text):
    encoded = value.encode("utf-8")
    result = {"utf8_bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}
    if include_text:
        result["text"] = value
    return result


def lines(raw, start):
    """Yield zero-based, end-exclusive byte spans; CRLF is one terminator."""
    pos = start
    for match in re.finditer(rb"\r\n|\r|\n", raw):
        if match.start() < start:
            continue
        yield pos, match.start(), match.end(), True
        pos = match.end()
    if pos < len(raw):
        yield pos, len(raw), len(raw), False


def audit_bytes(raw, *, include_text=False, samples=20, max_bytes=16777216, max_line_bytes=1048576):
    """Return exact counts and bounded examples from one finite response body.

    The input must start at the response body boundary. HTTP headers, gzip and
    transfer chunk markers are not decoded here. A leading BOM is skipped once.
    Decoding errors use U+FFFD replacement as in a browser, and become findings.
    Last-event-ID is committed at blank lines, even in a block without data.
    """
    if not isinstance(raw, bytes):
        raise InputError("input must be bytes")
    if any(type(v) is not int or v < 1 for v in (samples, max_bytes, max_line_bytes)):
        raise InputError("all limits must be positive integers")
    if len(raw) > max_bytes:
        raise InputError("capture byte budget exceeded")
    bom = raw.startswith(b"\xef\xbb\xbf")
    begin = 3 if bom else 0
    finding_counts = Counter()
    finding_examples = []
    event_examples = []
    fields = Counter()
    line_count = event_count = comment_count = blank_count = 0
    block_start, block_line = begin, 1
    data_parts = []
    event_type = id_buffer = committed_id = ""
    id_pending = False
    retry = None
    pending_line = None

    def finding(code, start, end, line):
        finding_counts[code] += 1
        if len(finding_examples) < samples:
            finding_examples.append(
                {"code": code, "byte_start": start, "byte_end": end, "line": line}
            )

    for start, content_end, end, terminated in lines(raw, begin):
        line_count += 1
        if end - start > max_line_bytes:
            raise InputError(f"line {line_count}: byte budget exceeded")
        line_raw = raw[start:content_end]
        try:
            text = line_raw.decode("utf-8")
        except UnicodeDecodeError:
            # Do not echo rejected bytes. A single finding counts an affected line.
            finding("invalid_utf8_line", start, content_end, line_count)
            text = line_raw.decode("utf-8", errors="replace")
        if not terminated:
            pending_line = {"byte_start": start, "byte_end": end, "line": line_count}
            finding("unterminated_line", start, end, line_count)
            break
        if text == "":
            blank_count += 1
            committed_id = id_buffer
            if data_parts:
                event_count += 1
                if len(event_examples) < samples:
                    event_examples.append(
                        {
                            "event": event_count,
                            "byte_start": block_start,
                            "byte_end": end,
                            "first_line": block_line,
                            "dispatch_line": line_count,
                            "type": describe(event_type or "message", include_text),
                            "data": describe("\n".join(data_parts), include_text),
                            "last_event_id": describe(committed_id, include_text),
                        }
                    )
            data_parts = []
            event_type = ""
            id_pending = False
            block_start, block_line = end, line_count + 1
            continue
        if text.startswith(":"):
            comment_count += 1
            continue
        field, sep, value = text.partition(":")
        if not sep:
            value = ""
        elif value.startswith(" "):
            value = value[1:]
        if field == "data":
            fields["data"] += 1
            data_parts.append(value)
        elif field == "event":
            fields["event"] += 1
            event_type = value
        elif field == "id":
            fields["id"] += 1
            if "\x00" in value:
                finding("nul_id_ignored", start, end, line_count)
            else:
                id_buffer = value
                id_pending = True
        elif field == "retry":
            fields["retry"] += 1
            if value and value.isascii() and value.isdecimal():
                # Retain exact decimal semantics without int digit limits or float overflow.
                retry = value.lstrip("0") or "0"
            else:
                finding("invalid_retry_ignored", start, end, line_count)
        else:
            fields["unknown"] += 1
            finding("unknown_field_ignored", start, end, line_count)
    pending = bool(data_parts or event_type or id_pending)
    if pending:
        finding("incomplete_block", block_start, len(raw), block_line)
    retry_info = (
        None
        if retry is None
        else {
            "decimal_ms": retry if len(retry) <= 64 else None,
            "digits": len(retry),
            "sha256": hashlib.sha256(retry.encode("ascii")).hexdigest(),
        }
    )
    return {
        "schema_version": 1,
        "complete": True,
        "capture_bytes": len(raw),
        "leading_bom": bom,
        "line_count": line_count,
        "blank_lines": blank_count,
        "comment_lines": comment_count,
        "field_counts": dict(sorted(fields.items())),
        "event_count": event_count,
        "event_examples": event_examples,
        "examples_omitted": max(0, event_count - samples),
        "last_event_id": describe(committed_id, include_text),
        "would_send_last_event_id": bool(committed_id),
        "retry": retry_info,
        "pending": {
            "incomplete_block": pending,
            "unterminated_line": pending_line,
            "terminated_data_lines": len(data_parts),
            "data": describe("\n".join(data_parts), include_text),
            "id_buffer": describe(id_buffer, include_text),
        },
        "finding_counts": dict(sorted(finding_counts.items())),
        "finding_examples": finding_examples,
        "findings": bool(finding_counts),
        "example_limit": samples,
    }


def audit_file(path, **kwargs):
    limit = kwargs.get("max_bytes", 16777216)
    if type(limit) is not int or limit < 1:
        raise InputError("byte budget must be positive")
    with Path(path).open("rb") as handle:
        raw = handle.read(limit + 1)
    return audit_bytes(raw, **kwargs)
