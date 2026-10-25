# sse-wire-audit

Explain what a browser would dispatch from a saved Server-Sent Events response body. The report shows event byte ranges, ignored fields, malformed UTF-8, unfinished EOF data, and the last **committed** reconnect ID. It runs offline with no runtime dependencies.

Use it when a streaming endpoint appears to send an event but the client never receives it. A file ending with `data: hello` or `data: hello\n` has no complete event: the blank line is significant. This tool preserves that distinction instead of treating EOF as an event separator.

## Install and try

Python 3.10+. This is a source/GitHub Release distribution, not a PyPI publication.

```sh
git clone https://github.com/KanadeK/sse-wire-audit.git
cd sse-wire-audit
python -m venv .venv
# Linux/macOS: . .venv/bin/activate
# PowerShell: .venv/Scripts/Activate.ps1
python -m pip install .
sse-wire-audit examples/clean.sse
sse-wire-audit examples/incomplete.sse --include-text
```

The clean synthetic example reports 2 events and exits **0**. The incomplete example reports 1 event, a pending ID and an unterminated line, then exits **1**. Its committed reconnect ID remains `1` although the pending ID buffer contains `2`.

`python -m sse_wire_audit` is equivalent. Uninstall with `python -m pip uninstall sse-wire-audit`; remove the dedicated virtual environment when finished. The tool creates no scratch files and does not modify captures.

## Capture format

Supply **one raw response body, captured from its start**. Do not include HTTP headers, gzip bytes or HTTP transfer-chunk markers. Decompress and dechunk before analysis. It does not connect to the endpoint or validate HTTP status, content type, timing, reconnection policy or network availability. A capture stopped midstream naturally produces EOF diagnostics; they do not prove the server is faulty.

Parsing follows the [WHATWG browser EventSource algorithm](https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream): CR, LF and CRLF delimit lines; one initial UTF-8 BOM is removed; multiline data uses LF; empty `data` still dispatches; names are case-sensitive; exactly one space after the first colon is removed. A blank line commits the ID even without data. NUL-containing IDs and non-ASCII/nondecimal retry values are ignored. Data and event type buffers reset after each blank line; the ID buffer persists.

Unterminated final lines are recorded but not processed. Terminated fields in a block without its closing blank line may change pending state, but cannot dispatch its event. A terminated valid `retry` field takes effect immediately. Retry values are represented as exact decimal strings, without claiming an actual browser wait duration; values above 64 digits are summarized by digit count and hash.

## Output and exit codes

JSON goes to stdout. Byte offsets are **zero-based, end-exclusive** and refer to the original captured bytes, including its BOM. Lines and event indexes are one-based. An event receipt spans the entire block since the prior blank line, including comments and ignored fields. `last_event_id` is committed state; `pending.id_buffer` may differ.

Default output includes text lengths and SHA-256 hashes, without raw data, IDs or event types. `--include-text` adds those values to sampled events and pending-state descriptors. JSON output escapes control characters. Hashes and lengths are not anonymization: small secrets can be guessed, and reports should be handled as sensitive. Redirect to a file different from the input.

| Exit | Meaning |
|---|---|
| 0 | Complete analysis without review findings; a heartbeat-only or empty capture can have zero events. |
| 1 | Complete analysis with ignored fields, replacement decoding or unfinished input to review. |
| 2 | Input, storage or budget error; no partial success report. |

An unknown extension field is legal to ignore. Exit 1 is a diagnostic review signal, **not** a blanket claim that the stream violates the protocol. Repeated IDs are legal and do not trigger warnings. The tool cannot determine whether valid-looking fields were injected or intentional.

Defaults: `--max-bytes 16777216`, `--max-line-bytes 1048576` including line terminators (the initial BOM is excluded), and `--samples 20`. The capture is held in memory within the byte cap; counts cover the full capture, while event/finding examples are capped independently. Increase limits explicitly if needed. No infinite-stream support or automatic input repair.

## Development and alternatives

```sh
python -m unittest discover -s tests -v
python -m pip install ruff build
ruff check .
python -m build
python scripts/smoke_wheel.py
```

Tests cover exact UTF-8 offsets, CR/LF variants, empty data, BOM, retry, ID resets, EOF loss, sample caps, budgets and installed CLI behavior. See [VALIDATION.md](VALIDATION.md). CI tests Windows/Linux with Python 3.10/3.13.

[eventsource-parser](https://github.com/rexxars/eventsource-parser) is a mature streaming parser to embed in JavaScript clients. This CLI adds offline byte receipts and interpretation diagnostics for finite captures. [FastAPI issue 15188](https://github.com/fastapi/fastapi/issues/15188) illustrates why wire-field boundaries matter; this tool does not claim to detect the intent behind such boundaries.

## 中文说明

离线分析保存的 SSE 响应正文，解释浏览器实际会派发哪些事件，并提供原始字节区间。检查 EOF 未完成事件、忽略字段、非法 retry、含 NUL 的 ID 与 UTF-8 替换解码。特别区分已提交的重连 ID 和尾部尚未提交的 ID。默认只输出长度和哈希，`--include-text` 才输出抽样内容。结束文件不等于事件分隔空行；工具不联网，也不证明网络或服务器故障。
