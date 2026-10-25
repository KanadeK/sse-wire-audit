# Validation

Local validation on 2026-10-25: Windows, CPython 3.13.16.

- 26 unittest tests passed: standard-derived dispatch expectations, byte offsets, ID buffering, EOF discard, replacement decoding, arbitrary retry integers, input budgets, privacy of default output and subprocess CLI statuses.
- An independent EventSource 5.1.3 client (Node.js 24.14.0) received 10 original synthetic fixtures over loopback HTTP in two-byte chunks. All dispatched event type/data/ID sequences matched this implementation. Cases included split multibyte UTF-8, malformed UTF-8, CR/LF, BOM, NUL ID, ID reset, an incomplete tail and multiline data. The client is verification-only, not a runtime dependency. This is a limited compatibility check, not a browser conformance certification.
- Ruff static checks passed. Packaging and clean wheel installation are exercised by `scripts/smoke_wheel.py`; it checks both README examples, import origin and uninstall.
- Manual review verified that the byte cap is applied before parsing, text is omitted by default, JSON escapes control characters, and input content is neither executed nor modified.

The CI workflow runs independently on Windows/Linux with Python 3.10/3.13. Read its actual run for remote status. No runtime third-party dependencies or copied implementations are distributed. Known limits and diagnostic exit semantics are documented in README.
