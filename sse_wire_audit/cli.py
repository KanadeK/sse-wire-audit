import argparse
import json
import sys

from . import __version__
from .core import InputError, audit_file


def positive(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Explain browser dispatch and EOF loss in a local SSE body capture."
    )
    parser.add_argument("file", help="raw UTF-8 response body; no headers or HTTP chunk framing")
    parser.add_argument(
        "--include-text",
        action="store_true",
        help="include sampled data, type and ID text; may expose secrets",
    )
    parser.add_argument("--samples", type=positive, default=20)
    parser.add_argument("--max-bytes", type=positive, default=16777216)
    parser.add_argument("--max-line-bytes", type=positive, default=1048576)
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        report = audit_file(
            args.file,
            include_text=args.include_text,
            samples=args.samples,
            max_bytes=args.max_bytes,
            max_line_bytes=args.max_line_bytes,
        )
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return int(report["findings"])
    except InputError as exc:
        print(json.dumps({"complete": False, "error": str(exc)}), file=sys.stderr)
        return 2
    except OSError:
        print('{"complete": false, "error": "input or output unavailable"}', file=sys.stderr)
        return 2
