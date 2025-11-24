from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import render_table
from .scanner import EndpointScanner


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan IP endpoints for common protocols and identify likely device types. "
            "Provide a text file with one IP address per line."
        )
    )
    parser.add_argument("input", type=Path, help="Path to text file containing IP addresses")
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Socket timeout (seconds) for each protocol probe (default: 0.5)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=32,
        help="Maximum number of parallel scans (default: 32)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write the report instead of printing to stdout",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    scanner = EndpointScanner(timeout=args.timeout, max_workers=args.workers)
    try:
        results = scanner.scan_file(str(args.input))
    except FileNotFoundError:
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 1

    table = render_table(results)
    if args.output:
        args.output.write_text(table + "\n", encoding="utf-8")
    else:
        print(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
