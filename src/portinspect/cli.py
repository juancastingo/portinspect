from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .scanner import get_listening_sockets, inspect_exposure


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portinspect",
        description="Inspect local network listening ports, interfaces, processes, and exposure boundaries",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output inspection results as structured JSON",
    )
    parser.add_argument(
        "--public-only",
        action="store_true",
        help="Only display sockets exposed to all interfaces (0.0.0.0 or ::)",
    )
    parser.add_argument(
        "--proto",
        choices=["tcp", "udp"],
        help="Filter by protocol (tcp or udp)",
    )
    parser.add_argument(
        "--ipv",
        choices=["v4", "v6"],
        help="Filter by IP version (v4 or v6)",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="portinspect 0.1.0",
    )
    return parser


def format_table(sockets: list) -> str:
    lines = []
    lines.append(f"\n{'PORT':<7} {'PROTO':<6} {'INTERFACE':<18} {'EXPOSURE':<22} {'PID':<8} {'PROCESS':<18} {'USER':<12}")
    lines.append("-" * 92)

    for s in sockets:
        pid_str = str(s.pid) if s.pid else "-"
        proc_str = s.process_name or "-"
        user_str = s.username or "-"

        lines.append(
            f"{s.port:<7} {s.protocol:<6} {s.ip:<18} {s.exposure_label:<22} {pid_str:<8} {proc_str:<18} {user_str:<12}"
        )

    lines.append(f"\nTotal sockets listed: {len(sockets)}\n")
    return "\n".join(lines)


def main(args: Optional[List[str]] = None) -> int:
    parser = create_parser()
    parsed = parser.parse_args(args)

    if parsed.json:
        report = inspect_exposure()
        if parsed.public_only:
            report.sockets = [s for s in report.sockets if s.is_all_interfaces]
        if parsed.proto:
            report.sockets = [s for s in report.sockets if s.protocol.lower() == parsed.proto.lower()]
        if parsed.ipv:
            report.sockets = [s for s in report.sockets if s.ip_version.lower() == parsed.ipv.lower()]
        print(report.to_json())
        return 0

    sockets = get_listening_sockets(
        protocol=parsed.proto,
        ip_version=parsed.ipv,
        only_public=parsed.public_only,
    )
    print(format_table(sockets))
    return 0


if __name__ == "__main__":
    sys.exit(main())
