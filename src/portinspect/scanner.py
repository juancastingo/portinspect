from __future__ import annotations

import os
import pwd
import socket
import struct
from typing import Dict, List, Optional, Tuple

from .models import InspectionReport, ListeningSocket


def hex_to_ipv4(hex_str: str) -> str:
    """Convert hex string from /proc/net/tcp to IPv4 string."""
    try:
        val = int(hex_str, 16)
        raw_bytes = struct.pack("<I", val)
        return socket.inet_ntop(socket.AF_INET, raw_bytes)
    except Exception:
        return hex_str


def hex_to_ipv6(hex_str: str) -> str:
    """Convert 32-character hex string to IPv6 address string."""
    try:
        # /proc/net/tcp6 stores 4 32-bit words in little endian
        words = [bytes.fromhex(hex_str[i : i + 8])[::-1] for i in range(0, 32, 8)]
        packed = b"".join(words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return hex_str


def get_inode_process_map() -> Dict[int, Tuple[int, str]]:
    """Scan /proc/[pid]/fd to map socket inodes to (pid, process_name)."""
    inode_map: Dict[int, Tuple[int, str]] = {}
    if not os.path.isdir("/proc"):
        return inode_map

    try:
        for pid_entry in os.listdir("/proc"):
            if not pid_entry.isdigit():
                continue
            pid = int(pid_entry)

            # Read process name from /proc/[pid]/comm
            proc_name = "unknown"
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    proc_name = f.read().strip()
            except Exception:
                pass

            fd_dir = f"/proc/{pid}/fd"
            if not os.path.isdir(fd_dir):
                continue

            try:
                for fd in os.listdir(fd_dir):
                    link_target = ""
                    try:
                        link_target = os.readlink(os.path.join(fd_dir, fd))
                    except Exception:
                        continue

                    if link_target.startswith("socket:[") and link_target.endswith("]"):
                        inode_str = link_target[8:-1]
                        if inode_str.isdigit():
                            inode_map[int(inode_str)] = (pid, proc_name)
            except Exception:
                continue
    except Exception:
        pass

    return inode_map


def get_uid_map() -> Dict[int, str]:
    """Build a mapping of UID to username using system passwd database."""
    user_map: Dict[int, str] = {}
    try:
        for user in pwd.getpwall():
            user_map[user.pw_uid] = user.pw_name
    except Exception:
        pass
    return user_map


def parse_proc_net_file(
    file_path: str,
    protocol: str,
    ip_version: str,
    inode_map: Dict[int, Tuple[int, str]],
    user_map: Dict[int, str],
) -> List[ListeningSocket]:
    sockets: List[ListeningSocket] = []
    if not os.path.isfile(file_path):
        return sockets

    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
    except Exception:
        return sockets

    for idx, line in enumerate(lines):
        if idx == 0:
            continue  # Skip header
        fields = line.strip().split()
        if len(fields) < 10:
            continue

        # State check: 0A is LISTEN for TCP
        state = fields[3]
        if protocol == "TCP" and state != "0A":
            continue

        local_addr = fields[1]
        if ":" not in local_addr:
            continue
        hex_ip, hex_port = local_addr.split(":", 1)

        try:
            port = int(hex_port, 16)
        except ValueError:
            continue

        ip = hex_to_ipv4(hex_ip) if ip_version == "v4" else hex_to_ipv6(hex_ip)

        uid_raw = fields[7]
        inode_raw = fields[9]

        uid = int(uid_raw) if uid_raw.isdigit() else None
        inode = int(inode_raw) if inode_raw.isdigit() else None

        pid, proc_name = None, None
        if inode and inode in inode_map:
            pid, proc_name = inode_map[inode]

        username = user_map.get(uid) if uid is not None else None

        is_all = ip in ("0.0.0.0", "::")
        is_local = ip in ("127.0.0.1", "::1")

        sockets.append(
            ListeningSocket(
                port=port,
                protocol=protocol,
                ip_version=ip_version,
                ip=ip,
                is_localhost=is_local,
                is_all_interfaces=is_all,
                pid=pid,
                process_name=proc_name,
                uid=uid,
                username=username,
            )
        )

    return sockets


def get_listening_sockets(
    protocol: Optional[str] = None,
    ip_version: Optional[str] = None,
    only_public: bool = False,
) -> List[ListeningSocket]:
    """Inspect local listening sockets and return filtered list."""
    inode_map = get_inode_process_map()
    user_map = get_uid_map()

    all_sockets: List[ListeningSocket] = []

    # TCP v4 & v6
    all_sockets.extend(parse_proc_net_file("/proc/net/tcp", "TCP", "v4", inode_map, user_map))
    all_sockets.extend(parse_proc_net_file("/proc/net/tcp6", "TCP", "v6", inode_map, user_map))

    # UDP v4 & v6
    all_sockets.extend(parse_proc_net_file("/proc/net/udp", "UDP", "v4", inode_map, user_map))
    all_sockets.extend(parse_proc_net_file("/proc/net/udp6", "UDP", "v6", inode_map, user_map))

    # Apply filters
    filtered: List[ListeningSocket] = []
    for s in all_sockets:
        if protocol and s.protocol.upper() != protocol.upper():
            continue
        if ip_version and s.ip_version.lower() != ip_version.lower():
            continue
        if only_public and not s.is_all_interfaces:
            continue
        filtered.append(s)

    filtered.sort(key=lambda s: (s.port, s.protocol))
    return filtered


def inspect_exposure() -> InspectionReport:
    """Run full socket inspection and produce structured InspectionReport."""
    sockets = get_listening_sockets()
    public_count = sum(1 for s in sockets if s.is_all_interfaces)
    local_count = sum(1 for s in sockets if s.is_localhost)

    return InspectionReport(
        total_sockets=len(sockets),
        public_exposures=public_count,
        localhost_only=local_count,
        sockets=sockets,
    )
