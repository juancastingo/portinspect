from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


@dataclass
class ListeningSocket:
    port: int
    protocol: str  # TCP or UDP
    ip_version: str  # v4 or v6
    ip: str
    is_localhost: bool
    is_all_interfaces: bool
    pid: Optional[int] = None
    process_name: Optional[str] = None
    uid: Optional[int] = None
    username: Optional[str] = None

    @property
    def exposure_label(self) -> str:
        if self.is_all_interfaces:
            return "ALL (0.0.0.0 / ::)"
        if self.is_localhost:
            return "Localhost"
        return "LAN / Specific IP"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "ip_version": self.ip_version,
            "ip": self.ip,
            "is_localhost": self.is_localhost,
            "is_all_interfaces": self.is_all_interfaces,
            "exposure": self.exposure_label,
            "pid": self.pid,
            "process_name": self.process_name,
            "uid": self.uid,
            "username": self.username,
        }


@dataclass
class InspectionReport:
    total_sockets: int
    public_exposures: int
    localhost_only: int
    sockets: List[ListeningSocket]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_sockets": self.total_sockets,
            "public_exposures": self.public_exposures,
            "localhost_only": self.localhost_only,
            "sockets": [s.to_dict() for s in self.sockets],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
