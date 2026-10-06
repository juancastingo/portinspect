# portinspect

[![CI](https://github.com/juancastingo/portinspect/actions/workflows/ci.yml/badge.svg)](https://github.com/juancastingo/portinspect/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/portinspect.svg)](https://pypi.org/project/portinspect/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

A lightweight, zero-dependency Python library and CLI tool for inspecting local network listening ports, interfaces, processes, and exposure boundaries.

---

## Features

- 🔍 **Kernel Socket Mapping**: Directly interrogates kernel socket tables (`/proc/net/{tcp,tcp6,udp,udp6}`) and correlates socket inodes to `/proc/[pid]/fd` and system usernames.
- 🌐 **IPv4 & IPv6 Dual Stack**: Accurately maps IPv4 (`127.0.0.1`, `0.0.0.0`) and IPv6 (`::1`, `::`) bindings.
- 🛡️ **Exposure Boundary Tagging**: Differentiates between loopback/localhost bindings and dangerous all-interface (`0.0.0.0` / `::`) exposures.
- ⚡ **Zero External Dependencies**: Standard library Python 3.9+ with fast execution.
- 📦 **Rich CLI + Normalized API**: Use as an interactive terminal inspection tool or programmatic security audit library.

---

## Installation

```bash
pip install portinspect
```

---

## Python API Usage

### Inspect Local Listening Sockets

```python
from portinspect import get_listening_sockets, inspect_exposure

# Get all listening sockets
sockets = get_listening_sockets()
for s in sockets:
    print(f"Port {s.port}/{s.protocol} bound to {s.ip} (PID: {s.pid}, Process: {s.process_name})")

# Filter only publicly exposed ports (0.0.0.0 or ::)
public_sockets = get_listening_sockets(only_public=True)
for s in public_sockets:
    print(f"[!] Public exposure: Port {s.port} owned by {s.process_name or 'unknown'}")

# Generate high-level inspection report
report = inspect_exposure()
print(f"Total sockets: {report.total_sockets}, Public exposures: {report.public_exposures}")
```

---

## CLI Usage

### View Listening Sockets Table

```bash
portinspect
```

Output:
```text
PORT    PROTO  INTERFACE          EXPOSURE               PID      PROCESS            USER        
--------------------------------------------------------------------------------------------
22      TCP    0.0.0.0            ALL (0.0.0.0 / ::)     1024     sshd               root        
80      TCP    0.0.0.0            ALL (0.0.0.0 / ::)     2450     nginx              www-data    
3000    TCP    127.0.0.1          Localhost              31294    node               developer   
5432    TCP    127.0.0.1          Localhost              1420     postgres           postgres    
```

### Filter Only Publicly Exposed Ports

```bash
portinspect --public-only
```

### JSON Output for Automation

```bash
portinspect --json
```

---

## CLI Options

| Flag | Description |
| :--- | :--- |
| `--json` | Output structured JSON report |
| `--public-only` | Show only ports exposed to all interfaces |
| `--proto {tcp,udp}`| Filter by protocol |
| `--ipv {v4,v6}` | Filter by IP version |
| `-v, --version` | Display version |

---

## License

MIT License © 2026 Juan Castin
