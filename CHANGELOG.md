# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-06

### Added
- Initial public release of `portinspect`.
- Pure Python discovery of local listening sockets via `/proc/net/{tcp,tcp6,udp,udp6}`.
- Inode resolution mapping open sockets to PIDs and command names.
- UID to system username resolution.
- Dual-stack IPv4 and IPv6 support.
- Public interface exposure flagging (`0.0.0.0` or `::`).
- Programmatic API (`get_listening_sockets`, `inspect_exposure`).
- CLI tool with formatted tables, `--json`, and `--public-only` filtering.
