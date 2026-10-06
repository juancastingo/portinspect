import json
import pytest
from portinspect import (
    ListeningSocket,
    InspectionReport,
    get_listening_sockets,
    inspect_exposure,
)
from portinspect.scanner import hex_to_ipv4, hex_to_ipv6, parse_proc_net_file
from portinspect.cli import main as cli_main


def test_ip_hex_decoding():
    # 0100007F in little endian hex is 127.0.0.1
    assert hex_to_ipv4("0100007F") == "127.0.0.1"
    # 00000000 is 0.0.0.0
    assert hex_to_ipv4("00000000") == "0.0.0.0"


def test_listening_socket_model():
    sock = ListeningSocket(
        port=5432,
        protocol="TCP",
        ip_version="v4",
        ip="0.0.0.0",
        is_localhost=False,
        is_all_interfaces=True,
        pid=1234,
        process_name="postgres",
        uid=999,
        username="postgres",
    )

    assert sock.exposure_label == "ALL (0.0.0.0 / ::)"
    d = sock.to_dict()
    assert d["port"] == 5432
    assert d["process_name"] == "postgres"
    assert d["exposure"] == "ALL (0.0.0.0 / ::)"


def test_live_socket_inspection():
    report = inspect_exposure()
    assert isinstance(report, InspectionReport)
    assert report.total_sockets >= 0
    assert report.public_exposures >= 0

    sockets = get_listening_sockets()
    assert isinstance(sockets, list)
    if sockets:
        first = sockets[0]
        assert isinstance(first.port, int)
        assert first.protocol in ("TCP", "UDP")


def test_filtered_socket_inspection():
    tcp_socks = get_listening_sockets(protocol="TCP")
    for s in tcp_socks:
        assert s.protocol == "TCP"

    udp_socks = get_listening_sockets(protocol="UDP")
    for s in udp_socks:
        assert s.protocol == "UDP"


def test_cli_execution(capsys):
    ret = cli_main(["--json"])
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "total_sockets" in data
    assert "sockets" in data
