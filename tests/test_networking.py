"""Tests for Week 5 networking tools."""

import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
)

import threading

import pytest
from banner_grabber import BannerGrabber  # pylint: disable=import-error
from marco_polo import PortScannerV3, ScanResult  # pylint: disable=import-error
from pcap_analyser import PCAPAnalyser  # pylint: disable=import-error
from socket_fundamentals import (  # pylint: disable=import-error
    run_tcp_client,
    run_tcp_server,
)


class TestTCPEcho:
    """W5-01: TCP client/server echo."""

    def test_tcp_echo(self) -> None:
        """Client sends ping, receives ping back."""
        event = threading.Event()
        thread = threading.Thread(
            target=run_tcp_server, args=("127.0.0.1", 19100, event), daemon=True
        )
        thread.start()
        event.wait(timeout=3)
        run_tcp_client("127.0.0.1", 19100, "ping")


class TestBannerGrabber:
    """W5-03: Banner grabber."""

    def test_grab_ssh_returns_banner(self) -> None:
        """grab() against port 22 returns a Banner with non-None raw_banner."""
        grabber = BannerGrabber()
        result = grabber.grab("127.0.0.1", 22)
        assert result is not None
        assert result.raw_banner is not None
        assert len(result.raw_banner) > 0

    def test_grab_closed_port_returns_none(self) -> None:
        """grab() against a closed port returns None."""
        grabber = BannerGrabber()
        result = grabber.grab("127.0.0.1", 19999)
        assert result is None


class TestPortScanner:
    """W5-04: Port scanner."""

    def test_scan_open_port(self) -> None:
        """scan_port() on port 22 returns state=open."""
        scanner = PortScannerV3("127.0.0.1")
        result = scanner.scan_port(22)
        assert isinstance(result, ScanResult)
        assert result.state == "open"

    def test_scan_closed_port(self) -> None:
        """scan_port() on a closed port returns state != open."""
        scanner = PortScannerV3("127.0.0.1")
        result = scanner.scan_port(19999)
        assert result.state != "open"

    def test_invalid_target_raises(self) -> None:
        """PortScannerV3 raises ValueError on unresolvable target."""
        with pytest.raises(ValueError):
            PortScannerV3("not.a.real.host.invalid")


class TestPCAPAnalyser:
    """W5-07: PCAP analyser."""

    PCAP_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "capture.pcap")

    @pytest.mark.skipif(
        not os.path.exists(
            os.path.join(os.path.dirname(__file__), "..", "data", "capture.pcap")
        ),
        reason="capture.pcap not present",
    )
    def test_load_returns_packets(self) -> None:
        """load() returns a non-empty list."""
        analyser = PCAPAnalyser()
        packets = analyser.load(self.PCAP_PATH)
        assert len(packets) > 0

    @pytest.mark.skipif(
        not os.path.exists(
            os.path.join(os.path.dirname(__file__), "..", "data", "capture.pcap")
        ),
        reason="capture.pcap not present",
    )
    def test_protocol_breakdown_has_tcp(self) -> None:
        """protocol_breakdown() returns dict with TCP key."""
        analyser = PCAPAnalyser()
        analyser.load(self.PCAP_PATH)
        breakdown = analyser.protocol_breakdown()
        assert "TCP" in breakdown


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
