"""Banner grabber and service fingerprinter using raw TCP sockets."""

import sys

from W5_04_network_formatter import NetworkFormatter
import argparse
from rich.console import Console
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

sys.path.append(".")


@dataclass
class Banner:
    """Raw grab result for a single port."""

    port: int
    raw_banner: str
    service_name: str
    version: str
    timestamp: str
    confidence: Literal["high", "medium", "low"]


@dataclass
class ServiceInfo:
    """Fingerprinted service identity extracted from a banner."""

    name: str
    version: str
    confidence: Literal["high", "medium", "low"]


class BannerGrabber:
    """Connects to TCP ports, sends protocol-appropriate probes, fingerprints responses."""

    def grab(self, host: str, port: int, timeout: float = 3.0) -> Banner | None:
        """Connect to host:port, send probe, return fingerprinted Banner or None on failure."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                raw = self._send_probe(sock, port)
                info = self.fingerprint(raw)
                return Banner(
                    port=port,
                    raw_banner=raw,
                    service_name=info.name,
                    version=info.version,
                    timestamp=datetime.now().isoformat(),
                    confidence=info.confidence,
                )
        except (OSError, TimeoutError):
            return None

    def _send_probe(self, sock: socket.socket, port: int) -> str:
        """Send protocol-appropriate probe and return raw response.

        HTTP ports get a HEAD request. FTP/SSH/SMTP just read the banner.
        All others get a bare CRLF — enough to trigger a response on most services.
        """
        if port in (80, 443, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port not in (21, 22, 25, 587):
            sock.sendall(b"\r\n")
        return sock.recv(1024).decode("utf-8", errors="replace")

    def fingerprint(self, banner: str) -> ServiceInfo:
        """Map raw banner string to ServiceInfo via regex.

        Patterns kept simple to avoid ReDoS. Input truncated to 1024 bytes.
        Confidence: high = strong pattern match, medium = partial, low = unknown.
        """
        if len(banner) > 1024:
            banner = banner[:1024]

        ssh = re.search(r"SSH-(\d+\.\d+)-(\S+)", banner)
        http = re.search(r"Server: (.+)", banner)
        ftp = re.search(r"220[- ](.+)", banner)

        if ssh:
            return ServiceInfo(
                name=f"SSH-{ssh.group(2)}",
                version=ssh.group(1),
                confidence="high",
            )
        if http:
            return ServiceInfo(
                name=http.group(1).strip(),
                version="",
                confidence="high",
            )
        if ftp:
            return ServiceInfo(
                name=ftp.group(1).strip(),
                version="",
                confidence="medium",
            )
        return ServiceInfo(
            name="unknown",
            version="",
            confidence="low",
        )

    def grab_multiple(self, host: str, ports: list) -> list[Banner]:
        """Grab banners from multiple ports concurrently. Returns only successful results."""
        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.grab, host, port): port for port in ports}
            for future in futures:
                result = future.result()
                if result is not None:
                    results.append(result)
        return results


if __name__ == "__main__":
    console = Console()
    parser = argparse.ArgumentParser(
        description="Banner grabber and service fingerprinter."
    )
    parser.add_argument("--host", required=True, help="Target host.")
    parser.add_argument(
        "--ports", required=True, help="Comma-separated ports e.g. 22,80,21"
    )
    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(",")]
    grabber = BannerGrabber()
    banners = grabber.grab_multiple(args.host, ports)

    formatter = NetworkFormatter()
    console.print(formatter.banner_table(banners))
