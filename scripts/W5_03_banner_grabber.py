"""Banner grabber and service fingerprinter using raw TCP sockets."""

import argparse
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from rich.console import Console

sys.path.append(".")
from W5_04_network_formatter import NetworkFormatter


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

    def _send_probe(self, sock: socket.socket, port: int) -> str:
        """Send protocol-appropriate probe and return raw response.
        HTTP ports get a HEAD request. FTP/SSH/SMTP/MySQL just read the banner.
        All others get a bare CRLF to trigger a response.
        """
        if port in (80, 443, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port not in (21, 22, 25, 587, 3306):
            sock.sendall(b"\r\n")
        return sock.recv(1024).decode("utf-8", errors="replace")

    def grab(self, host: str, port: int, timeout: float = 3.0) -> Banner | None:
        """Connect to host:port, send probe, return fingerprinted Banner or None on failure."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                raw = self._send_probe(sock, port)
                info = self.fingerprint(raw)
                if port in (80, 443, 8080, 8443):
                    status = raw.split("\r\n")[0]
                    server = re.search(r"Server: (.+)", raw)
                    raw = f"{status} | {server.group(1).strip()}" if server else status
                if port == 3306:
                    version = re.search(
                        r"(\d+\.\d+\.\d+[^\x00]*)\x00",
                        raw.encode("latin-1", errors="replace").decode("latin-1"),
                    )
                    auth = re.search(
                        r"(caching_sha2_password|mysql_native_password)", raw
                    )
                    raw = f"MySQL {version.group(1) if version else ''} {auth.group(1) if auth else ''}".strip()
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

    def fingerprint(self, banner: str) -> ServiceInfo:
        """Map raw banner to ServiceInfo via pattern table. Input capped at 1024 bytes.

        Patterns ordered by specificity — more specific patterns first.
        Confidence: high = strong match, medium = partial, low = unknown.
        """
        if len(banner) > 1024:
            banner = banner[:1024]

        patterns = [
            (r"SSH-(\d+\.\d+)-(\S+)", lambda m: ("ssh", m.group(1), "high")),
            (
                r"Server: (.+)|HTTP/\d\.\d \d+ .+ \| (.+)",
                lambda m: ("http", "", "high"),
            ),
            (r"220[- ](.+?)(?:ESMTP|SMTP)", lambda m: ("smtp", "", "high")),
            (r"\+OK (.+)", lambda m: ("pop3", "", "high")),
            (r"\* OK (.+)", lambda m: ("imap", "", "high")),
            (r"RFB (\d+\.\d+)", lambda m: ("vnc", m.group(1), "high")),
            (r"Redis (\S+)", lambda m: ("redis", m.group(1), "high")),
            (r"PostgreSQL (\S+)", lambda m: ("postgresql", m.group(1), "high")),
            (r"(\d+\.\d+\.\d+-\w+)", lambda m: ("mysql", m.group(1), "high")),
            (r"SMB|SAMBA", lambda m: ("smb", "", "medium")),
            (r"login:|telnet|Welcome", lambda m: ("telnet", "", "medium")),
            (r"\x03\x00", lambda m: ("rdp", "", "medium")),
            (r"220[- ](.+)", lambda m: ("ftp", "", "medium")),
        ]

        for pattern, builder in patterns:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                name, version, confidence = builder(m)
                return ServiceInfo(name=name, version=version, confidence=confidence)

        return ServiceInfo(name="unknown", version="", confidence="low")


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
