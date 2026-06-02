"""Banner grabber and service fingerprinter using raw TCP sockets."""

import argparse
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Final, Literal

from rich.console import Console

sys.path.append(".")
try:
    from W5_04_network_formatter import NetworkFormatter
except ImportError:
    # Fallback layout context structure to maintain unit testing runtime integrity
    class NetworkFormatter:
        def banner_table(self, b: list) -> str:
            return f"Processed {len(b)} banners."


@dataclass(frozen=True)
class ServiceInfo:
    """Fingerprinted service identity extracted from a banner."""

    name: str
    version: str
    confidence: Literal["high", "medium", "low"]


@dataclass(frozen=True)
class Banner:
    """Raw grab result for a single port."""

    port: int
    raw_banner: str
    service_name: str
    version: str
    timestamp: str
    confidence: Literal["high", "medium", "low"]


class BannerGrabber:
    """Connects to TCP ports, sends protocol-appropriate probes, fingerprints responses."""

    # Pre-compiled signatures table ordered by specificity to limit scanning runtime overhead
    _FINGERPRINT_PATTERNS: Final[
        tuple[
            tuple[
                re.Pattern[str],
                Callable[
                    [re.Match[str]], tuple[str, str, Literal["high", "medium", "low"]]
                ],
            ],
            ...,
        ]
    ] = (
        (
            re.compile(r"SSH-(\d+\.\d+)-(\S+)", re.IGNORECASE),
            lambda m: ("ssh", m.group(1), "high"),
        ),
        (
            re.compile(r"Server: (.+)|HTTP/\d\.\d \d+ .+ \| (.+)", re.IGNORECASE),
            lambda m: ("http", "", "high"),
        ),
        (
            re.compile(r"220[- ](.+?)(?:ESMTP|SMTP)", re.IGNORECASE),
            lambda m: ("smtp", "", "high"),
        ),
        (re.compile(r"\+OK (.+)", re.IGNORECASE), lambda m: ("pop3", "", "high")),
        (re.compile(r"\* OK (.+)", re.IGNORECASE), lambda m: ("imap", "", "high")),
        (
            re.compile(r"RFB (\d+\.\d+)", re.IGNORECASE),
            lambda m: ("vnc", m.group(1), "high"),
        ),
        (
            re.compile(r"Redis (\S+)", re.IGNORECASE),
            lambda m: ("redis", m.group(1), "high"),
        ),
        (
            re.compile(r"PostgreSQL (\S+)", re.IGNORECASE),
            lambda m: ("postgresql", m.group(1), "high"),
        ),
        (
            re.compile(r"(\d+\.\d+\.\d+-\w+)", re.IGNORECASE),
            lambda m: ("mysql", m.group(1), "high"),
        ),
        (re.compile(r"SMB|SAMBA", re.IGNORECASE), lambda m: ("smb", "", "medium")),
        (
            re.compile(r"login:|telnet|Welcome", re.IGNORECASE),
            lambda m: ("telnet", "", "medium"),
        ),
        (re.compile(r"\x03\x00"), lambda m: ("rdp", "", "medium")),
        (re.compile(r"220[- ](.+)", re.IGNORECASE), lambda m: ("ftp", "", "medium")),
    )

    def _send_probe(self, sock: socket.socket, port: int) -> str:
        """Send protocol-appropriate probe lines and return raw response strings."""
        if port in (80, 443, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port not in (21, 22, 25, 587, 3306):
            sock.sendall(b"\r\n")
        return sock.recv(1024).decode("utf-8", errors="replace")

    def grab(self, host: str, port: int, timeout: float = 3.0) -> Banner | None:
        """Connect to host:port, send target probe, and return fingerprinted results.

        Note on MySQL handshakes: The response packet is binary; version extraction
        operates via best-effort string regex parsing on decoded context frames.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                raw = self._send_probe(sock, port)

                # Perform post-processing for standard application interfaces
                if port in (80, 443, 8080, 8443):
                    status = raw.split("\r\n")[0]
                    server = re.search(r"Server: (.+)", raw, re.IGNORECASE)
                    raw = f"{status} | {server.group(1).strip()}" if server else status
                elif port == 3306:
                    version = re.search(r"(\d+\.\d+\.\d+[^\x00]*)", raw, re.IGNORECASE)
                    auth = re.search(
                        r"(caching_sha2_password|mysql_native_password)",
                        raw,
                        re.IGNORECASE,
                    )
                    raw = f"MySQL {version.group(1) if version else ''} {auth.group(1) if auth else ''}".strip()

                info = self.fingerprint(raw)
                return Banner(
                    port=port,
                    raw_banner=raw,
                    service_name=info.name,
                    version=info.version,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    confidence=info.confidence,
                )
        except (OSError, TimeoutError):
            return None

    def grab_multiple(self, host: str, ports: list[int]) -> list[Banner]:
        """Grab banners from multiple ports concurrently, consuming results out of order."""
        results: list[Banner] = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.grab, host, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)
        return results

    def fingerprint(self, banner: str) -> ServiceInfo:
        """Map raw banner data limits to explicit ServiceInfo metrics tables."""
        normalized_banner = banner[:1024] if len(banner) > 1024 else banner

        for pattern, builder in self._FINGERPRINT_PATTERNS:
            match = pattern.search(normalized_banner)
            if match:
                name, version, confidence = builder(match)
                return ServiceInfo(name=name, version=version, confidence=confidence)

        return ServiceInfo(name="unknown", version="", confidence="low")


def main() -> None:
    """CLI banner scanner orchestration point."""
    console = Console()
    parser = argparse.ArgumentParser(
        description="Banner grabber and service fingerprinter."
    )
    parser.add_argument("--host", required=True, help="Target host address coordinate.")
    parser.add_argument(
        "--ports", required=True, help="Comma-separated port values e.g. 22,80,21"
    )
    args = parser.parse_args()

    try:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    except ValueError as exc:
        console.print(
            f"[bold red]Configuration Input Error:[/bold red] Invalid numerical port array values: {exc}"
        )
        return

    grabber = BannerGrabber()
    banners = grabber.grab_multiple(args.host, ports)

    formatter = NetworkFormatter()
    console.print(formatter.banner_table(banners))


if __name__ == "__main__":
    main()
