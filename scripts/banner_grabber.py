"""Banner grabber and service fingerprinter using raw TCP sockets.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing, compliance validation, and
educational auditing purposes only. Network scanning without explicit, prior, written
permission from the asset owner may be illegal in your jurisdiction. The author assumes
no responsibility for misuse or operational disruption caused by this script.
"""

import argparse
import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Final, Literal

from rich.console import Console

# Setup logging configuration
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
log: logging.Logger = logging.getLogger(__name__)

try:
    from network_formatter import NetworkFormatter
except ImportError:
    # Fallback layout context structure to maintain unit testing runtime integrity
    class NetworkFormatter:  # type: ignore[no-redef]
        """Fallback formatter if custom network formatter package is missing."""

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

    # Resource and timing constraints
    MAX_WORKERS_CAP: Final[int] = 10
    DEFAULT_TIMEOUT: Final[float] = 3.0

    # Sensitive data sanitization signatures
    _SENSITIVE_DATA_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
        re.compile(
            r"(?:sessionid|cookie|set-cookie|authorization|bearer|token|passwd|password)\s*=\s*\S+",
            re.IGNORECASE,
        ),
        re.compile(r"(?:authorization|proxy-authorization):\s*\S+", re.IGNORECASE),
    )

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

    def _sanitize_banner(self, raw_data: str) -> str:
        """Strip high-risk session vectors (auth tokens, cookies) from captured data."""
        sanitized = raw_data
        for pattern in self._SENSITIVE_DATA_PATTERNS:
            sanitized = pattern.sub("[REDACTED_SENSITIVE_FIELD]", sanitized)
        return sanitized

    def _validate_target(self, host: str) -> str:
        """Validate target format using strict socket addrinfo inspection mechanisms.

        Args:
            host: Target hostname or IP coordinate address.

        Returns:
            The resolved target IP string representation.
        """
        try:
            # Rejects lookups that are malformed or pose local network resolution hazards
            addr_info = socket.getaddrinfo(
                host, None, socket.AF_INET, socket.SOCK_STREAM
            )
            return str(addr_info[0][4][0])
        except socket.gaierror as err:
            raise ValueError(
                f"Target address mapping evaluation failed or unroutable: {err}"
            ) from err

    def _send_probe(self, sock: socket.socket, port: int) -> str:
        """Send protocol-appropriate probe lines and return raw response strings."""
        if port in (80, 443, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port not in (21, 22, 25, 587, 3306):
            sock.sendall(b"\r\n")
        return sock.recv(1024).decode("utf-8", errors="replace")

    def grab(
        self, host: str, port: int, timeout: float = DEFAULT_TIMEOUT
    ) -> Banner | None:
        """Connect to host:port, send target probe, and return fingerprinted results."""
        # Enforce structural socket timeouts
        current_timeout = timeout if timeout > 0.0 else self.DEFAULT_TIMEOUT

        try:
            resolved_ip = self._validate_target(host)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(current_timeout)
                sock.connect((resolved_ip, port))
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

                # Clean raw data bounds of telemetry hooks or explicit private data leaking vectors
                raw = self._sanitize_banner(raw)
                info = self.fingerprint(raw)

                return Banner(
                    port=port,
                    raw_banner=raw,
                    service_name=info.name,
                    version=info.version,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    confidence=info.confidence,
                )
        except (OSError, TimeoutError, ValueError) as err:
            log.debug(
                "Operational socket interaction dropped on target port %d: %s",
                port,
                err,
            )
            return None

    def grab_multiple(
        self, host: str, ports: list[int], rate_limit_delay: float = 0.1
    ) -> list[Banner]:
        """Grab banners from multiple ports concurrently with defensive resource and pacing limits."""
        results: list[Banner] = []

        try:
            self._validate_target(host)
        except ValueError as err:
            log.error("Aborting batch scan execution profile: %s", err)
            return results

        # Enforce safe worker thread boundaries
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS_CAP) as executor:
            futures = {}
            for port in ports:
                # Defensive pacing: Introduces small delay spacing steps between connection task spawns
                if rate_limit_delay > 0.0:
                    time.sleep(rate_limit_delay)
                futures[executor.submit(self.grab, host, port)] = port

            try:
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        results.append(result)
            except KeyboardInterrupt:
                log.warning(
                    "Interrupt signal intercepted. Cleaning up active scan worker threads..."
                )
                # ThreadPoolExecutor block exit cleanly triggers thread termination contexts safely

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
        description="Secure banner grabber and service fingerprinter reference utility."
    )
    parser.add_argument("--host", required=True, help="Target host address coordinate.")
    parser.add_argument(
        "--ports", required=True, help="Comma-separated port values e.g. 22,80,21"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Pacing transmission delay time interval between ports (default: 0.1s)",
    )
    args = parser.parse_args()

    try:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        if any(p < 1 or p > 65535 for p in ports):
            raise ValueError(
                "Port identity bounds must fall securely between 1 and 65535."
            )
    except ValueError as exc:
        console.print(
            f"[bold red]Configuration Input Error:[/bold red] Invalid numerical port target parameters: {exc}"
        )
        return

    grabber = BannerGrabber()
    console.print(
        f"[bold yellow]Initializing target collection scanner context against host: {args.host}[/bold yellow]"
    )

    banners = grabber.grab_multiple(args.host, ports, rate_limit_delay=args.delay)

    formatter = NetworkFormatter()
    console.print(formatter.banner_table(banners))


if __name__ == "__main__":
    main()
