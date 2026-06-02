# ETHICAL USE NOTICE
# This tool is for authorised security testing and educational purposes only.
# Only scan systems you own or have explicit written permission to test.
# Unauthorised port scanning may be illegal in your jurisdiction.
# The author assumes no responsibility for misuse.

"""Port scanner v3 — concurrent, banner-grabbing, benchmarkable."""

import argparse
import errno
import logging
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, Literal

from rich import box
from rich.console import Console
from rich.table import Table

try:
    from banner_grabber import BannerGrabber  # type: ignore[import-not-found]
    from network_formatter import NetworkFormatter  # type: ignore[import-not-found]
except ImportError:
    import contextlib

    class BannerGrabber:  # type: ignore[no-redef]
        """Fallback stub when banner grabber module is unavailable."""

        def grab(self, target: str, port: int) -> None:
            """Return None — no banner grabber available."""
            return None

    class NetworkFormatter:  # type: ignore[no-redef]
        """Fallback stub when network formatter module is unavailable."""

        def print_panel(self, title: str, subtitle: str) -> None:
            """Print a plain text panel."""
            print(f"=== {title} ({subtitle}) ===")

        def progress_bar(self, total: int) -> contextlib.AbstractContextManager:
            """Return a no-op progress bar context manager."""

            class _DummyProgress:
                def add_task(self, *a: object, **kw: object) -> int:
                    return 0

                def advance(self, *a: object) -> None:
                    pass

            return contextlib.nullcontext(_DummyProgress())

        def port_table(self, results: list) -> str:
            """Return a plain text summary."""
            return f"Processed {len(results)} targets."


log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result for a single scanned port."""

    port: int
    state: Literal["open", "closed", "filtered"]
    service: str
    banner: str
    scan_ms: float


class PortScannerV3:
    """Concurrent TCP port scanner with banner grabbing and Rich output."""

    UDP_PORTS: Final[list[int]] = [53, 67, 123, 161, 500]
    TOP_PORTS: Final[list[int]] = sorted(
        set(
            [
                1,
                3,
                4,
                6,
                7,
                9,
                13,
                17,
                19,
                20,
                21,
                22,
                23,
                25,
                26,
                30,
                32,
                33,
                37,
                42,
                43,
                49,
                53,
                70,
                79,
                80,
                81,
                82,
                83,
                84,
                85,
                88,
                89,
                90,
                99,
                100,
                106,
                109,
                110,
                111,
                113,
                119,
                125,
                135,
                139,
                143,
                144,
                146,
                161,
                163,
                179,
                199,
                211,
                212,
                222,
                254,
                255,
                256,
                259,
                264,
                280,
                301,
                306,
                311,
                340,
                366,
                389,
                406,
                407,
                416,
                417,
                425,
                427,
                443,
                444,
                445,
                458,
                464,
                465,
                481,
                497,
                500,
                512,
                513,
                514,
                515,
                524,
                541,
                543,
                544,
                545,
                548,
                554,
                555,
                563,
                587,
                593,
                616,
                617,
                625,
                631,
                636,
                646,
                648,
                666,
                667,
                668,
                683,
                687,
                691,
                700,
                705,
                711,
                714,
                720,
                722,
                726,
                749,
                765,
                777,
                783,
                787,
                800,
                801,
                808,
                843,
                873,
                880,
                888,
                898,
                900,
                901,
                902,
                903,
                911,
                912,
                981,
                987,
                990,
                992,
                993,
                995,
                999,
                1000,
                1021,
                1022,
                1023,
                1024,
                1025,
                1026,
                1027,
                1028,
                1029,
                1030,
                1080,
                1099,
                1100,
                1102,
                1110,
                1433,
                1434,
                1521,
                1723,
                1900,
                2000,
                2001,
                2049,
                2100,
                2222,
                2375,
                2376,
                3000,
                3306,
                3389,
                3690,
                4000,
                4444,
                4567,
                4848,
                5000,
                5060,
                5432,
                5555,
                5900,
                5984,
                6000,
                6379,
                6666,
                7000,
                7001,
                7070,
                7443,
                7777,
                8000,
                8008,
                8009,
                8080,
                8081,
                8082,
                8083,
                8086,
                8088,
                8090,
                8180,
                8443,
                8888,
                8983,
                9000,
                9001,
                9042,
                9090,
                9092,
                9200,
                9300,
                9418,
                9999,
                10000,
                10001,
                11211,
                27017,
                27018,
                28017,
                49152,
                49153,
                49154,
                49155,
                49156,
                49157,
                50000,
                55555,
                61616,
                65000,
            ]
        )
    )
    MAX_WORKERS: Final[int] = 1024

    def __init__(
        self,
        target: str,
        max_workers: int = 100,
        timeout: float = 0.5,
        rate_limit: float | None = None,
    ) -> None:
        """Initialise scanner and resolve the target hostname.

        Args:
            target: IP address or resolvable hostname.
            max_workers: Thread pool size. Capped at MAX_WORKERS.
            timeout: Per-port connection timeout in seconds. Clamped to 0.1–10.0.
            rate_limit: Max connections per second. None = unlimited.

        Raises:
            ValueError: If target cannot be resolved.
        """
        try:
            socket.inet_aton(target)
            self.target = target
        except OSError:
            try:
                self.target = socket.gethostbyname(target)
            except socket.gaierror as exc:
                raise ValueError(f"Invalid target: {target}") from exc

        self.max_workers = max(1, min(max_workers, self.MAX_WORKERS))
        self.timeout = max(0.1, min(timeout, 10.0))
        self.rate_limit = rate_limit
        self.banner_grabber = BannerGrabber()

    def scan_port(self, port: int) -> ScanResult:
        """Connect to a single port and return its state, service, and banner.

        Args:
            port: Port number to scan (1–65535).

        Returns:
            ScanResult with state open, closed, or filtered.
        """
        if not 1 <= port <= 65535:
            return ScanResult(
                port=port, state="filtered", service="", banner="", scan_ms=0.0
            )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        banner = ""
        state: Literal["open", "closed", "filtered"] = "filtered"
        start = time.perf_counter()
        service_name = ""

        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                state = "open"
                try:
                    grabbed = self.banner_grabber.grab(self.target, port)
                    if grabbed:
                        raw = getattr(grabbed, "raw_banner", "").strip()
                        banner = raw[:80].replace("\n", " ").replace("\r", " ")
                        service_name = getattr(grabbed, "service_name", "")
                except Exception as e:  # pylint: disable=broad-exception-caught
                    log.debug("Banner grab failed on port %d: %s", port, e)
            elif result in (errno.ECONNREFUSED, errno.ENETUNREACH):
                state = "closed"
        except OSError:
            state = "filtered"
        finally:
            scan_ms = (time.perf_counter() - start) * 1000
            sock.close()

        if self.rate_limit and self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)

        return ScanResult(
            port=port,
            state=state,
            service=service_name,
            banner=banner,
            scan_ms=scan_ms,
        )

    def scan_udp_port(self, port: int) -> ScanResult:
        """Send a UDP datagram and infer port state from the response.

        UDP has no handshake — open and filtered are indistinguishable without
        protocol-specific probes. No response is treated as filtered.

        Args:
            port: Port number to probe (1–65535).

        Returns:
            ScanResult with state open, closed, or filtered.
        """
        if not 1 <= port <= 65535:
            return ScanResult(
                port=port, state="filtered", service="", banner="", scan_ms=0.0
            )

        start = time.perf_counter()
        udp_state: Literal["open", "closed", "filtered"] = "filtered"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            sock.settimeout(self.timeout)
            sock.sendto(b"", (self.target, port))
            try:
                sock.recvfrom(1024)
                udp_state = "open"
            except socket.timeout:
                udp_state = (
                    "filtered"  # open|filtered — indistinguishable without probes
                )
            except (ConnectionRefusedError, OSError) as e:
                if (
                    isinstance(e, ConnectionRefusedError)
                    or getattr(e, "errno", None) == errno.ECONNREFUSED
                ):
                    udp_state = "closed"
        except OSError:
            udp_state = "filtered"
        finally:
            scan_ms = (time.perf_counter() - start) * 1000
            sock.close()

        return ScanResult(
            port=port, state=udp_state, service="", banner="", scan_ms=scan_ms
        )

    def _scan_ports(self, ports: list[int], label: str) -> list[ScanResult]:
        """Scan a list of ports concurrently with a progress bar.

        Args:
            ports: Port numbers to scan.
            label: Description shown on the progress bar.

        Returns:
            All ScanResult objects (all states included).
        """
        results: list[ScanResult] = []
        formatter = NetworkFormatter()

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self.scan_port, port): port for port in ports}
            with formatter.progress_bar(total=len(ports)) as progress:
                task = progress.add_task(label, total=len(ports))
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        log.warning("Scan worker error: %s", e)
                    progress.advance(task)
        return results

    def scan_udp(self) -> list[ScanResult]:
        """Scan common UDP ports — DNS, DHCP, NTP, SNMP, IKE."""
        results: list[ScanResult] = []
        formatter = NetworkFormatter()

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {
                ex.submit(self.scan_udp_port, port): port for port in self.UDP_PORTS
            }
            with formatter.progress_bar(total=len(self.UDP_PORTS)) as progress:
                task = progress.add_task(
                    f"scanning UDP {self.target}...", total=len(self.UDP_PORTS)
                )
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        log.warning("UDP scan worker error: %s", e)
                    progress.advance(task)
        return [r for r in results if r.state != "closed"]

    def scan_range(self, start: int, end: int) -> list[ScanResult]:
        """Scan a port range concurrently. Returns only open results.

        Args:
            start: First port in range (clamped to 1–65535).
            end: Last port in range (clamped to 1–65535).

        Returns:
            Open ScanResult objects only.
        """
        start = max(1, min(start, 65535))
        end = max(1, min(end, 65535))
        if start > end:
            start, end = end, start
        ports = list(range(start, end + 1))
        results = self._scan_ports(ports, f"scanning {self.target}...")
        return [r for r in results if r.state == "open"]

    def scan_top_ports(self, n: int = 1000) -> list[ScanResult]:
        """Scan the top N most common ports. Returns only open results.

        Args:
            n: Number of ports to scan from TOP_PORTS list.

        Returns:
            Open ScanResult objects only.
        """
        n = max(1, min(n, len(self.TOP_PORTS)))
        ports = self.TOP_PORTS[:n]
        results = self._scan_ports(ports, f"scanning top {n} ports...")
        return [r for r in results if r.state == "open"]

    def scan_all(self) -> list[ScanResult]:
        """Scan all 65535 ports. Requires high worker count and low timeout."""
        return self.scan_range(1, 65535)

    def generate_report(self, results: list[ScanResult]) -> str:
        """Generate a markdown report from scan results.

        Args:
            results: List of open ScanResult objects.

        Returns:
            Formatted markdown string.
        """
        lines = [
            "# MarcoPolo Scan Report",
            f"**Target:** {self.target}",
            f"**Open ports:** {len(results)}",
            f"**Scanned at:** {datetime.now(timezone.utc).isoformat()}",
            "",
            "---",
            "",
        ]
        for r in results:
            lines.append(f"**{r.port}** — {r.service or 'unknown'}")
            if r.banner:
                lines.append(f"> {r.banner}")
            lines.append(f"_{r.scan_ms:.1f}ms_")
            lines.append("")
        return "\n".join(lines)


def run_benchmark(target: str) -> None:
    """Scan ports 1–1000 with 1, 100, and 500 workers and print a comparison table.

    Args:
        target: Resolved target IP address.
    """
    console = Console()
    bench_results: list[tuple[str, str]] = []

    for n_workers in [1, 100, 500]:
        scanner = PortScannerV3(target, max_workers=n_workers, timeout=0.5)
        t_start = time.perf_counter()
        scanner.scan_range(1, 1000)
        elapsed = time.perf_counter() - t_start
        bench_results.append((str(n_workers), f"{elapsed:.2f}s"))

    table = Table(
        title="[bold orange1]benchmark results[/bold orange1]",
        box=box.SIMPLE,
        header_style="bold orange1",
        border_style="grey35",
        padding=(0, 3),
        show_edge=False,
    )
    table.add_column("workers", style="orange1", justify="right")
    table.add_column("time", style="grey89")
    for workers_str, elapsed_str in bench_results:
        table.add_row(workers_str, elapsed_str)
    console.print(table)


def main() -> None:
    """Parse arguments and dispatch to the appropriate scan mode."""
    parser = argparse.ArgumentParser(
        description="Port scanner v3 — concurrent, banner-grabbing."
    )
    parser.add_argument("--target", required=True, help="Target IP or hostname.")
    parser.add_argument("--top", type=int, help="Scan top N ports.")
    parser.add_argument("--udp", action="store_true", help="Scan common UDP ports.")
    parser.add_argument("--range", dest="port_range", help="Port range e.g. 1-1000.")
    parser.add_argument("--benchmark", action="store_true", help="Run benchmark mode.")
    args = parser.parse_args()

    formatter = NetworkFormatter()
    console = Console()

    formatter.print_panel(
        "MarcoPolo — Port Scanner v3",
        f"target: {args.target}  |  ethical use only",
    )

    try:
        scanner = PortScannerV3(args.target)
    except ValueError as e:
        console.print(f"[bold red]Error:[/] {e}")
        return

    if args.benchmark:
        run_benchmark(scanner.target)
        return

    results: list[ScanResult] = []

    if args.top:
        if args.top <= 0:
            console.print("[bold red]Error:[/] --top must be greater than 0.")
            return
        results = scanner.scan_top_ports(args.top)
    elif args.port_range:
        try:
            range_start, range_end = map(int, args.port_range.split("-", 1))
            if not (1 <= range_start <= 65535 and 1 <= range_end <= 65535):
                raise ValueError
        except ValueError:
            console.print(
                "[bold red]Error:[/] --range must be START-END integers within 1–65535."
            )
            return
        results = scanner.scan_range(range_start, range_end)
    elif args.udp:
        results = scanner.scan_udp()
    else:
        parser.print_help()
        return

    console.print(formatter.port_table(results))

    safe_name = "".join(
        c for c in os.path.basename(scanner.target) if c.isalnum() or c in ".-_"
    )
    report_path = f"marco_polo_{safe_name}.md"

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(scanner.generate_report(results))
        console.print(f"[grey66]report saved → {report_path}[/grey66]")
    except OSError as e:
        console.print(f"[bold red]Error saving report:[/] {e}")


if __name__ == "__main__":
    main()
