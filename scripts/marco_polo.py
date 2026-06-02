# ETHICAL USE NOTICE
# This tool is for authorised security testing and educational purposes only.
# Only scan systems you own or have explicit written permission to test.
# Unauthorised port scanning may be illegal in your jurisdiction.
# The author assumes no responsibility for misuse.

"""Port scanner v3 — concurrent, banner-grabbing, benchmarkable."""

import argparse
import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from rich import box
from rich.console import Console
from rich.table import Table
from W5_03_banner_grabber import BannerGrabber
from W5_04_network_formatter import NetworkFormatter


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

    UDP_PORTS: list[int] = [53, 67, 123, 161, 500]
    TOP_PORTS: list[int] = sorted(
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

    def __init__(
        self,
        target: str,
        max_workers: int = 500,
        timeout: float = 0.5,
        rate_limit: float | None = None,
    ) -> None:
        """Initialise scanner and resolve the target hostname.

        Args:
            target: IP address or resolvable hostname.
            max_workers: Thread pool size.
            timeout: Per-port connection timeout in seconds.
            rate_limit: Max connections per second. None = unlimited.

        Raises:
            ValueError: If target cannot be resolved.
        """
        self.target = target
        try:
            socket.inet_aton(target)
        except OSError:
            try:
                socket.gethostbyname(target)
            except socket.gaierror as exc:
                raise ValueError(f"Invalid target: {target}") from exc
        self.max_workers = max_workers
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.banner_grabber = BannerGrabber()

    def scan_port(self, port: int) -> ScanResult:
        """Connect to port, return state, service name, banner, and scan time."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        banner = ""
        state: Literal["open", "closed", "filtered"] = "filtered"
        start = time.time()
        service_name = ""
        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                state = "open"
                grabbed = self.banner_grabber.grab(self.target, port)
                if grabbed:
                    banner = grabbed.raw_banner.strip()
                    service_name = grabbed.service_name
            elif result == errno.ECONNREFUSED:
                state = "closed"
            else:
                state = "filtered"
        except OSError:
            state = "filtered"
        finally:
            scan_ms = (time.time() - start) * 1000
            sock.close()

        if self.rate_limit:
            time.sleep(1 / self.rate_limit)
        return ScanResult(
            port=port,
            state=state,
            service=service_name,
            banner=banner,
            scan_ms=scan_ms,
        )

    def scan_udp_port(self, port: int) -> ScanResult:
        """Send UDP datagram and infer port state from response.

        UDP has no handshake — ambiguity is inherent:
        - ICMP port unreachable (ECONNREFUSED) → closed
        - No response → open|filtered (cannot distinguish without protocol probes)
        """
        start = time.time()
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
                    "filtered"  # open|filtered — cannot distinguish without probes
                )
            except ConnectionRefusedError:
                udp_state = "closed"
        except OSError:
            udp_state = "filtered"
        finally:
            scan_ms = (time.time() - start) * 1000
            sock.close()

        return ScanResult(
            port=port,
            state=udp_state,
            service="",
            banner="",
            scan_ms=scan_ms,
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
                    results.append(future.result())
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
                    results.append(future.result())
                    progress.advance(task)
        return [r for r in results if r.state != "closed"]

    def scan_range(self, start: int, end: int) -> list[ScanResult]:
        """Scan a port range concurrently. Returns only open results."""
        ports = list(range(start, end + 1))
        results = self._scan_ports(ports, f"scanning {self.target}...")
        return [r for r in results if r.state == "open"]

    def scan_top_ports(self, n: int = 1000) -> list[ScanResult]:
        """Scan top N most common ports using nmap's frequency list."""
        ports = self.TOP_PORTS[:n]
        results = self._scan_ports(ports, f"scanning top {n} ports...")
        return [r for r in results if r.state == "open"]

    def scan_all(self) -> list[ScanResult]:
        """Scan all 65535 ports. Requires high worker count and low timeout."""
        return self.scan_range(1, 65535)

    def generate_report(self, results: list[ScanResult]) -> str:
        """Generate a markdown report from scan results."""
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
            lines.append(f"**{r.port}** — {r.service}")
            if r.banner:
                lines.append(f"> {r.banner[:80].strip()}")
            lines.append(f"_{r.scan_ms:.1f}ms_")
            lines.append("")
        return "\n".join(lines)


def run_benchmark(target: str) -> None:
    """Scan ports 1–1000 with 1, 100, and 500 workers and print a comparison table."""
    console = Console()
    bench_results: list[tuple[str, str]] = []
    for n_workers in [1, 100, 500]:
        scanner = PortScannerV3(target, max_workers=n_workers, timeout=0.5)
        t_start = time.time()
        scanner.scan_range(1, 1000)
        elapsed = time.time() - t_start
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
    """CLI entry point — parse arguments and dispatch to the appropriate scan mode."""
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

    if args.benchmark:
        run_benchmark(args.target)
        return

    scanner = PortScannerV3(args.target)

    if args.top:
        results = scanner.scan_top_ports(args.top)
    elif args.port_range:
        range_start, range_end = map(int, args.port_range.split("-"))
        results = scanner.scan_range(range_start, range_end)
    elif args.udp:
        results = scanner.scan_udp()
    else:
        parser.print_help()
        return

    console.print(formatter.port_table(results))
    report = scanner.generate_report(results)
    report_path = f"marco_polo_{args.target}.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    console.print(f"[grey66]report saved → {report_path}[/grey66]")


if __name__ == "__main__":
    main()
