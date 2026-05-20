"""Terminal output formatter using Rich — tables, panels, and progress for all network tools."""

import sys
import time
from dataclasses import dataclass
from typing import Literal

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

sys.path.append(".")


class NetworkFormatter:
    """Rich-based formatter for network tool output — imported by all W5 tools."""

    ACCENT = "orange1"
    TEXT = "grey89"
    MUTED = "grey54"
    DIM = "grey35"
    OPEN = "spring_green1"
    CLOSED = "indian_red"
    FILTERED = "dark_goldenrod"

    def __init__(self):
        self.console = Console()

    def port_table(self, scan_results: list) -> Table:
        """Coloured table of port scan results — open=green, closed=red, filtered=yellow."""
        table = Table(
            title=f"[bold {self.ACCENT}]port scan[/bold {self.ACCENT}]",
            box=box.SIMPLE,
            header_style=f"bold {self.ACCENT}",
            border_style=self.DIM,
            padding=(0, 3),
            show_edge=False,
        )
        table.add_column("port", style=self.ACCENT, justify="right")
        table.add_column("state", justify="left")
        table.add_column("service", style=self.TEXT)
        table.add_column("banner", style=self.MUTED)
        for scan in scan_results:
            if scan.state == "open":
                style = self.OPEN
            elif scan.state == "closed":
                style = self.CLOSED
            else:
                style = self.FILTERED
            table.add_row(
                str(scan.port), scan.state, scan.service, scan.banner, style=style
            )
        return table

    def banner_table(self, banners: list) -> Table:
        """Table of banner grab results — port, service, version, confidence."""
        table = Table(
            title=f"[bold {self.ACCENT}]banner grab[/bold {self.ACCENT}]",
            box=box.SIMPLE,
            header_style=f"bold {self.ACCENT}",
            border_style=self.DIM,
            padding=(0, 3),
            show_edge=False,
        )
        table.add_column("port", style=self.ACCENT, justify="right")
        table.add_column("service", style=self.TEXT)
        table.add_column("version", style=self.MUTED)
        table.add_column("confidence", justify="left")
        for banner in banners:
            confidence_style = (
                self.OPEN
                if banner.confidence == "high"
                else self.FILTERED if banner.confidence == "medium" else self.DIM
            )
            table.add_row(
                str(banner.port),
                banner.service_name,
                banner.version,
                f"[{confidence_style}]{banner.confidence}[/{confidence_style}]",
            )
        return table

    def packet_summary(self, packets: list) -> Table:
        """Table of captured packets — src, dst, protocol, size, info."""
        table = Table(
            title=f"[bold {self.ACCENT}]packets[/bold {self.ACCENT}]",
            box=box.SIMPLE,
            header_style=f"bold {self.ACCENT}",
            border_style=self.DIM,
            padding=(0, 3),
            show_edge=False,
        )
        table.add_column("src", style=self.ACCENT, justify="right")
        table.add_column("dst", style=self.TEXT)
        table.add_column("proto", style=self.MUTED, justify="center")
        table.add_column("size", style=self.DIM, justify="right")
        table.add_column("info", style=self.MUTED)
        for packet in packets:
            table.add_row(
                packet["src"],
                packet["dst"],
                packet["protocol"],
                f"{packet['size']}B",
                packet["info"],
            )
        return table

    def progress_bar(self, total: int) -> Progress:
        """Return a styled Rich Progress context manager — caller controls the loop."""
        return Progress(
            SpinnerColumn(style=self.ACCENT),
            TextColumn(f"[{self.ACCENT}]{{task.description}}"),
            BarColumn(
                bar_width=36,
                style=self.DIM,
                complete_style=self.ACCENT,
                finished_style=self.OPEN,
            ),
            TextColumn(f"[{self.MUTED}]{{task.completed}}/{{task.total}}"),
            console=self.console,
        )

    def print_panel(self, title: str, content: str, style: str = None) -> None:
        """Print a minimal Rich panel with title and content to the terminal."""
        self.console.print()
        self.console.print(
            Panel(
                f"[{self.TEXT}]{content}[/{self.TEXT}]",
                title=f"[bold {self.ACCENT}]{title}[/bold {self.ACCENT}]",
                border_style=style or self.DIM,
                padding=(0, 3),
                expand=False,
            )
        )
        self.console.print()


if __name__ == "__main__":
    console = Console()
    formatter = NetworkFormatter()

    @dataclass
    class MockBanner:
        port: int
        service_name: str
        version: str
        confidence: Literal["high", "medium", "low"]

    @dataclass
    class MockScan:
        port: int
        state: str
        service: str
        banner: str

    formatter.print_panel(
        "W5-09 — output_formatter.py",
        "NetworkFormatter loaded. All W5 tools use this module.",
    )

    banners = [
        MockBanner(22, "SSH-OpenSSH_10.3p1", "2.0", "high"),
        MockBanner(80, "Apache/2.4.66 (Debian)", "", "high"),
        MockBanner(21, "vsftpd", "", "medium"),
        MockBanner(9999, "unknown", "", "low"),
    ]
    console.print(formatter.banner_table(banners))
    console.print()

    scans = [
        MockScan(22, "open", "ssh", "OpenSSH_10.3p1"),
        MockScan(80, "open", "http", "Apache/2.4.66"),
        MockScan(443, "closed", "https", ""),
        MockScan(8080, "filtered", "http-alt", ""),
    ]
    console.print(formatter.port_table(scans))
    console.print()

    packets = [
        {
            "src": "192.168.1.1",
            "dst": "8.8.8.8",
            "protocol": "DNS",
            "size": 64,
            "info": "query google.com",
        },
        {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "protocol": "TCP",
            "size": 128,
            "info": "SYN port 80",
        },
        {
            "src": "172.16.0.5",
            "dst": "172.16.0.1",
            "protocol": "ICMP",
            "size": 84,
            "info": "echo request",
        },
    ]
    console.print(formatter.packet_summary(packets))
    console.print()

    with formatter.progress_bar(total=20) as progress:
        task = progress.add_task("scanning...", total=20)
        for _ in range(20):
            time.sleep(0.05)
            progress.advance(task)

    console.print()
    formatter.print_panel("done", "all formatters verified.")
