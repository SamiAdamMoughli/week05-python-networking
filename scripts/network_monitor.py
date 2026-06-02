# ETHICAL USE NOTICE
# This tool is for authorised security testing and educational purposes only.
# Only monitor networks you own or have explicit written permission to monitor.
# Unauthorised network monitoring may be illegal in your jurisdiction.
# The author assumes no responsibility for misuse.

"""Live network monitor with Rich dashboard and anomaly detection.

Usage:
    sudo python network_monitor.py --interface lo
    sudo python network_monitor.py --interface eth0 --alert-threshold 20
"""

import argparse
import logging
import queue
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Final

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import scapy.all as scapy  # Clean namespace tracking to ensure type consistency

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
log: logging.Logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

SUSPICIOUS_PORTS: Final[frozenset[int]] = frozenset(
    {
        31337,
        4444,
        1337,
        6667,
        6668,
        6669,  # common C2 / IRC
        9001,
        9050,  # Tor
        5554,
        16660,  # Sasser / Slapper worm ports
        12345,
        54321,  # classic backdoors
    }
)

JUMBO_FRAME_THRESHOLD: Final[int] = 9000  # bytes
PORT_SCAN_WINDOW: Final[float] = 10.0  # seconds
MAX_RECENT_PACKETS: Final[int] = 10
MAX_ALERTS: Final[int] = 20
TOP_N: Final[int] = 5

# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class PacketSummary:
    """Condensed representation of a single captured packet."""

    timestamp: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: str
    flags: str
    size: int


@dataclass
class TrafficStats:
    """Aggregate traffic counters updated on every packet."""

    total: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    other: int = 0
    total_bytes: int = 0
    start_time: float = field(default_factory=time.time)

    def elapsed(self) -> float:
        """Return seconds since monitoring started."""
        return max(time.time() - self.start_time, 1.0)

    def packets_per_sec(self) -> float:
        """Return average packets per second."""
        return self.total / self.elapsed()

    def bytes_per_sec(self) -> float:
        """Return average bytes per second."""
        return self.total_bytes / self.elapsed()


# ── NetworkMonitor ────────────────────────────────────────────────────────────


class NetworkMonitor:
    """Live network monitor — captures packets, detects anomalies, renders dashboard.

    All packet processing happens in a background thread. The main thread runs
    the Rich Live display loop, draining the packet queue and refreshing panels
    on each update interval.
    """

    def __init__(
        self,
        interface: str = "lo",
        update_interval: float = 1.0,
        alert_threshold: int = 20,
        bpf_filter: str = "",
    ) -> None:
        """Initialise the network monitor."""
        self.interface: str = interface
        self.update_interval: float = update_interval
        self.alert_threshold: int = alert_threshold
        self.bpf_filter: str = bpf_filter

        self._packet_queue: queue.Queue[scapy.Packet] = queue.Queue()
        self._stop_event: threading.Event = threading.Event()
        self._sniff_thread: threading.Thread | None = None

        self.stats: TrafficStats = TrafficStats()
        self.recent_packets: deque[PacketSummary] = deque(maxlen=MAX_RECENT_PACKETS)
        self.alerts: deque[str] = deque(maxlen=MAX_ALERTS)
        self.src_counters: defaultdict[str, int] = defaultdict(int)
        self.dst_counters: defaultdict[str, int] = defaultdict(int)

        # Port scan detection: src_ip → list of (timestamp, port) tuples
        self._port_scan_tracker: defaultdict[str, list[tuple[float, int]]] = (
            defaultdict(list)
        )
        self._lock: threading.Lock = threading.Lock()

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self) -> None:
        """Start sniffing in a background thread and launch the Live display loop."""
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="sniff-loop"
        )
        self._sniff_thread.start()

        console = Console()
        layout = self._build_layout()

        with Live(layout, console=console, refresh_per_second=4, screen=True):
            try:
                while not self._stop_event.is_set():
                    self._process_queue()
                    self._update_layout(layout)
                    time.sleep(self.update_interval)
            except KeyboardInterrupt:
                pass

        self.stop()

    def stop(self) -> None:
        """Signal the sniff loop to stop and wait for the thread to join."""
        self._stop_event.set()
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=3.0)

    # ── Internal: sniffing ────────────────────────────────────────────────────

    def _sniff_loop(self) -> None:
        """Run Scapy sniff in background, feeding packets into the queue."""
        scapy.sniff(
            iface=self.interface,
            filter=self.bpf_filter or None,
            prn=self._packet_queue.put,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def _process_queue(self) -> None:
        """Drain the packet queue and update all stats and counters."""
        while True:
            try:
                pkt = self._packet_queue.get_nowait()
                self._process_packet(pkt)
            except queue.Empty:
                break

    def _process_packet(self, pkt: scapy.Packet) -> None:
        """Extract fields from a packet and update stats, counters, and alerts."""
        with self._lock:
            size = len(pkt)
            self.stats.total += 1
            self.stats.total_bytes += size

            if not pkt.haslayer(scapy.IP):
                self.stats.other += 1
                return

            src_ip: str = str(pkt[scapy.IP].src)
            dst_ip: str = str(pkt[scapy.IP].dst)
            self.src_counters[src_ip] += 1
            self.dst_counters[dst_ip] += 1

            src_port: int | None = None
            dst_port: int | None = None
            flags = ""
            protocol = "Other"

            if pkt.haslayer(scapy.TCP):
                self.stats.tcp += 1
                protocol = "TCP"
                src_port = int(pkt[scapy.TCP].sport)
                dst_port = int(pkt[scapy.TCP].dport)
                flags = str(pkt[scapy.TCP].flags)
                self._detect_port_scan(src_ip, dst_port)
                self._detect_suspicious_port(dst_port, src_ip)
            elif pkt.haslayer(scapy.UDP):
                self.stats.udp += 1
                protocol = "UDP"
                src_port = int(pkt[scapy.UDP].sport)
                dst_port = int(pkt[scapy.UDP].dport)
                self._detect_suspicious_port(dst_port, src_ip)
            elif pkt.haslayer(scapy.ICMP):
                self.stats.icmp += 1
                protocol = "ICMP"
            else:
                self.stats.other += 1

            self._detect_large_transfer(size, src_ip)

            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            self.recent_packets.append(
                PacketSummary(
                    timestamp=ts,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    flags=flags,
                    size=size,
                )
            )

    # ── Anomaly detection ─────────────────────────────────────────────────────

    def _detect_port_scan(self, src_ip: str, dst_port: int) -> None:
        """Flag src_ip if it contacts more than alert_threshold unique ports in the window."""
        now = time.time()
        entries = self._port_scan_tracker[src_ip]
        entries.append((now, dst_port))

        cutoff = now - PORT_SCAN_WINDOW
        self._port_scan_tracker[src_ip] = [e for e in entries if e[0] >= cutoff]

        unique_ports = {e[1] for e in self._port_scan_tracker[src_ip]}
        if len(unique_ports) >= self.alert_threshold:
            alert = (
                f"[bold red]PORT SCAN[/] {src_ip} → "
                f"{len(unique_ports)} ports in {PORT_SCAN_WINDOW:.0f}s"
            )
            if alert not in self.alerts:
                self.alerts.appendleft(alert)
            self._port_scan_tracker[src_ip] = []

    def _detect_large_transfer(self, size: int, src_ip: str) -> None:
        """Flag packets exceeding the jumbo frame threshold."""
        if size > JUMBO_FRAME_THRESHOLD:
            self.alerts.appendleft(
                f"[bold yellow]LARGE PACKET[/] {src_ip} — {size:,} bytes "
                f"(>{JUMBO_FRAME_THRESHOLD:,})"
            )

    def _detect_suspicious_port(self, port: int, src_ip: str) -> None:
        """Flag connections to known suspicious ports."""
        if port in SUSPICIOUS_PORTS:
            self.alerts.appendleft(
                f"[bold magenta]SUSPICIOUS PORT[/] {src_ip} → port {port}"
            )

    # ── Rich display ──────────────────────────────────────────────────────────

    def _build_layout(self) -> Layout:
        """Construct the initial Rich Layout skeleton."""
        layout = Layout(name="root")
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="top", size=10),
            Layout(name="middle"),
        )
        layout["top"].split_row(
            Layout(name="stats"),
            Layout(name="talkers"),
            Layout(name="destinations"),
        )
        layout["middle"].split_row(
            Layout(name="recent"),
            Layout(name="alerts"),
        )
        return layout

    def _update_layout(self, layout: Layout) -> None:
        """Refresh all panels in the layout with current data using a central lock."""
        with self._lock:
            layout["header"].update(self._render_header())
            layout["stats"].update(self._render_stats())
            layout["talkers"].update(self._render_top_talkers())
            layout["destinations"].update(self._render_top_destinations())
            layout["recent"].update(self._render_recent_packets())
            layout["alerts"].update(self._render_alerts())

    def _render_header(self) -> Panel:
        """Render the title banner."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        text = Text(justify="center")
        text.append("⬡  NetworkMonitor", style="bold orange1")
        text.append("   interface: ", style="grey54")
        text.append(self.interface, style="spring_green1")
        text.append(f"   {ts}", style="grey54")
        return Panel(text, box=box.SIMPLE, border_style="grey35")

    def _render_stats(self) -> Panel:
        """Render the traffic statistics panel."""
        s = self.stats
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column(style="grey54")
        table.add_column(style="orange1", justify="right")
        table.add_row("Total Packets", f"{s.total:,}")
        table.add_row("TCP", f"{s.tcp:,}")
        table.add_row("UDP", f"{s.udp:,}")
        table.add_row("ICMP", f"{s.icmp:,}")
        table.add_row("Other", f"{s.other:,}")
        table.add_row("Packets/sec", f"{s.packets_per_sec():.1f}")
        table.add_row("Bytes/sec", f"{s.bytes_per_sec() / 1024:.1f} KB")
        return Panel(
            table,
            title="[bold orange1]Traffic Stats[/]",
            box=box.SIMPLE,
            border_style="grey35",
        )

    def _render_top_talkers(self) -> Panel:
        """Render the top source IPs panel."""
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column(style="spring_green1")
        table.add_column(style="grey89", justify="right")
        top = sorted(self.src_counters.items(), key=lambda x: x[1], reverse=True)
        for ip, count in top[:TOP_N]:
            table.add_row(ip, f"{count:,}")
        if not self.src_counters:
            table.add_row("[grey54]waiting...[/]", "")
        return Panel(
            table,
            title="[bold orange1]Top Talkers[/]",
            box=box.SIMPLE,
            border_style="grey35",
        )

    def _render_top_destinations(self) -> Panel:
        """Render the top destination IPs panel."""
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column(style="indian_red")
        table.add_column(style="grey89", justify="right")
        top = sorted(self.dst_counters.items(), key=lambda x: x[1], reverse=True)
        for ip, count in top[:TOP_N]:
            table.add_row(ip, f"{count:,}")
        if not self.dst_counters:
            table.add_row("[grey54]waiting...[/]", "")
        return Panel(
            table,
            title="[bold orange1]Top Destinations[/]",
            box=box.SIMPLE,
            border_style="grey35",
        )

    def _render_recent_packets(self) -> Panel:
        """Render the scrolling recent packets panel."""
        table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        table.add_column("Time", style="grey54", no_wrap=True)
        table.add_column("Src", style="spring_green1", no_wrap=True)
        table.add_column("Dst", style="indian_red", no_wrap=True)
        table.add_column("Proto", style="orange1", width=5)
        table.add_column("Flags", style="grey54", width=8)
        table.add_column("B", style="grey89", justify="right", width=6)

        for pkt in list(self.recent_packets):
            src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
            dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
            table.add_row(
                pkt.timestamp, src, dst, pkt.protocol, pkt.flags, str(pkt.size)
            )

        return Panel(
            table,
            title="[bold orange1]Recent Packets[/]",
            box=box.SIMPLE,
            border_style="grey35",
        )

    def _render_alerts(self) -> Panel:
        """Render the anomaly alerts panel."""
        text = Text()
        if not self.alerts:
            text.append("No alerts.", style="grey54")
        else:
            for alert in list(self.alerts):
                text.append("▸ ", style="grey54")
                text.append_text(Text.from_markup(alert))
                text.append("\n")
        return Panel(
            text,
            title="[bold red]Alerts[/]",
            box=box.SIMPLE,
            border_style="grey35",
        )


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> None:
    """CLI entry point — parse arguments and start the network monitor."""
    parser = argparse.ArgumentParser(
        description="Live network monitor with anomaly detection. Requires root."
    )
    parser.add_argument(
        "--interface",
        "-i",
        default="lo",
        help="Network interface to monitor (default: lo)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Display refresh interval in seconds",
    )
    parser.add_argument(
        "--alert-threshold",
        type=int,
        default=20,
        help="Unique ports per IP before port scan alert (default: 20)",
    )
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        default="",
        help="BPF filter string e.g. 'tcp port 5000'",
    )
    args = parser.parse_args()

    monitor = NetworkMonitor(
        interface=args.interface,
        update_interval=args.interval,
        alert_threshold=args.alert_threshold,
        bpf_filter=args.bpf_filter,
    )
    monitor.start()


if __name__ == "__main__":
    main()
