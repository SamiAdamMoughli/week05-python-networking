"""Packet sniffer and protocol parser using Scapy. Loopback and authorised interfaces only.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing, compliance validation, and
educational auditing purposes only. Network monitoring or unauthorized packet sniffing
without explicit, prior, written permission from the asset owner may be illegal in your
jurisdiction. The author assumes no responsibility for misuse or operational disruption
caused by this script.
"""

import argparse
import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Final, TypedDict

import scapy.all as scapy
from rich.console import Console

# Resolve circular dependencies or structural typing validation problems across modules
try:
    from network_formatter import NetworkFormatter
except ImportError:

    class NetworkFormatter:  # type: ignore[no-redef]
        """Fallback formatter if custom network formatter package is missing."""

        def packet_summary(self, packets: list) -> str:
            return f"Formatted {len(packets)} packets for display."


log: logging.Logger = logging.getLogger(__name__)
LIVE_DISPLAY_MAX_ROWS: Final[int] = 20


class UIFieldRow(TypedDict):
    """Structural interface constraints for NetworkFormatter inputs."""

    src: str
    dst: str
    protocol: str
    size: int
    info: str


@dataclass
class SnifferStats:
    """Statistical tracking metrics schema for protocol metadata evaluation."""

    total: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    dns: int = 0
    http: int = 0
    other: int = 0

    def __str__(self) -> str:
        """Render a summarized metric line format."""
        return (
            f"Total: {self.total} | TCP: {self.tcp} | UDP: {self.udp} | "
            f"ICMP: {self.icmp} | DNS: {self.dns} | HTTP: {self.http} | Other: {self.other}"
        )


class PacketSniffer:
    """Asynchronous background socket frame capture and parser engine."""

    def __init__(
        self,
        interface: str | None = None,
        bpf_filter: str | None = None,
        count: int = 0,
    ) -> None:
        """Initialize operational sniffing state boundaries."""
        self.interface: str | None = interface
        self.bpf_filter: str | None = bpf_filter
        self.count: int = count
        self.packets: list[scapy.Packet] = []
        self._thread: threading.Thread | None = None
        self._running: bool = False
        self.stats: SnifferStats = SnifferStats()
        self._lock: threading.Lock = threading.Lock()

    def _validate_interface(self) -> str | None:
        """Verify the specified interface is available on the local operating host device."""
        if self.interface is None:
            return None

        try:
            # Query standard OS interface resolution structures to prevent invalid device allocation attempts
            scapy.get_if_hwaddr(self.interface)
            return self.interface
        except Exception as err:
            raise ValueError(
                f"Interface validation error: Interface '{self.interface}' "
                f"is unmapped, down, or requires elevated access privileges: {err}"
            ) from err

    def start(self) -> None:
        """Spawn the asynchronous background network capture processing loop."""
        self._validate_interface()
        self._running = True
        self._thread = threading.Thread(
            target=self._sniff_packets, name="sniffer-engine-loop"
        )
        self._thread.daemon = True
        self._thread.start()

    def _sniff_packets(self) -> None:
        """Directly engage the standard block system capture drivers."""
        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                count=self.count,
                prn=self._process_packet,
                store=True,
                stop_filter=lambda _: not self._running,
            )
        except Exception as err:
            log.error(
                "Fatal exception terminated network sniffing driver context: %s", err
            )
            self._running = False

    def stop(self) -> None:
        """Signal execution loop termination constraints and synchronize tracking handles."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def _process_packet(self, pkt: scapy.Packet) -> None:
        """Evaluate raw datagram packets and adjust profile metric totals under a thread lock."""
        with self._lock:
            self.packets.append(pkt)
            self.stats.total += 1

            if pkt.haslayer(scapy.Ether):
                self._parse_ethernet(pkt)
            if pkt.haslayer(scapy.IP):
                self._parse_ip(pkt)
            if pkt.haslayer(scapy.TCP):
                self.stats.tcp += 1
                self._parse_tcp(pkt)
            if pkt.haslayer(scapy.UDP):
                self.stats.udp += 1
                self._parse_udp(pkt)
            if pkt.haslayer(scapy.ICMP):
                self.stats.icmp += 1
            if pkt.haslayer(scapy.DNS):
                self.stats.dns += 1
                self._parse_dns(pkt)
            if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
                # Ensure validation tracking evaluates specific sub-protocol elements before incrementing
                parsed_http = self._parse_http(pkt)
                if parsed_http:
                    self.stats.http += 1

            if not any(
                [
                    pkt.haslayer(scapy.TCP),
                    pkt.haslayer(scapy.UDP),
                    pkt.haslayer(scapy.ICMP),
                    pkt.haslayer(scapy.DNS),
                ]
            ):
                self.stats.other += 1

    def _parse_ethernet(self, pkt: scapy.Packet) -> dict[str, object]:
        """Deconstruct layer-2 Ethernet properties."""
        return {
            "src": pkt[scapy.Ether].src,
            "dst": pkt[scapy.Ether].dst,
            "ethertype": pkt[scapy.Ether].type,
        }

    def _parse_ip(self, pkt: scapy.Packet) -> dict[str, object]:
        """Deconstruct layer-3 IPv4 properties."""
        return {
            "src": pkt[scapy.IP].src,
            "dst": pkt[scapy.IP].dst,
            "proto": pkt[scapy.IP].proto,
            "ttl": pkt[scapy.IP].ttl,
            "len": pkt[scapy.IP].len,
        }

    def _parse_tcp(self, pkt: scapy.Packet) -> dict[str, object]:
        """Deconstruct layer-4 TCP stream states."""
        return {
            "sport": pkt[scapy.TCP].sport,
            "dport": pkt[scapy.TCP].dport,
            "flags": str(pkt[scapy.TCP].flags),
            "seq": pkt[scapy.TCP].seq,
            "ack": pkt[scapy.TCP].ack,
        }

    def _parse_udp(self, pkt: scapy.Packet) -> dict[str, object]:
        """Deconstruct layer-4 UDP packets."""
        return {
            "sport": pkt[scapy.UDP].sport,
            "dport": pkt[scapy.UDP].dport,
            "len": pkt[scapy.UDP].len,
        }

    def _parse_dns(self, pkt: scapy.Packet) -> dict[str, object] | None:
        """Extract information fields from DNS standard payloads safely."""
        if not pkt.haslayer(scapy.UDP) or not pkt.haslayer(scapy.DNS):
            return None
        if pkt[scapy.DNS].qd is None:
            return None

        if pkt[scapy.UDP].dport == 53 or pkt[scapy.UDP].sport == 53:
            qname_bytes = pkt[scapy.DNS].qd.qname
            qname_str = (
                qname_bytes.decode(errors="replace")
                if isinstance(qname_bytes, bytes)
                else str(qname_bytes)
            )
            return {
                "qname": qname_str,
                "qtype": pkt[scapy.DNS].qd.qtype,
            }
        return None

    def _parse_http(self, pkt: scapy.Packet) -> dict[str, object] | None:
        """Deconstruct signature fields out of raw application streams with safe sanitization."""
        if not pkt.haslayer(scapy.TCP) or not pkt.haslayer(scapy.Raw):
            return None
        try:
            payload = pkt[scapy.Raw].load.decode(errors="ignore")
            lines = payload.split("\r\n")
            if not lines or not lines[0]:
                return None

            parts = lines[0].split(" ")
            method = parts[0]
            # Ensure out-of-bounds queries on corrupt or modified request frames fail safely
            path = parts[1] if len(parts) > 1 else ""

            # Confirm standard HTTP methods are visible within signature bounds
            if method not in (
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "HEAD",
                "OPTIONS",
                "PATCH",
                "HTTP/1.",
            ):
                return None

            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.strip()] = value.strip()

            return {
                "method": method,
                "path": path,
                "host": headers.get("Host"),
                "user_agent": headers.get("User-Agent"),
                "content_type": headers.get("Content-Type"),
                # Explicitly strip and redact sensitive session contexts to prevent raw disk logging leaks
                "authorization": (
                    "[REDACTED_S_FIELD]" if headers.get("Authorization") else None
                ),
                "cookie": "[REDACTED_S_FIELD]" if headers.get("Cookie") else None,
            }
        except (ValueError, IndexError, AttributeError) as e:
            log.debug("Failed parsing application layer protocol elements: %s", e)
            return None

    def get_stats(self) -> SnifferStats:
        """Retrieve total calculated traffic protocol statistics counters under thread-safe locks."""
        with self._lock:
            return self.stats

    def dump_pcap(self, filepath: str) -> None:
        """Export raw collected buffer items to file using standardized PCAP files."""
        with self._lock:
            packets_snapshot = list(self.packets)
        scapy.wrpcap(filepath, packets_snapshot)

    def dump_json(self, filepath: str) -> None:
        """Serialize deconstructed application components into human-readable data maps."""
        with self._lock:
            packets_snapshot = list(self.packets)

        parsed: list[dict[str, object]] = []
        for pkt in packets_snapshot:
            entry: dict[str, object] = {}
            if pkt.haslayer(scapy.IP):
                entry["ip"] = self._parse_ip(pkt)
            if pkt.haslayer(scapy.TCP):
                entry["tcp"] = self._parse_tcp(pkt)
            if pkt.haslayer(scapy.UDP):
                entry["udp"] = self._parse_udp(pkt)
            if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
                entry["http"] = self._parse_http(pkt)
            if pkt.haslayer(scapy.DNS):
                entry["dns"] = self._parse_dns(pkt)
            entry["size"] = len(pkt)
            entry["summary"] = pkt.summary()
            parsed.append(entry)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(parsed, f, indent=2, default=str)


def _infer_packet_protocol(pkt: scapy.Packet) -> str:
    """Evaluate layers sequentially to determine the highest abstract context type label."""
    if pkt.haslayer(scapy.Raw) and pkt.haslayer(scapy.TCP):
        return "HTTP"
    if pkt.haslayer(scapy.DNS):
        return "DNS"
    if pkt.haslayer(scapy.TCP):
        return "TCP"
    if pkt.haslayer(scapy.UDP):
        return "UDP"
    if pkt.haslayer(scapy.ICMP):
        return "ICMP"
    return "Other"


def main() -> None:
    """CLI capture pipeline executor hub."""
    parser = argparse.ArgumentParser(
        description="Secure Packet Sniffer reference framework utility."
    )
    parser.add_argument(
        "--interface", default="lo", help="Network interface (default: lo)"
    )
    parser.add_argument(
        "--filter", dest="bpf_filter", help="BPF filter e.g. 'tcp port 80'"
    )
    parser.add_argument(
        "--count", type=int, default=0, help="Packets to capture (0 = unlimited)"
    )
    parser.add_argument("--dump", help="Save captured packets to JSON file")
    parser.add_argument("--pcap", help="Save captured packets to PCAP file")
    args = parser.parse_args()

    try:
        sniffer = PacketSniffer(
            interface=args.interface,
            bpf_filter=args.bpf_filter,
            count=args.count,
        )
        sniffer.start()
    except ValueError as exc:
        print(f"Initialization Aborted: {exc}")
        return

    formatter = NetworkFormatter()
    console = Console()
    console.print(
        f"[orange1]Sniffing on device adapter: {args.interface}... Ctrl+C to stop.[/orange1]"
    )

    try:
        while True:
            time.sleep(0.5)
            # Create a thread-safe atomic local copy of recent objects to run UI parsing rules against safely
            with sniffer._lock:  # pylint: disable=protected-access
                current_packet_snapshot = list(sniffer.packets[-LIVE_DISPLAY_MAX_ROWS:])

            ui_rows: list[UIFieldRow] = []
            for pkt in current_packet_snapshot:
                ui_rows.append(
                    {
                        "src": (
                            str(pkt[scapy.IP].src) if pkt.haslayer(scapy.IP) else "?"
                        ),
                        "dst": (
                            str(pkt[scapy.IP].dst) if pkt.haslayer(scapy.IP) else "?"
                        ),
                        "protocol": _infer_packet_protocol(pkt),
                        "size": len(pkt),
                        "info": str(pkt.summary()),
                    }
                )

            console.clear()
            # Suppress explicit layout updates if the current capture window snapshot is empty
            if ui_rows:
                console.print(formatter.packet_summary(ui_rows))  # type: ignore[arg-type]
            console.print(f"[grey54]{sniffer.get_stats()}[/grey54]")
    except KeyboardInterrupt:
        sniffer.stop()
        console.print(
            "[orange1]Capture driver interface loops successfully stopped and unified.[/orange1]"
        )

    if args.dump:
        sniffer.dump_json(args.dump)
        console.print(
            f"[grey54]Saved sanitized JSON log matrix map structure to: {args.dump}[/grey54]"
        )
    if args.pcap:
        sniffer.dump_pcap(args.pcap)
        console.print(
            f"[grey54]Saved raw global packet structure traces to PCAP file: {args.pcap}[/grey54]"
        )


if __name__ == "__main__":
    main()
