"""PCAP file analyser — conversations, protocol breakdown, HTTP and DNS extraction.

Provides an automated processing pipeline to ingest raw network frame captures
and extract operational traffic metrics, application signatures, and flow baselines.
"""

# pylint: disable=no-member

import argparse
import logging
import os
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Final, NamedTuple

import scapy.all as scapy

# Configure module logging structure
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log: logging.Logger = logging.getLogger(__name__)

DEFAULT_DISPLAY_LIMIT: Final[int] = 10


@dataclass
class Conversation:
    """Statistical schema tracking communication flows between discrete sockets."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packet_count: int
    bytes_total: int
    duration_ms: float

    def __str__(self) -> str:
        """Render standard flow metrics output format."""
        return (
            f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} | "
            f"{self.packet_count} pkts | {self.bytes_total}B | {self.duration_ms}ms"
        )


class ConversationGroup(NamedTuple):
    """Internal structural buffer tracking grouped session packet frames."""

    packets: list[scapy.Packet]
    bytes_total: int


class TimelineEntry(NamedTuple):
    """Structured capture log sequence trace detailing frame events across time."""

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    frame_size: int


def _infer_packet_protocol(pkt: scapy.Packet) -> str:
    """Evaluate packet properties to determine its abstract network classification.

    Args:
        pkt: Target Scapy frame handle.

    Returns:
        String identifying the network protocol structure ('TCP', 'UDP', 'ICMP', or 'Other').
    """
    if pkt.haslayer(scapy.TCP):
        return "TCP"
    if pkt.haslayer(scapy.UDP):
        return "UDP"
    if pkt.haslayer(scapy.ICMP):
        return "ICMP"
    return "Other"


class PCAPAnalyser:
    """Ingestion and metadata processing engine for network trace files."""

    def __init__(self) -> None:
        """Initialize core engine collection properties."""
        self.packets: list[scapy.Packet] = []

    def load(self, filepath: str) -> list[scapy.Packet]:
        """Read standard PCAP binary structures from disk into local memory buffers.

        Args:
            filepath: Target absolute or relative location reference path string.

        Returns:
            A list containing hydrated Scapy packet elements.
        """
        self.packets = list(scapy.rdpcap(filepath))
        return self.packets

    def top_talkers(self, n: int = DEFAULT_DISPLAY_LIMIT) -> list[tuple[str, int]]:
        """Identify layer-3 interfaces emitting the highest transmission frame totals.

        Args:
            n: Restrict output evaluation bounds to the top N entries.

        Returns:
            List containing pairing records corresponding to (Source IP, Packet Count).
        """
        sources = [pkt[scapy.IP].src for pkt in self.packets if pkt.haslayer(scapy.IP)]
        return Counter(sources).most_common(n)

    def top_destinations(self, n: int = DEFAULT_DISPLAY_LIMIT) -> list[tuple[str, int]]:
        """Identify layer-3 interfaces receiving the highest transmission frame totals.

        Args:
            n: Restrict output evaluation bounds to the top N entries.

        Returns:
            List containing pairing records corresponding to (Destination IP, Packet Count).
        """
        destinations = [
            pkt[scapy.IP].dst for pkt in self.packets if pkt.haslayer(scapy.IP)
        ]
        return Counter(destinations).most_common(n)

    def protocol_breakdown(self) -> dict[str, int]:
        """Calculate traffic classification profile distributions over the buffer.

        Returns:
            Dictionary mapped by layer-4 tracking profile labels and their associated totals.
        """
        breakdown = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        for pkt in self.packets:
            proto = _infer_packet_protocol(pkt)
            breakdown[proto] += 1
        return breakdown

    def port_breakdown(self) -> dict[int, int]:
        """Evaluate network port activity across layer-4 transport protocols.

        Returns:
            Sorted counter sequence map matching active destination port indexes against totals.
        """
        ports: list[int] = []
        for pkt in self.packets:
            if pkt.haslayer(scapy.TCP):
                ports.append(int(pkt[scapy.TCP].dport))
            elif pkt.haslayer(scapy.UDP):
                ports.append(int(pkt[scapy.UDP].dport))
        return dict(Counter(ports).most_common(DEFAULT_DISPLAY_LIMIT))

    def tcp_conversations(self) -> list[Conversation]:
        """Assemble individual sequential stream tracking segments from raw arrays.

        Returns:
            List filled with uniquely aggregated flow conversation details.
        """
        groups: dict[tuple[str, int, str, int], ConversationGroup] = {}

        for pkt in self.packets:
            if not pkt.haslayer(scapy.TCP) or not pkt.haslayer(scapy.IP):
                continue

            key = (
                str(pkt[scapy.IP].src),
                int(pkt[scapy.TCP].sport),
                str(pkt[scapy.IP].dst),
                int(pkt[scapy.TCP].dport),
            )

            if key not in groups:
                groups[key] = ConversationGroup(packets=[], bytes_total=0)

            groups[key].packets.append(pkt)
            # Reconstruct the tracking tuple cleanly with updated byte values
            groups[key] = groups[key]._replace(
                bytes_total=groups[key].bytes_total + len(pkt)
            )

        conversations: list[Conversation] = []
        for (src_ip, src_port, dst_ip, dst_port), data in groups.items():
            pkts = data.packets
            duration = (float(pkts[-1].time) - float(pkts[0].time)) * 1000
            conversations.append(
                Conversation(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    packet_count=len(pkts),
                    bytes_total=data.bytes_total,
                    duration_ms=round(duration, 2),
                )
            )
        return conversations

    def find_http_requests(self) -> list[dict[str, str | None]]:
        """Parse raw stream buffer strings to isolate application layer HTTP components.

        Returns:
            List containing dictionary maps with keys describing metadata characteristics.
        """
        requests: list[dict[str, str | None]] = []
        for pkt in self.packets:
            if not pkt.haslayer(scapy.TCP) or not pkt.haslayer(scapy.Raw):
                continue

            payload = pkt[scapy.Raw].load.decode(errors="ignore")
            if not payload.startswith(("GET", "POST", "PUT", "DELETE")):
                continue

            lines = payload.split("\r\n")
            if not lines or not lines[0]:
                continue

            parts = lines[0].split(" ")
            method = parts[0]
            path = parts[1] if len(parts) > 1 else ""
            headers: dict[str, str] = {}

            for line in lines[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.strip()] = value.strip()

            requests.append(
                {
                    "method": method,
                    "path": path,
                    "host": headers.get("Host"),
                    "user_agent": headers.get("User-Agent"),
                    "src": pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else None,
                }
            )
        return requests

    def find_dns_queries(self) -> list[dict[str, object]]:
        """Deconstruct active domain resolution interactions inside the capture data.

        Returns:
            List detailing standard resolution information objects.
        """
        queries: list[dict[str, object]] = []
        for pkt in self.packets:
            if not pkt.haslayer(scapy.DNS) or not pkt[scapy.DNS].qd:
                continue

            qname_bytes = pkt[scapy.DNS].qd.qname
            qname_str = (
                qname_bytes.decode(errors="ignore")
                if isinstance(qname_bytes, bytes)
                else str(qname_bytes)
            )

            answer_val: str | None = None
            if pkt[scapy.DNS].an:
                answer_record = pkt[scapy.DNS].an
                if hasattr(answer_record, "rdata") and answer_record.rdata is not None:
                    answer_val = str(answer_record.rdata)

            query = {
                "qname": qname_str,
                "qtype": int(pkt[scapy.DNS].qd.qtype),
                "answer": answer_val,
            }
            queries.append(query)
        return queries

    def timeline(self) -> list[TimelineEntry]:
        """Sequence capture frame histories linearly across an ordered chronological spectrum.

        Returns:
            A sorted collection list of timeline snapshot sequence entries.
        """
        result: list[TimelineEntry] = []
        for pkt in self.packets:
            if not pkt.haslayer(scapy.IP):
                continue
            result.append(
                TimelineEntry(
                    timestamp=float(pkt.time),
                    src_ip=str(pkt[scapy.IP].src),
                    dst_ip=str(pkt[scapy.IP].dst),
                    protocol=_infer_packet_protocol(pkt),
                    frame_size=len(pkt),
                )
            )
        return sorted(result, key=lambda entry: entry.timestamp)

    def generate_report(self) -> str:
        """Compile internal processed metrics summaries into readable Markdown records.

        Returns:
            A string payload structured in plain Markdown markdown notation.
        """
        report: list[str] = ["# PCAP Analysis Report\n", "## Top Talkers"]
        for ip, count in self.top_talkers():
            report.append(f"- {ip}: {count} packets")

        report.append("\n## Top Destinations")
        for ip, count in self.top_destinations():
            report.append(f"- {ip}: {count} packets")

        report.append("\n## Protocol Breakdown")
        for proto, count in self.protocol_breakdown().items():
            report.append(f"- {proto}: {count}")

        report.append("\n## Port Breakdown")
        for port, count in self.port_breakdown().items():
            report.append(f"- Port {port}: {count} packets")

        report.append("\n## TCP Conversations")
        for convo in self.tcp_conversations():
            report.append(f"- {convo}")

        report.append("\n## HTTP Requests")
        for req in self.find_http_requests():
            report.append(
                f"- {req['method']} {req['path']} from {req['src']} (host: {req['host']})"
            )

        report.append("\n## DNS Queries")
        for query in self.find_dns_queries():
            report.append(f"- {query['qname']} ({query['qtype']}) → {query['answer']}")

        return "\n".join(report)


def main() -> None:
    """Central interface entry routing CLI configurations."""
    parser = argparse.ArgumentParser(description="PCAP Analysis Reference Utility")
    parser.add_argument(
        "--file", required=True, help="Path to input PCAP target file structure"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate explicit markdown summary data output",
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Isolate and render verified HTTP request states",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Isolate and render identified domain query actions",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        log.error(
            "The specified target trace path was invalid or cannot be resolved: %s",
            args.file,
        )
        sys.exit(1)

    analyser = PCAPAnalyser()

    try:
        analyser.load(args.file)
    except (FileNotFoundError, PermissionError) as error:
        log.error("Failed to read system file data cleanly: %s", error)
        sys.exit(1)

    if args.report:
        print(analyser.generate_report())
    if args.http:
        for req in analyser.find_http_requests():
            print(req)
    if args.dns:
        for query in analyser.find_dns_queries():
            print(query)


if __name__ == "__main__":
    main()
