# ETHICAL USE NOTICE
# This tool is for authorised security testing and educational purposes only.
# Only scan systems you own or have explicit written permission to test.
# Unauthorised scanning may be illegal in your jurisdiction.
# The author assumes no responsibility for misuse.

"""ReconToolkit — unified CLI entry point for all Week 5 networking tools.

Usage:
    sudo python recon_toolkit.py --help
    sudo python recon_toolkit.py scan --target 127.0.0.1 --top 1000
    sudo python recon_toolkit.py grab --target 127.0.0.1 --ports 22,80,443
    sudo python recon_toolkit.py sniff --interface lo --count 100
    sudo python recon_toolkit.py analyse --file capture.pcap --report
    sudo python recon_toolkit.py monitor --interface lo
    sudo python recon_toolkit.py dns --domain example.com
    sudo python recon_toolkit.py ping --host 127.0.0.1
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

log: logging.Logger = logging.getLogger(__name__)
console: Console = Console()

ETHICAL_WARNING: Final[
    str
] = """[bold yellow]⚠  ReconToolkit — For authorised use only.[/]
[grey54]Only scan systems you own or have explicit permission to test.
Unauthorised scanning is illegal in most jurisdictions.[/]"""


# ── Safety & Verification Helpers ─────────────────────────────────────────────


def print_banner() -> None:
    """Print the ethical use warning on every invocation."""
    console.print()
    console.print(
        Panel(
            Text.from_markup(ETHICAL_WARNING),
            box=box.SIMPLE,
            border_style="grey35",
            expand=False,
        )
    )
    console.print()


def verify_safe_path(target_path: str, write_operation: bool = False) -> Path:
    """Validate and resolve target files safely to prevent path traversal bugs.

    Args:
        target_path: Absolute or relative file string path input.
        write_operation: Flag checking if the location needs parent folder validation.

    Returns:
        A fully validated and safe Path object instance.
    """
    resolved = Path(os.path.realpath(target_path))

    if write_operation:
        if not resolved.parent.exists():
            abort(f"Destination folder does not exist: {resolved.parent}")
    else:
        if not resolved.exists():
            abort(f"Target file path not found: {resolved}")

    return resolved


def save_output(data: Any, output_path: str) -> None:
    """Serialise data safely to JSON or Markdown depending on file extension.

    Args:
        data: Python object to serialise.
        output_path: Destination file path (.json or .md).
    """
    path = verify_safe_path(output_path, write_operation=True)
    ts = datetime.now(timezone.utc).isoformat()

    if path.suffix == ".json":
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"timestamp": ts, "data": data}, f, indent=2, default=str)
            console.print(f"[grey54]Output saved → {path}[/]")
        except (IOError, TypeError) as err:
            abort(f"Failed to generate structured JSON storage: {err}")
    elif path.suffix == ".md":
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# ReconToolkit Output\n\n**Timestamp:** {ts}\n\n")
                if isinstance(data, list):
                    for item in data:
                        f.write(f"- {item}\n")
                else:
                    f.write(f"```\n{data}\n```\n")
            console.print(f"[grey54]Output saved → {path}[/]")
        except IOError as err:
            abort(f"Failed to write markdown output report: {err}")
    else:
        console.print(f"[yellow]Unknown extension '{path.suffix}' — saving as JSON.[/]")
        path = path.with_suffix(".json")
        save_output(data, str(path))


def abort(message: str) -> None:
    """Print an error safely and exit with failure code 1.

    Args:
        message: Error message to display.
    """
    console.print(f"[bold red]Error:[/] {message}")
    sys.exit(1)


# ── Subcommand handlers ───────────────────────────────────────────────────────


def cmd_scan(args: argparse.Namespace) -> None:
    """Run the port scanner against an authorized target host."""
    try:
        from marco_polo import PortScannerV3  # type: ignore[import-not-found]
        from network_formatter import NetworkFormatter  # type: ignore[import-not-found]
    except ImportError as e:
        abort(f"Could not load local network port scanning dependency modules: {e}")

    formatter = NetworkFormatter()
    formatter.print_panel(
        "Port Scanner",
        f"target: {args.target}  |  ethical use only",
    )

    scanner = PortScannerV3(args.target)

    if args.range:
        try:
            start_str, end_str = args.range.split("-", 1)
            start, end = int(start_str), int(end_str)
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError
        except ValueError:
            abort(
                "--range must be formatted as valid START-END integers within 1-65535 bounds."
            )
        results = scanner.scan_range(start, end)
    elif args.top:
        if args.top <= 0:
            abort("--top allocation parameter must be a positive integer value.")
        results = scanner.scan_top_ports(args.top)
    else:
        results = scanner.scan_top_ports(1000)

    console.print(formatter.port_table(results))

    if args.output:
        save_output(
            [
                {
                    "port": r.port,
                    "state": r.state,
                    "service": r.service,
                    "banner": r.banner,
                    "scan_ms": r.scan_ms,
                }
                for r in results
            ],
            args.output,
        )


def cmd_grab(args: argparse.Namespace) -> None:
    """Grab service banners from explicit ports on a validated target host."""
    try:
        from banner_grabber import BannerGrabber  # type: ignore[import-not-found]
        from network_formatter import NetworkFormatter  # type: ignore[import-not-found]
    except ImportError as e:
        abort(f"Could not load service validation modules: {e}")

    try:
        ports = [int(p.strip()) for p in args.ports.split(",")]
        if any(not (1 <= p <= 65535) for p in ports):
            raise ValueError
    except ValueError:
        abort(
            "--ports must be a comma-separated list of integer ports between 1 and 65535."
        )

    formatter = NetworkFormatter()
    formatter.print_panel(
        "Banner Grabber",
        f"target: {args.target}  |  ports: {args.ports}",
    )

    grabber = BannerGrabber()
    banners = grabber.grab_multiple(args.target, ports)

    if not banners:
        console.print("[grey54]No banners retrieved.[/]")
        return

    console.print(formatter.banner_table(banners))

    if args.output:
        save_output(
            [
                {
                    "port": b.port,
                    "service": b.service_name,
                    "version": b.version,
                    "banner": b.raw_banner,
                    "confidence": b.confidence,
                }
                for b in banners
            ],
            args.output,
        )


def cmd_sniff(args: argparse.Namespace) -> None:
    """Capture interface packets safely via structural Scapy wrappers."""
    try:
        from packet_sniffer import PacketSniffer  # type: ignore[import-not-found]
        from network_formatter import NetworkFormatter  # type: ignore[import-not-found]
    except ImportError as e:
        abort(f"Could not load packet sniffing components: {e}")

    formatter = NetworkFormatter()
    formatter.print_panel(
        "Packet Sniffer",
        f"interface: {args.interface}  |  count: {args.count or 'unlimited'}",
    )

    sniffer = PacketSniffer(
        interface=args.interface,
        bpf_filter=args.filter or "",
        count=args.count or 0,
    )

    try:
        sniffer.start()
        console.print(
            "[orange1]Sniffing loop initialized... Press Ctrl+C to terminate.[/]"
        )
        while getattr(sniffer, "_running", False):
            time.sleep(0.5)
    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Interrupted by operational user request. Cleaning up handles...[/]"
        )
    finally:
        sniffer.stop()

    console.print(f"\n[grey54]{sniffer.get_stats()}[/]")

    if args.output:
        safe_out = str(verify_safe_path(args.output, write_operation=True))
        if safe_out.endswith(".pcap"):
            sniffer.dump_pcap(safe_out)
        else:
            sniffer.dump_json(safe_out)
        console.print(f"[grey54]Saved package elements -> {safe_out}[/]")


def cmd_analyse(args: argparse.Namespace) -> None:
    """Analyse an existing PCAP capture file file safely."""
    try:
        from pcap_analyser import PCAPAnalyser  # type: ignore[import-not-found]
    except ImportError as e:
        abort(f"Could not load trace analysis dependency package tools: {e}")

    validated_pcap = verify_safe_path(args.file, write_operation=False)

    analyser = PCAPAnalyser()
    analyser.load(str(validated_pcap))

    if args.report:
        report = analyser.generate_report()
        console.print(report)
        if args.output:
            save_output(report, args.output)
    else:
        if args.http:
            for r in analyser.find_http_requests():
                console.print(r)
        if args.dns:
            for q in analyser.find_dns_queries():
                console.print(q)


def cmd_monitor(args: argparse.Namespace) -> None:
    """Launch the live telemetry monitor dashboard."""
    try:
        from network_monitor import NetworkMonitor  # type: ignore[import-not-found]
    except ImportError as e:
        abort(f"Could not initialize live interface UI components: {e}")

    monitor = NetworkMonitor(
        interface=args.interface,
        update_interval=args.interval,
        alert_threshold=args.alert_threshold,
        bpf_filter=args.filter or "",
    )
    monitor.start()


def cmd_dns(args: argparse.Namespace) -> None:
    """Perform a secure structured DNS lookup via Scapy."""
    try:
        import scapy.all as scapy
    except ImportError as e:
        abort(f"Scapy engine core library unavailable: {e}")

    console.print(f"[orange1]DNS lookup:[/] [grey89]{args.domain}[/]\n")

    pkt = (
        scapy.IP(dst="8.8.8.8")
        / scapy.UDP()
        / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=args.domain, qtype="A"))
    )
    ans = scapy.sr1(pkt, verbose=0, timeout=3)

    if ans is None:
        console.print("[indian_red]No response from designated lookup node.[/]")
        return

    if not ans.haslayer(scapy.DNS) or ans[scapy.DNS].an is None:
        console.print(
            "[indian_red]No resolution answer fields within target server response.[/]"
        )
        return

    record = ans[scapy.DNS].an
    results = []
    while record:
        rdata = str(record.rdata) if hasattr(record, "rdata") else "Unknown"
        console.print(
            f"  [spring_green1]{args.domain}[/] [grey54]→[/] [orange1]{rdata}[/]"
        )
        results.append({"domain": args.domain, "rdata": rdata})
        record = (
            record.payload
            if record.payload and hasattr(record.payload, "rdata")
            else None
        )

    if args.output:
        save_output(results, args.output)


def cmd_ping(args: argparse.Namespace) -> None:
    """Transmit a verification ICMP frame echo request via Scapy."""
    try:
        import scapy.all as scapy
    except ImportError as e:
        abort(f"Scapy system framework mapping drivers missing: {e}")

    console.print(f"[orange1]ICMP ping target:[/] [grey89]{args.host}[/]\n")

    pkt = scapy.IP(dst=args.host) / scapy.ICMP()
    ans = scapy.sr1(pkt, verbose=0, timeout=2)

    if ans is None:
        console.print(
            f"  [indian_red]Host unreachable, dropped, or filtered by gateway context.[/]"
        )
        if args.output:
            save_output({"host": args.host, "alive": False}, args.output)
        return

    ttl = ans[scapy.IP].ttl if scapy.IP in ans else 0
    rtt_ms = (ans.time - pkt.sent_time) * 1000 if hasattr(pkt, "sent_time") else 0.0
    console.print(
        f"  [spring_green1]Target node responsive[/] — "
        f"TTL: [bold orange1]{ttl}[/]  RTT: [grey89]{rtt_ms:.2f}ms[/]"
    )

    if args.output:
        save_output(
            {"host": args.host, "alive": True, "ttl": ttl, "rtt_ms": rtt_ms},
            args.output,
        )


# ── Argument parser generation definitions ────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Build and return the full unified CLI argument parser tree structure."""
    parser = argparse.ArgumentParser(
        prog="recon_toolkit",
        description="Unified network diagnostics CLI toolkit wrapper reference pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Save analytical results data out to FILE path (.json or .md format target namespaces)",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # ── scan subcommand parser ──
    p_scan = sub.add_parser("scan", help="TCP port scanner tool")
    p_scan.add_argument(
        "--target", required=True, help="Target host destination domain or IPv4 pointer"
    )
    p_scan.add_argument(
        "--top", type=int, metavar="N", help="Scan top N protocol port listings"
    )
    p_scan.add_argument(
        "--range",
        metavar="START-END",
        help="Explicit scope range bounds index e.g. 1-1024",
    )
    p_scan.set_defaults(func=cmd_scan)

    # ── grab subcommand parser ──
    p_grab = sub.add_parser(
        "grab", help="Banner grabber and service fingerprinting utility"
    )
    p_grab.add_argument(
        "--target", required=True, help="Target host destination domain or IPv4 pointer"
    )
    p_grab.add_argument(
        "--ports",
        required=True,
        help="Comma-separated target testing ports e.g. 22,80,443",
    )
    p_grab.set_defaults(func=cmd_grab)

    # ── sniff subcommand parser ──
    p_sniff = sub.add_parser("sniff", help="Asynchronous frame packet capture monitor")
    p_sniff.add_argument(
        "--interface",
        "-i",
        default="lo",
        help="Target operating system interface driver",
    )
    p_sniff.add_argument(
        "--count",
        type=int,
        default=0,
        help="Total packet frame constraints limit boundary counts (0 = infinite)",
    )
    p_sniff.add_argument(
        "--filter",
        metavar="BPF",
        help="BPF formatting string query syntax profile rules e.g. 'tcp port 443'",
    )
    p_sniff.set_defaults(func=cmd_sniff)

    # ── analyse subcommand parser ──
    p_anal = sub.add_parser("analyse", help="PCAP capture file analysis framework")
    p_anal.add_argument(
        "--file",
        required=True,
        help="Target local file system PCAP log map source pointer",
    )
    p_anal.add_argument(
        "--report",
        action="store_true",
        help="Compile and format full markdown metrics report file outputs",
    )
    p_anal.add_argument(
        "--http",
        action="store_true",
        help="Filter and isolate HTTP application logs metadata strings",
    )
    p_anal.add_argument(
        "--dns", action="store_true", help="Extract domain lookup queries metrics"
    )
    p_anal.set_defaults(func=cmd_analyse)

    # ── monitor subcommand parser ──
    p_mon = sub.add_parser(
        "monitor", help="Live diagnostic network telemetry panel dashboard interface"
    )
    p_mon.add_argument(
        "--interface",
        "-i",
        default="lo",
        help="Network interface adapter monitoring handle",
    )
    p_mon.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Dashboard panel frame refresh rate interval parameters",
    )
    p_mon.add_argument(
        "--alert-threshold",
        type=int,
        default=20,
        help="Port connections boundary scans trigger ceiling counts",
    )
    p_mon.add_argument(
        "--filter",
        metavar="BPF",
        help="BPF optimization rule filters string settings profile",
    )
    p_mon.set_defaults(func=cmd_monitor)

    # ── dns subcommand parser ──
    p_dns = sub.add_parser("dns", help="DNS query resolver")
    p_dns.add_argument(
        "--domain",
        required=True,
        help="Target zone host destination string pointer to parse",
    )
    p_dns.set_defaults(func=cmd_dns)

    # ── ping subcommand parser ──
    p_ping = sub.add_parser("ping", help="ICMP connection validation ping test")
    p_ping.add_argument(
        "--host",
        required=True,
        help="Target host verification location destination pointer",
    )
    p_ping.set_defaults(func=cmd_ping)

    return parser


# ── Entry Routing Framework Execution Engine Hub ───────────────────────────────


def main() -> None:
    """Parse runtime execution configurations and dispatch safely to command targets."""
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "output"):
        args.output = None

    print_banner()

    try:
        args.func(args)
    except AttributeError:
        parser.print_help()
    except Exception as fatal_err:
        abort(f"Unexpected operational toolkit error: {fatal_err}")


if __name__ == "__main__":
    main()
