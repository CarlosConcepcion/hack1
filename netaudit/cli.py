from __future__ import annotations
import asyncio
import logging
import signal
import sys
import threading
import time
from typing import Optional

import click

from netaudit import __version__
from netaudit.config import NetAuditConfig
from netaudit.models import CaptureResults
from netaudit.core.sniffer import Sniffer
from netaudit.core.packet_handler import PacketHandler
from netaudit.output.console import build_layout, console
from netaudit.output.json_exporter import export_json
from netaudit.output.csv_exporter import export_csv_credentials, export_csv_dns

logger = logging.getLogger("netaudit")

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


class GracefulKiller:
    def __init__(self):
        self.kill_now = False
        self._orig_sigint = None
        self._orig_sigterm = None

    def __enter__(self):
        self._orig_sigint = signal.signal(signal.SIGINT, self._exit_gracefully)
        self._orig_sigterm = signal.signal(signal.SIGTERM, self._exit_gracefully)
        return self

    def __exit__(self, *args):
        if self._orig_sigint:
            signal.signal(signal.SIGINT, self._orig_sigint)
        if self._orig_sigterm:
            signal.signal(signal.SIGTERM, self._orig_sigterm)

    def _exit_gracefully(self, signum, frame):
        self.kill_now = True


def setup_logging(quiet: bool = False):
    level = logging.ERROR if quiet else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=__version__, prog_name="NetAudit")
def cli():
    """NetAudit - Network Traffic Analyzer for Security Audits

    Real-time network sniffer focused on credential extraction,
    service discovery, and traffic analysis for professional audits.
    """


@cli.command()
@click.option("-i", "--interface", help="Network interface to capture on")
@click.option("-r", "--read", "pcap_file", type=click.Path(exists=True), help="Read from PCAP file")
@click.option("-o", "--output", type=click.Path(), help="Export results to JSON file")
@click.option("--csv", "csv_output", type=click.Path(), help="Export credentials to CSV file")
@click.option("--bpf", "bpf_filter", help="BPF filter expression (e.g. 'tcp port 80')")
@click.option("--creds-only", is_flag=True, help="Only capture credentials (HTTP/FTP/Telnet)")
@click.option("--no-resolve", is_flag=True, help="Skip DNS resolution (noted)")
@click.option("--stats-every", type=int, default=2, help="Stats refresh interval (seconds)")
@click.option("--quiet", is_flag=True, help="Suppress debug logs")
@click.option("-w", "--write", "save_pcap", type=click.Path(), help="Save capture to PCAP file (not yet implemented)")
def capture(
    interface: Optional[str],
    pcap_file: Optional[str],
    output: Optional[str],
    csv_output: Optional[str],
    bpf_filter: Optional[str],
    creds_only: bool,
    no_resolve: bool,
    stats_every: int,
    quiet: bool,
    save_pcap: Optional[str],
):
    """Capture and analyze network traffic in real-time."""
    setup_logging(quiet)

    config = NetAuditConfig(
        interface=interface,
        pcap_file=pcap_file,
        output_file=output,
        csv_output=csv_output,
        bpf_filter=bpf_filter,
        creds_only=creds_only,
        no_resolve=no_resolve,
        stats_every=stats_every,
        save_pcap=save_pcap,
        quiet=quiet,
    )

    results = CaptureResults()
    handler = PacketHandler(config, results)
    sniffer = Sniffer(config, results)
    sniffer.set_callback(handler.handle)

    console.print(f"[bold cyan]NetAudit v{__version__}[/] - Network Audit Tool")
    console.print(f"[dim]Interface: {interface or 'default'} | BPF: {bpf_filter or 'none'}[/]")
    if creds_only:
        console.print("[yellow]Mode: Credentials only (HTTP Basic, FTP, Telnet)[/]")
    console.print("[dim]Press Ctrl+C to stop...[/]\n")

    if not pcap_file:
        if not interface:
            interfaces = Sniffer.list_interfaces()
            if interfaces:
                console.print("[yellow]Available interfaces:[/]")
                for iface in interfaces:
                    console.print(f"  {iface['name']} - {iface['description']}")
                console.print()
                return

    killer = GracefulKiller()

    if pcap_file:
        console.print("[yellow]Processing PCAP file...[/]")
        try:
            sniffer.start(interface=None, pcap_file=pcap_file)
        except Exception as e:
            console.print(f"[red]Error reading PCAP file: {e}[/]")
            return
    else:
        def run_sniffer():
            sniffer.start(interface=interface, pcap_file=None)

        sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        sniffer_thread.start()

        try:
            from rich.live import Live
            with Live(build_layout(results), refresh_per_second=4, screen=True) as live:
                while not killer.kill_now:
                    live.update(build_layout(results))
                    for _ in range(int(4 * 0.25)):
                        if killer.kill_now:
                            break
                        time.sleep(0.25)
        except KeyboardInterrupt:
            pass
        finally:
            console.print("\n[yellow]Stopping capture...[/]")
            sniffer.stop()
            if sniffer_thread.is_alive():
                sniffer_thread.join(timeout=3)

    _print_results_summary(results)

    if output:
        try:
            path = export_json(results, output)
            console.print(f"[green]Results exported to: {path}[/]")
        except Exception as e:
            console.print(f"[red]Error exporting JSON: {e}[/]")

    if csv_output:
        try:
            base = csv_output.replace(".csv", "") if csv_output.endswith(".csv") else csv_output
            creds_path = f"{base}_credentials.csv"
            dns_path = f"{base}_dns.csv"
            path = export_csv_credentials(results, creds_path)
            console.print(f"[green]Credentials exported to: {path}[/]")
            path2 = export_csv_dns(results, dns_path)
            console.print(f"[green]DNS queries exported to: {path2}[/]")
        except Exception as e:
            console.print(f"[red]Error exporting CSV: {e}[/]")


@cli.command(name="list-interfaces")
def list_interfaces():
    """List available network interfaces."""
    setup_logging()
    interfaces = Sniffer.list_interfaces()
    if not interfaces:
        console.print("[red]No interfaces found. Run as administrator?[/]")
        return

    table = _build_interfaces_table(interfaces)
    console.print(table)


def _build_interfaces_table(interfaces: list[dict]):
    from rich.table import Table
    table = Table(title="Available Network Interfaces", box=None)
    table.add_column("Name", style="cyan", width=20)
    table.add_column("Description", style="white", width=50)
    table.add_column("IP", style="green", width=16)
    table.add_column("MAC", style="yellow", width=18)

    for iface in interfaces:
        table.add_row(
            iface["name"][:19],
            iface["description"][:49],
            iface["ip"][:15],
            iface["mac"][:17],
        )
    return table


@cli.command()
def version():
    """Show version information."""
    console.print(f"[bold cyan]NetAudit v{__version__}[/]")
    console.print("Network Traffic Analyzer for Security Audits")


def _print_results_summary(results: CaptureResults):
    from netaudit.analysis.stats import get_traffic_stats

    stats = get_traffic_stats(results)
    elapsed = time.time() - results.start_time

    console.print(f"\n[bold]=== Capture Summary ===[/]")
    console.print(f"  Duration: {elapsed:.1f}s")
    console.print(f"  Total packets: {stats['total_packets']:,}")
    console.print(f"  Total data: {stats['total_mb']:.2f} MB")
    console.print(f"  TCP: {stats['tcp_packets']:,} | UDP: {stats['udp_packets']:,} | ICMP: {stats['icmp_packets']:,}")
    console.print(f"  Unique sources: {stats['unique_sources']} | Unique destinations: {stats['unique_destinations']}")

    total_creds = len(results.http_credentials) + len(results.ftp_credentials) + len(results.telnet_credentials)
    ntlm_creds = sum(1 for c in results.ntlm_credentials if c.ntlm_type == 3 and c.username)
    console.print(f"\n[bold red]Credentials captured: {total_creds}[/]")
    console.print(f"  HTTP Basic Auth: {len(results.http_credentials)}")
    console.print(f"  HTTP POST Form: {sum(1 for c in results.http_credentials if c.method=='POST')}")
    console.print(f"  FTP: {len(results.ftp_credentials)}")
    console.print(f"  Telnet: {len(results.telnet_credentials)}")
    console.print(f"  NTLMv2 (usernames): {ntlm_creds}")

    console.print(f"\n[bold yellow]DNS queries: {len(results.dns_queries)}[/]")
    console.print(f"[bold green]Service banners: {len(results.banners)}[/]")
    console.print(f"[bold]HTTP requests: {len(results.http_requests)}[/]")
    console.print(f"[bold]Cookies captured: {len(results.cookies)}[/]")
    console.print(f"[bold]SMB messages: {len(results.smb_info)}[/]")
    console.print(f"[bold]Kerberos auths: {len(results.kerberos_auths)}[/]")
    console.print(f"[bold]TLS handshakes: {len(results.tls_info)}[/]")
