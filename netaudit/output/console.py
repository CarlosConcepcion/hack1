from __future__ import annotations
import time
from typing import Optional

from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console, Group
from rich.text import Text
from rich import box
from rich.progress import BarColumn, Progress, TextColumn

from netaudit.models import CaptureResults
from netaudit.analysis.stats import get_traffic_stats, get_top_talkers
from netaudit.analysis.conversations import get_top_conversations


console = Console()


def build_status_bar(results: CaptureResults) -> Panel:
    elapsed = time.time() - results.start_time
    pps = results.total_packets / elapsed if elapsed > 0 else 0
    stats = get_traffic_stats(results)

    text = Text()
    text.append(f"NetAudit v1.0.0", style="bold cyan")
    text.append(f"  |  Packets: {stats['total_packets']:,}", style="white")
    text.append(f"  |  Data: {stats['total_mb']:.1f} MB", style="yellow")
    text.append(f"  |  {pps:.0f} pkt/s", style="green")
    text.append(f"  |  Time: {elapsed:.0f}s", style="blue")
    text.append(f"  |  TCP: {stats['tcp_packets']:,}", style="bold cyan")
    text.append(f"  UDP: {stats['udp_packets']:,}", style="bold magenta")
    text.append(f"  ICMP: {stats['icmp_packets']:,}", style="bold green")

    return Panel(text, border_style="bright_blue", box=box.HEAVY)


def build_credentials_table(results: CaptureResults) -> Panel:
    table = Table(
        title="[bold red]Captured Credentials[/]",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold red",
        show_lines=True,
        width=120
    )
    table.add_column("Proto", style="cyan", width=7)
    table.add_column("Target", style="yellow", width=22)
    table.add_column("Username", style="green", width=25)
    table.add_column("Password / Hash", style="red", width=25)
    table.add_column("URL / Info", style="white", width=40)

    all_creds = []
    for c in results.http_credentials[-15:]:
        all_creds.append(("HTTP", f"{c.dst_ip}:{c.dst_port}", c.username, c.password, c.url))
    for c in results.ftp_credentials[-8:]:
        all_creds.append(("FTP", f"{c.dst_ip}:{c.dst_port}", c.username, c.password, c.server_banner[:40]))
    for c in results.telnet_credentials[-8:]:
        all_creds.append(("TELNET", f"{c.dst_ip}:{c.dst_port}" if c.dst_ip else "N/A", c.username, c.password, ""))
    for c in results.ntlm_credentials[-8:]:
        if c.ntlm_type == 3 and c.username:
            domain_info = f"{c.domain}\\{c.username}" if c.domain else c.username
            hash_info = f"NT:{c.nt_response[:24]}.." if c.nt_response else "NTLMv2"
            all_creds.append(("NTLMv2", f"{c.dst_ip}:{c.dst_port}", domain_info, hash_info, c.workstation))

    if not all_creds:
        table.add_row("", "[italic]No credentials captured yet...[/]", "", "", "")
    else:
        for proto, target, user, pwd, info in all_creds[-30:]:
            table.add_row(proto, target, user, pwd, info[:40])

    return Panel(table, border_style="red")


def build_dns_table(results: CaptureResults) -> Panel:
    table = Table(
        title="[bold yellow]DNS Queries[/]",
        box=box.SIMPLE,
        border_style="yellow",
        header_style="bold yellow",
        width=80
    )
    table.add_column("Domain", style="white", width=45)
    table.add_column("Type", style="cyan", width=6)
    table.add_column("Response", style="green", width=28)

    queries = results.dns_queries[-20:]
    if not queries:
        table.add_row("[italic]No DNS queries captured...[/]", "", "")
    else:
        for q in queries:
            table.add_row(q.domain[:44], q.query_type, q.response[:27])

    return Panel(table, border_style="yellow")


def build_banners_table(results: CaptureResults) -> Panel:
    table = Table(
        title="[bold green]Service Banners[/]",
        box=box.SIMPLE,
        border_style="green",
        header_style="bold green",
        width=80
    )
    table.add_column("IP:Port", style="cyan", width=22)
    table.add_column("Service", style="yellow", width=10)
    table.add_column("Banner", style="white", width=47)

    banners = results.banners[-15:]
    if not banners:
        table.add_row("[italic]No banners captured...[/]", "", "")
    else:
        for b in banners:
            table.add_row(f"{b.ip}:{b.port}", b.service, b.banner[:46])

    return Panel(table, border_style="green")


def build_stats_panel(results: CaptureResults) -> Panel:
    stats = get_traffic_stats(results)
    talkers = get_top_talkers(results, 5)

    text = Text()
    text.append(f"Protocols:\n", style="bold")
    for proto, count in sorted(stats["protocol_breakdown"].items(), key=lambda x: x[1], reverse=True)[:8]:
        pct = count / stats["total_packets"] * 100 if stats["total_packets"] > 0 else 0
        text.append(f"  {proto:12s} {count:>8,} ({pct:5.1f}%)\n", style="white")

    text.append(f"\nTop Talkers:\n", style="bold")
    for t in talkers[:5]:
        mb = t["bytes"] / (1024 * 1024)
        text.append(f"  {t['ip']:20s} {mb:6.1f} MB\n", style="cyan")

    text.append(f"\nUnique IPs: {stats['unique_sources']} src / {stats['unique_destinations']} dst", style="italic")

    return Panel(text, title="[bold magenta]Statistics[/]", border_style="magenta", width=50)


def build_network_table(results: CaptureResults) -> Panel:
    table = Table(
        title="[bold blue]SMB / Kerberos / TLS[/]",
        box=box.SIMPLE,
        border_style="blue",
        header_style="bold blue",
        width=80
    )
    table.add_column("Proto", style="cyan", width=6)
    table.add_column("Target", style="yellow", width=22)
    table.add_column("Info", style="white", width=51)

    entries = []
    for s in results.smb_info[-10:]:
        entries.append(("SMB", f"{s.dst_ip}:{s.dst_port}", f"{s.smb_version} {s.command} user={s.username} share={s.share}"))
    for k in results.kerberos_auths[-10:]:
        entries.append(("KRB", f"{k.dst_ip}:{k.dst_port}", f"{k.msg_type} realm={k.realm} user={k.client_name} svc={k.service_name}"))
    for t in results.tls_info[-10:]:
        sni_str = f" SNI={t.sni}" if t.sni else ""
        cert_str = f" CN={t.subject}" if t.subject else ""
        entries.append(("TLS", f"{t.dst_ip}:{t.dst_port}", f"{t.tls_version} {t.handshake_type}{sni_str}{cert_str}"))

    if not entries:
        table.add_row("", "[italic]Waiting for data...[/]", "")
    else:
        for proto, target, info in entries[-15:]:
            table.add_row(proto, target, info[:50])

    return Panel(table, border_style="blue")


def build_layout(results: CaptureResults) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="body"),
        Layout(name="footer", size=4),
    )
    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right"),
    )
    layout["left"].split_column(
        Layout(name="creds", ratio=3),
        Layout(name="network", ratio=2),
    )
    layout["right"].split_column(
        Layout(name="banners", ratio=2),
        Layout(name="stats", ratio=2),
    )

    layout["header"].update(build_status_bar(results))
    layout["creds"].update(build_credentials_table(results))
    layout["network"].update(build_network_table(results))
    layout["banners"].update(build_banners_table(results))
    layout["stats"].update(build_stats_panel(results))

    footer = Text()
    ntlm_count = sum(1 for c in results.ntlm_credentials if c.ntlm_type == 3 and c.username)
    cookie_count = len(results.cookies)
    smb_count = len(results.smb_info)
    kerb_count = len(results.kerberos_auths)
    tls_count = len(results.tls_info)
    footer.append(f" Ctrl+C to stop  |  HTTP:{len(results.http_credentials)} FTP:{len(results.ftp_credentials)} Telnet:{len(results.telnet_credentials)} NTLMv2:{ntlm_count} Cookies:{cookie_count} SMB:{smb_count} KRB:{kerb_count} TLS:{tls_count} DNS:{len(results.dns_queries)}",
                  style="italic dim")
    layout["footer"].update(Panel(footer, border_style="bright_black"))

    return layout


async def run_console_display(results: CaptureResults, stop_event):
    try:
        with Live(build_layout(results), refresh_per_second=4, screen=True, console=console) as live:
            while not stop_event.is_set():
                live.update(build_layout(results))
                for _ in range(10):
                    if stop_event.is_set():
                        break
                    time.sleep(0.1)
    except Exception as e:
        console.print(f"[red]Display error: {e}[/]")
