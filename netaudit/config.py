import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NetAuditConfig:
    interface: Optional[str] = None
    pcap_file: Optional[str] = None
    output_file: Optional[str] = None
    csv_output: Optional[str] = None
    bpf_filter: Optional[str] = None
    creds_only: bool = False
    no_resolve: bool = False
    stats_every: int = 2
    save_pcap: Optional[str] = None
    quiet: bool = False
    show_all_dns: bool = False
    max_creds_display: int = 50
    max_dns_display: int = 20
    max_banners_display: int = 20
    max_urls_display: int = 30

    HTTP_PORTS = {80, 8080, 8000, 8888, 3128}
    FTP_PORTS = {21}
    TELNET_PORTS = {23}
    DNS_PORTS = {53}
    BANNER_PORTS = {21, 22, 25, 80, 8080, 110, 143, 443}
    SSH_PORTS = {22}
    SMTP_PORTS = {25}
    POP3_PORTS = {110}
    IMAP_PORTS = {143}
    HTTPS_PORTS = {443, 8443}
