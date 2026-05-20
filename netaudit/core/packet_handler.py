from __future__ import annotations
import logging
import base64
import time
from typing import Optional

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

from netaudit.config import NetAuditConfig
from netaudit.models import (
    CaptureResults, HTTPCredential, FTPCredential, TelnetCredential,
    DNSQuery, ServiceBanner, CapturedURL, HTTPRequest,
    FTLPORT_PROTO
)
from netaudit.protocols.http import parse_http
from netaudit.protocols.ftp import parse_ftp
from netaudit.protocols.telnet import parse_telnet
from netaudit.protocols.smb import parse_smb
from netaudit.protocols.kerberos import parse_kerberos
from netaudit.protocols.tls import parse_tls
from netaudit.protocols.banners import check_banner

logger = logging.getLogger("netaudit.handler")


class PacketHandler:
    def __init__(self, config: NetAuditConfig, results: CaptureResults):
        self.config = config
        self.results = results
        self._seen_banners: set = set()

    def handle(self, pkt: Packet):
        try:
            self.results.total_packets += 1
            self.results.total_bytes += len(pkt)

            if Ether in pkt:
                self._handle_ether(pkt)
            elif IP in pkt:
                self._handle_ip(pkt)
        except Exception as e:
            logger.debug(f"Error handling packet: {e}")

    def _handle_ether(self, pkt: Packet):
        if IP in pkt:
            self._handle_ip(pkt)

    def _handle_ip(self, pkt: Packet):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        iplen = ip_layer.len

        self.results.ip_packets += 1
        self.results.unique_src_ips.add(src_ip)
        self.results.unique_dst_ips.add(dst_ip)

        if TCP in pkt:
            self.results.tcp_packets += 1
            self.results.protocol_counts["TCP"] += 1
            self._handle_tcp(pkt, src_ip, dst_ip)
        elif UDP in pkt:
            self.results.udp_packets += 1
            self.results.protocol_counts["UDP"] += 1
            self._handle_udp(pkt, src_ip, dst_ip)
        elif ICMP in pkt:
            self.results.icmp_packets += 1
            self.results.protocol_counts["ICMP"] += 1
        else:
            self.results.other_packets += 1
            proto = ip_layer.proto
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"IP-{proto}")
            self.results.protocol_counts[proto_name] += 1

    def _handle_tcp(self, pkt: Packet, src_ip: str, dst_ip: str):
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        payload = bytes(tcp.payload)
        payload_len = len(payload)
        timestamp = time.time()

        self.results.update_conversation(
            src_ip, src_port, dst_ip, dst_port, "TCP",
            payload_len + 20, timestamp
        )

        if not payload:
            return

        if self.config.creds_only:
            self._check_creds_only_tcp(
                src_ip, src_port, dst_ip, dst_port,
                payload, timestamp, pkt
            )
            return

        if dst_port in self.config.HTTP_PORTS or src_port in self.config.HTTP_PORTS:
            self.results.protocol_counts["HTTP"] += 1
            parse_http(self.results, self.config, src_ip, src_port, dst_ip, dst_port, payload, timestamp, src_port > dst_port)
            self._check_banner(pkt, src_ip, src_port, dst_ip, dst_port, payload, timestamp)
        elif dst_port in self.config.FTP_PORTS or src_port in self.config.FTP_PORTS:
            self.results.protocol_counts["FTP"] += 1
            is_server = src_port in self.config.FTP_PORTS
            parse_ftp(self.results, src_ip, src_port, dst_ip, dst_port, payload, timestamp, is_server)
            self._check_banner(pkt, src_ip, src_port, dst_ip, dst_port, payload, timestamp)
        elif dst_port in self.config.TELNET_PORTS or src_port in self.config.TELNET_PORTS:
            self.results.protocol_counts["TELNET"] += 1
            is_server = src_port in self.config.TELNET_PORTS
            parse_telnet(self.results, src_ip, src_port, dst_ip, dst_port, payload, timestamp, is_server)
        elif dst_port == 22 or src_port == 22:
            self.results.protocol_counts["SSH"] += 1
            self._check_banner(pkt, src_ip, src_port, dst_ip, dst_port, payload, timestamp)
        elif dst_port == 25 or src_port == 25:
            self.results.protocol_counts["SMTP"] += 1
            self._check_banner(pkt, src_ip, src_port, dst_ip, dst_port, payload, timestamp)
        elif dst_port == 445 or src_port == 445:
            self.results.protocol_counts["SMB"] += 1
            is_response = src_port == 445
            parse_smb(self.results, src_ip, src_port, dst_ip, dst_port, payload, timestamp, is_response)
            self._check_banner(pkt, src_ip, src_port, dst_ip, dst_port, payload, timestamp)
        elif dst_port == 88 or src_port == 88:
            self.results.protocol_counts["KERBEROS"] += 1
            parse_kerberos(self.results, src_ip, src_port, dst_ip, dst_port, payload, timestamp)
        elif dst_port == 443 or dst_port == 8443 or src_port == 443:
            self.results.protocol_counts["TLS"] += 1
            parse_tls(self.results, src_ip, src_port, dst_ip, dst_port, payload, timestamp)
        elif dst_port in self.config.BANNER_PORTS or src_port in self.config.BANNER_PORTS:
            self._check_banner(pkt, src_ip, src_port, dst_ip, dst_port, payload, timestamp)
        else:
            service = FTLPORT_PROTO.get(dst_port) or FTLPORT_PROTO.get(src_port)
            if service:
                self.results.protocol_counts[service] += 1
                self._check_banner(pkt, src_ip, src_port, dst_ip, dst_port, payload, timestamp)

    def _handle_udp(self, pkt: Packet, src_ip: str, dst_ip: str):
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        payload = bytes(udp.payload)
        payload_len = len(payload)
        timestamp = time.time()

        self.results.update_conversation(
            src_ip, src_port, dst_ip, dst_port, "UDP",
            payload_len + 8, timestamp
        )

        if dst_port in self.config.DNS_PORTS or src_port in self.config.DNS_PORTS:
            self._handle_dns(pkt, src_ip, dst_ip, timestamp)
        elif dst_port == 88 or src_port == 88:
            self.results.protocol_counts["KERBEROS"] += 1
            parse_kerberos(self.results, src_ip, src_port, dst_ip, dst_port, payload, timestamp)

    def _handle_dns(self, pkt: Packet, src_ip: str, dst_ip: str, timestamp: float):
        self.results.protocol_counts["DNS"] += 1
        try:
            if DNS in pkt:
                dns = pkt[DNS]
                qd = dns.qd
                if isinstance(qd, DNSQR):
                    qd_list = [qd]
                elif isinstance(qd, list) and len(qd) > 0:
                    qd_list = qd
                else:
                    return

                for query in qd_list:
                    if not hasattr(query, 'qname'):
                        continue
                    domain = query.qname.decode("utf-8", errors="replace").rstrip(".")
                    qtype = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT",
                             28: "AAAA", 33: "SRV", 255: "ANY"}.get(query.qtype, str(query.qtype))

                    response = ""
                    if dns.an:
                        an = dns.an
                        if isinstance(an, DNSRR):
                            an_list = [an]
                        elif isinstance(an, list):
                            an_list = an
                        else:
                            an_list = []
                        for answer in an_list:
                            if hasattr(answer, 'rdata'):
                                rdata = answer.rdata
                                if isinstance(rdata, bytes):
                                    response = rdata.decode("utf-8", errors="replace")
                                else:
                                    response = str(rdata)
                                break

                    self.results.add_dns_query(DNSQuery(
                        timestamp=timestamp,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        domain=domain,
                        query_type=qtype,
                        response=str(response) if response else ""
                    ))
        except Exception as e:
            logger.debug(f"DNS parse error: {e}")

    def _check_banner(self, pkt: Packet, src_ip: str, src_port: int,
                      dst_ip: str, dst_port: int, payload: bytes, timestamp: float):
        if not payload:
            return
        banner_key = f"{dst_ip}:{dst_port}"
        if banner_key in self._seen_banners:
            return
        server_banner = check_banner(dst_port, src_port, payload)
        if server_banner:
            self._seen_banners.add(banner_key)
            self.results.add_banner(ServiceBanner(
                timestamp=timestamp,
                ip=dst_ip,
                port=dst_port,
                service=server_banner["service"],
                banner=server_banner["banner"]
            ))

    def _check_creds_only_tcp(self, src_ip, src_port, dst_ip, dst_port, payload, timestamp, pkt):
        if dst_port in self.config.HTTP_PORTS or src_port in self.config.HTTP_PORTS:
            parse_http(self.results, self.config, src_ip, src_port, dst_ip, dst_port, payload, timestamp, src_port > dst_port)
        elif dst_port in self.config.FTP_PORTS or src_port in self.config.FTP_PORTS:
            is_server = src_port in self.config.FTP_PORTS
            parse_ftp(self.results, src_ip, src_port, dst_ip, dst_port, payload, timestamp, is_server)
        elif dst_port in self.config.TELNET_PORTS or src_port in self.config.TELNET_PORTS:
            is_server = src_port in self.config.TELNET_PORTS
            parse_telnet(self.results, src_ip, src_port, dst_ip, dst_port, payload, timestamp, is_server)
