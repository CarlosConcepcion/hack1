from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict
import threading
import time


@dataclass
class HTTPCredential:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    username: str
    password: str
    url: str
    method: str = ""
    host: str = ""


@dataclass
class FTPCredential:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    username: str
    password: str
    server_banner: str = ""


@dataclass
class TelnetCredential:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    username: str
    password: str
    raw_data: bytes = b""


@dataclass
class DNSQuery:
    timestamp: float
    src_ip: str
    dst_ip: str
    domain: str
    query_type: str
    response: str = ""


@dataclass
class ServiceBanner:
    timestamp: float
    ip: str
    port: int
    service: str
    banner: str


@dataclass
class NTLMCredential:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    username: str = ""
    domain: str = ""
    workstation: str = ""
    ntlm_type: int = 3
    challenge: str = ""
    nt_response: str = ""
    lm_response: str = ""
    session_key: str = ""
    os_version: str = ""
    raw_data: str = ""


@dataclass
class HTTPCookie:
    timestamp: float
    src_ip: str
    dst_ip: str
    domain: str
    path: str
    name: str
    value: str
    secure: bool = False
    http_only: bool = False
    source: str = "response"


@dataclass
class SMBInfo:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    smb_version: str = ""
    command: str = ""
    username: str = ""
    domain: str = ""
    share: str = ""
    ntlmssp_detected: bool = False


@dataclass
class KerberosAuth:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    msg_type: str = ""
    realm: str = ""
    client_name: str = ""
    service_name: str = ""
    ticket_encryption: str = ""


@dataclass
class TLSInfo:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    handshake_type: str = ""
    tls_version: str = ""
    sni: str = ""
    subject: str = ""
    issuer: str = ""
    cipher_suite: str = ""
    certificate_serial: str = ""
    not_before: str = ""
    not_after: str = ""


@dataclass
class CapturedURL:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    method: str
    host: str
    path: str
    full_url: str
    user_agent: str = ""


@dataclass
class HTTPRequest:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    method: str
    host: str
    path: str
    user_agent: str = ""
    headers: dict = field(default_factory=dict)
    body: bytes = b""


@dataclass
class Conversation:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packets: int = 0
    bytes_total: int = 0
    start_time: float = 0.0
    last_time: float = 0.0
    src_data: bytes = b""
    dst_data: bytes = b""


FTLPORT_PROTO = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL",
    5900: "VNC", 6379: "REDIS", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MONGODB",
}


class CaptureResults:
    def __init__(self):
        self.http_credentials: list[HTTPCredential] = []
        self.ftp_credentials: list[FTPCredential] = []
        self.telnet_credentials: list[TelnetCredential] = []
        self.dns_queries: list[DNSQuery] = []
        self.banners: list[ServiceBanner] = []
        self.urls: list[CapturedURL] = []
        self.http_requests: list[HTTPRequest] = []
        self.ntlm_credentials: list[NTLMCredential] = []
        self.cookies: list[HTTPCookie] = []
        self.smb_info: list[SMBInfo] = []
        self.kerberos_auths: list[KerberosAuth] = []
        self.tls_info: list[TLSInfo] = []
        self.conversations: dict[str, Conversation] = {}
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.ip_packets: int = 0
        self.tcp_packets: int = 0
        self.udp_packets: int = 0
        self.icmp_packets: int = 0
        self.other_packets: int = 0
        self.unique_src_ips: set = set()
        self.unique_dst_ips: set = set()
        self.start_time: float = time.time()
        self.protocol_counts: dict = defaultdict(int)
        self._lock = threading.Lock()

    def add_http_credential(self, cred: HTTPCredential):
        with self._lock:
            self.http_credentials.append(cred)

    def add_ftp_credential(self, cred: FTPCredential):
        with self._lock:
            self.ftp_credentials.append(cred)

    def add_telnet_credential(self, cred: TelnetCredential):
        with self._lock:
            self.telnet_credentials.append(cred)

    def add_dns_query(self, query: DNSQuery):
        with self._lock:
            self.dns_queries.append(query)

    def add_banner(self, banner: ServiceBanner):
        with self._lock:
            self.banners.append(banner)

    def add_url(self, url: CapturedURL):
        with self._lock:
            self.urls.append(url)

    def add_ntlm_credential(self, cred: NTLMCredential):
        with self._lock:
            self.ntlm_credentials.append(cred)

    def add_cookie(self, cookie: HTTPCookie):
        with self._lock:
            self.cookies.append(cookie)

    def add_smb_info(self, info: SMBInfo):
        with self._lock:
            self.smb_info.append(info)

    def add_kerberos_auth(self, auth: KerberosAuth):
        with self._lock:
            self.kerberos_auths.append(auth)

    def add_tls_info(self, info: TLSInfo):
        with self._lock:
            self.tls_info.append(info)

    def add_http_request(self, req: HTTPRequest):
        with self._lock:
            self.http_requests.append(req)

    @property
    def all_credentials(self) -> list:
        creds = []
        with self._lock:
            for c in self.http_credentials:
                creds.append(("HTTP", c.timestamp, c.src_ip, c.dst_ip, c.dst_port, c.username, c.password, c.url))
            for c in self.ftp_credentials:
                creds.append(("FTP", c.timestamp, c.src_ip, c.dst_ip, c.dst_port, c.username, c.password, ""))
            for c in self.telnet_credentials:
                creds.append(("TELNET", c.timestamp, c.src_ip, c.dst_ip, c.dst_port, c.username, c.password, ""))
        return sorted(creds, key=lambda x: x[1])

    def get_conversation_key(self, src_ip, src_port, dst_ip, dst_port, protocol):
        ips = sorted([src_ip, dst_ip])
        ports = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        return f"{protocol}|{ports[0][0]}:{ports[0][1]}<->{ports[1][0]}:{ports[1][1]}"

    def update_conversation(self, src_ip, src_port, dst_ip, dst_port, protocol, payload_len, timestamp):
        key = self.get_conversation_key(src_ip, src_port, dst_ip, dst_port, protocol)
        with self._lock:
            if key not in self.conversations:
                self.conversations[key] = Conversation(
                    src_ip=src_ip, src_port=src_port,
                    dst_ip=dst_ip, dst_port=dst_port,
                    protocol=protocol, start_time=timestamp
                )
            conv = self.conversations[key]
            conv.packets += 1
            conv.bytes_total += payload_len
            conv.last_time = timestamp
