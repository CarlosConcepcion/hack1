from __future__ import annotations
from netaudit.models import CaptureResults, DNSQuery
from scapy.packet import Packet
from scapy.layers.dns import DNS, DNSQR, DNSRR

import logging
logger = logging.getLogger("netaudit.dns")


def parse_dns_packet(results: CaptureResults, pkt: Packet, src_ip: str, dst_ip: str, timestamp: float):
    if DNS not in pkt:
        return

    try:
        dns = pkt[DNS]
        if dns.qr != 0:
            return

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

            results.add_dns_query(DNSQuery(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                domain=domain,
                query_type=qtype,
                response=response
            ))
    except Exception as e:
        logger.debug(f"DNS parse error: {e}")
