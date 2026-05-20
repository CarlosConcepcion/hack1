from __future__ import annotations
import json
import time
from typing import Optional

from netaudit.models import CaptureResults
from netaudit.analysis.credentials import get_credentials_report
from netaudit.analysis.stats import get_traffic_stats


def export_json(results: CaptureResults, filepath: str) -> str:
    data = _build_export_data(results)
    json_str = json.dumps(data, indent=2, default=str)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(json_str)
    return filepath


def _build_export_data(results: CaptureResults) -> dict:
    stats = get_traffic_stats(results)

    credentials = get_credentials_report(results)

    http_reqs = []
    for r in results.http_requests:
        http_reqs.append({
            "timestamp": r.timestamp,
            "source": f"{r.src_ip}:{r.src_port}",
            "target": f"{r.dst_ip}:{r.dst_port}",
            "method": r.method,
            "host": r.host,
            "path": r.path,
            "user_agent": r.user_agent,
        })

    dns_entries = []
    for q in results.dns_queries:
        dns_entries.append({
            "timestamp": q.timestamp,
            "source": q.src_ip,
            "resolver": q.dst_ip,
            "domain": q.domain,
            "type": q.query_type,
            "response": q.response,
        })

    banners = []
    for b in results.banners:
        banners.append({
            "timestamp": b.timestamp,
            "ip": b.ip,
            "port": b.port,
            "service": b.service,
            "banner": b.banner,
        })

    conversations = []
    for c in results.conversations.values():
        conversations.append({
            "src_ip": c.src_ip,
            "src_port": c.src_port,
            "dst_ip": c.dst_ip,
            "dst_port": c.dst_port,
            "protocol": c.protocol,
            "packets": c.packets,
            "bytes": c.bytes_total,
            "duration": round(c.last_time - c.start_time, 2) if c.start_time and c.last_time else 0,
        })

    ntlm_entries = []
    for n in results.ntlm_credentials:
        ntlm_entries.append({
            "timestamp": n.timestamp,
            "type": f"NTLM Type {n.ntlm_type}",
            "source": f"{n.src_ip}:{n.src_port}",
            "target": f"{n.dst_ip}:{n.dst_port}",
            "username": n.username,
            "domain": n.domain,
            "workstation": n.workstation,
            "challenge": n.challenge,
            "nt_response": n.nt_response,
            "lm_response": n.lm_response,
            "os_version": n.os_version,
        })

    cookie_entries = []
    for ck in results.cookies:
        cookie_entries.append({
            "timestamp": ck.timestamp,
            "source": ck.src_ip,
            "domain": ck.domain,
            "name": ck.name,
            "value": ck.value,
            "secure": ck.secure,
            "http_only": ck.http_only,
        })

    smb_entries = []
    for s in results.smb_info:
        smb_entries.append({
            "timestamp": s.timestamp,
            "source": f"{s.src_ip}:{s.src_port}",
            "target": f"{s.dst_ip}:{s.dst_port}",
            "smb_version": s.smb_version,
            "command": s.command,
            "username": s.username,
            "domain": s.domain,
            "share": s.share,
            "ntlmssp_detected": s.ntlmssp_detected,
        })

    kerb_entries = []
    for k in results.kerberos_auths:
        kerb_entries.append({
            "timestamp": k.timestamp,
            "source": f"{k.src_ip}:{k.src_port}",
            "target": f"{k.dst_ip}:{k.dst_port}",
            "msg_type": k.msg_type,
            "realm": k.realm,
            "client_name": k.client_name,
            "service_name": k.service_name,
            "ticket_encryption": k.ticket_encryption,
        })

    tls_entries = []
    for t in results.tls_info:
        tls_entries.append({
            "timestamp": t.timestamp,
            "source": f"{t.src_ip}:{t.src_port}",
            "target": f"{t.dst_ip}:{t.dst_port}",
            "handshake_type": t.handshake_type,
            "tls_version": t.tls_version,
            "sni": t.sni,
            "subject": t.subject,
            "issuer": t.issuer,
        })

    return {
        "tool": "NetAudit v1.0.0",
        "capture_duration": round(time.time() - results.start_time, 2),
        "statistics": stats,
        "credentials": credentials,
        "http_requests": http_reqs,
        "dns_queries": dns_entries,
        "service_banners": banners,
        "ntlm_authentication": ntlm_entries,
        "http_cookies": cookie_entries,
        "smb_traffic": smb_entries,
        "kerberos_authentication": kerb_entries,
        "tls_handshakes": tls_entries,
        "conversations": conversations,
    }
