from __future__ import annotations
from netaudit.models import CaptureResults


def get_credentials_summary(results: CaptureResults) -> dict:
    total = len(results.http_credentials) + len(results.ftp_credentials) + len(results.telnet_credentials)
    return {
        "total": total,
        "http": len(results.http_credentials),
        "ftp": len(results.ftp_credentials),
        "telnet": len(results.telnet_credentials),
    }


def get_credentials_report(results: CaptureResults) -> list[dict]:
    report = []
    for c in results.http_credentials:
        report.append({
            "type": "HTTP Basic Auth",
            "timestamp": c.timestamp,
            "source": f"{c.src_ip}:{c.src_port}",
            "target": f"{c.dst_ip}:{c.dst_port}",
            "username": c.username,
            "password": c.password,
            "url": c.url,
            "method": c.method,
        })
    for c in results.ftp_credentials:
        report.append({
            "type": "FTP",
            "timestamp": c.timestamp,
            "source": f"{c.src_ip}:{c.src_port}",
            "target": f"{c.dst_ip}:{c.dst_port}",
            "username": c.username,
            "password": c.password,
            "banner": c.server_banner,
        })
    for c in results.telnet_credentials:
        report.append({
            "type": "Telnet",
            "timestamp": c.timestamp,
            "source": f"{c.src_ip}:{c.src_port}",
            "target": f"{c.dst_ip}:{c.dst_port}",
            "username": c.username,
            "password": c.password,
        })
    return sorted(report, key=lambda x: x["timestamp"])
