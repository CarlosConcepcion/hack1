from __future__ import annotations
from netaudit.models import CaptureResults


def get_traffic_stats(results: CaptureResults) -> dict:
    elapsed = results.total_bytes / (1024 * 1024) if results.total_bytes > 0 else 0
    return {
        "total_packets": results.total_packets,
        "total_bytes": results.total_bytes,
        "total_mb": round(elapsed, 2),
        "ip_packets": results.ip_packets,
        "tcp_packets": results.tcp_packets,
        "udp_packets": results.udp_packets,
        "icmp_packets": results.icmp_packets,
        "other_packets": results.other_packets,
        "unique_sources": len(results.unique_src_ips),
        "unique_destinations": len(results.unique_dst_ips),
        "protocol_breakdown": dict(results.protocol_counts),
    }


def get_top_talkers(results: CaptureResults, n: int = 5) -> list[dict]:
    ip_bytes: dict[str, int] = {}
    for conv in results.conversations.values():
        ip_bytes[conv.src_ip] = ip_bytes.get(conv.src_ip, 0) + conv.bytes_total
        ip_bytes[conv.dst_ip] = ip_bytes.get(conv.dst_ip, 0) + conv.bytes_total

    sorted_ips = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)
    return [{"ip": ip, "bytes": bytes_count} for ip, bytes_count in sorted_ips[:n]]
