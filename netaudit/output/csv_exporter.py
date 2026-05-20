from __future__ import annotations
import csv
import time
from typing import Optional

from netaudit.models import CaptureResults
from netaudit.analysis.credentials import get_credentials_report


def export_csv_credentials(results: CaptureResults, filepath: str) -> str:
    creds = get_credentials_report(results)
    fieldnames = ["type", "timestamp", "source", "target", "username", "password", "url", "method", "banner"]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for c in creds:
            writer.writerow(c)

    return filepath


def export_csv_dns(results: CaptureResults, filepath: str) -> str:
    fieldnames = ["timestamp", "source", "resolver", "domain", "type", "response"]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for q in results.dns_queries:
            writer.writerow({
                "timestamp": q.timestamp,
                "source": q.src_ip,
                "resolver": q.dst_ip,
                "domain": q.domain,
                "type": q.query_type,
                "response": q.response,
            })

    return filepath


def export_csv_all(results: CaptureResults, base_path: str) -> list[str]:
    exported = []
    creds_path = base_path.replace(".csv", "_credentials.csv") if base_path.endswith(".csv") else f"{base_path}_credentials.csv"
    dns_path = base_path.replace(".csv", "_dns.csv") if base_path.endswith(".csv") else f"{base_path}_dns.csv"
    exported.append(export_csv_credentials(results, creds_path))
    exported.append(export_csv_dns(results, dns_path))
    return exported
