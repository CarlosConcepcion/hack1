from __future__ import annotations
from netaudit.models import CaptureResults, Conversation


def get_top_conversations(results: CaptureResults, n: int = 10) -> list[Conversation]:
    convs = sorted(
        results.conversations.values(),
        key=lambda c: c.bytes_total,
        reverse=True
    )
    return convs[:n]


def get_conversation_stats(results: CaptureResults) -> dict:
    total_conv = len(results.conversations)
    total_bytes = sum(c.bytes_total for c in results.conversations.values())
    total_packets = sum(c.packets for c in results.conversations.values())
    active_conv = sum(1 for c in results.conversations.values()
                      if c.last_time > 0 and (results.start_time - c.last_time) < 60)

    return {
        "total_conversations": total_conv,
        "total_conversation_bytes": total_bytes,
        "total_conversation_packets": total_packets,
        "active_last_60s": active_conv,
    }
