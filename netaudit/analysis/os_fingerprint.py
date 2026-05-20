TTL_MAP = {
    range(0, 33): "Unknown (low TTL)",
    range(32, 65): "Linux/Unix (TTL 64)",
    range(64, 129): "Windows (TTL 128)",
    range(128, 256): "BSD/Solaris/Cisco (TTL 255)",
}


def fingerprint_ttl(ttl: int) -> str:
    for ttl_range, os_name in TTL_MAP.items():
        if ttl in ttl_range:
            return os_name
    return f"Unknown (TTL {ttl})"


def fingerprint_from_tcp(tcp_flags: int, window_size: int, ttl: int, options: bytes = b"") -> dict:
    result = {
        "ttl": ttl,
        "ttl_guess": fingerprint_ttl(ttl),
        "window_size": window_size,
    }

    if window_size == 65535 and ttl <= 128:
        result["window_guess"] = "Windows (common)"
    elif window_size == 5840 and ttl <= 64:
        result["window_guess"] = "Linux (common)"
    elif window_size == 16384:
        result["window_guess"] = "BSD (common)"
    else:
        result["window_guess"] = "Unknown"

    return result
