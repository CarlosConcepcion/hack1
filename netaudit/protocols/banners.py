from __future__ import annotations
from typing import Optional


def check_banner(dst_port: int, src_port: int, payload: bytes) -> Optional[dict]:
    if not payload or len(payload) < 4:
        return None

    try:
        text = payload.decode("utf-8", errors="replace")[:512]
    except Exception:
        return None

    if dst_port == 21 or src_port == 21:
        if text.startswith("220"):
            banner = text.split("\r\n")[0] if "\r\n" in text else text[:200]
            return {"service": "FTP", "banner": banner.strip()}

    if dst_port == 22 or src_port == 22:
        if text.startswith("SSH-"):
            banner = text.split("\r\n")[0] if "\r\n" in text else text[:200]
            return {"service": "SSH", "banner": banner.strip()}

    if dst_port == 25 or src_port == 25:
        if text.startswith("220"):
            banner = text.split("\r\n")[0] if "\r\n" in text else text[:200]
            return {"service": "SMTP", "banner": banner.strip()}

    if dst_port in (80, 8080, 8000) or src_port in (80, 8080):
        lines = text.split("\r\n")
        if lines and lines[0].startswith("HTTP/"):
            for line in lines[1:]:
                if line.lower().startswith("server:"):
                    return {"service": "HTTP", "banner": line.split(":", 1)[1].strip()}

    if dst_port == 110 or src_port == 110:
        if text.startswith("+OK"):
            banner = text.split("\r\n")[0] if "\r\n" in text else text[:200]
            return {"service": "POP3", "banner": banner.strip()}

    if dst_port == 143 or src_port == 143:
        if text.startswith("* OK"):
            banner = text.split("\r\n")[0] if "\r\n" in text else text[:200]
            return {"service": "IMAP", "banner": banner.strip()}

    if dst_port == 3306 or src_port == 3306:
        if len(payload) >= 4:
            server_version = payload[4:].split(b"\0")[0] if b"\0" in payload[4:] else payload[4:32]
            try:
                banner = server_version.decode("utf-8", errors="replace").strip()
                if banner:
                    return {"service": "MySQL", "banner": banner}
            except Exception:
                pass

    if dst_port == 5432 or src_port == 5432:
        if len(payload) >= 16:
            try:
                version_end = payload.find(b"\0", 8)
                if version_end > 8:
                    banner = payload[8:version_end].decode("utf-8", errors="replace").strip()
                    if banner:
                        return {"service": "PostgreSQL", "banner": banner}
            except Exception:
                pass

    if dst_port == 6379 or src_port == 6379:
        text_upper = text.upper()
        if text_upper.startswith("+PONG") or text_upper.startswith("-") or text_upper.startswith("$") or text_upper.startswith("*") or text_upper.startswith(":"):
            for line in text.split("\r\n"):
                if line:
                    return {"service": "Redis", "banner": line[:200].strip()}

    if dst_port == 27017 or src_port == 27017:
        if len(payload) >= 36:
            try:
                if payload[0:1] == b"\x3a" or payload[0:1] == b"\x01":
                    return {"service": "MongoDB", "banner": "MongoDB wire protocol detected"}
            except Exception:
                pass

    if dst_port == 3389 or src_port == 3389:
        if len(payload) >= 8 and payload[0:3] == b"\x03\x00\x00":
            try:
                banner_text = payload[8:].split(b"\x00")[0].decode("utf-8", errors="replace").strip()
                if banner_text:
                    return {"service": "RDP", "banner": banner_text[:200]}
            except Exception:
                return {"service": "RDP", "banner": "RDP protocol detected"}

    if dst_port == 5900 or src_port == 5900:
        if payload.startswith(b"RFB "):
            banner = text.split("\r\n")[0] if "\r\n" in text else text[:200]
            return {"service": "VNC", "banner": banner.strip()}

    if dst_port == 445 or src_port == 445:
        if len(payload) >= 8:
            if payload[0:4] == b"\x00\x00\x00\x85" or payload[0:4] == b"\x00\x00\x00\x72":
                return {"service": "SMB", "banner": "SMB protocol detected"}

    if dst_port == 443 or dst_port == 8443 or src_port == 443:
        return None

    return None
