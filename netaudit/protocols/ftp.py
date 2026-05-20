from __future__ import annotations
import logging
from typing import Optional

from netaudit.models import CaptureResults, FTPCredential

logger = logging.getLogger("netaudit.ftp")

_ftp_sessions: dict[str, dict] = {}


def parse_ftp(
    results: CaptureResults, src_ip: str, src_port: int,
    dst_ip: str, dst_port: int, payload: bytes, timestamp: float,
    is_server: bool
):
    if not payload:
        return

    try:
        text = payload.decode("utf-8", errors="replace").strip()
    except Exception:
        return

    if not text:
        return

    session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

    sess = _ftp_sessions.get(session_key)
    if sess is None:
        sess = _ftp_sessions.get(rev_key)
        if sess is None:
            sess = {"user": "", "pass": "", "banner": "", "logged": False}
            _ftp_sessions[session_key] = sess

    if is_server:
        if text.startswith("220 ") and not sess["banner"]:
            sess["banner"] = text[4:]
        elif text.startswith("230 ") and sess["user"] and sess["pass"] and not sess["logged"]:
            sess["logged"] = True
            results.add_ftp_credential(FTPCredential(
                timestamp=timestamp,
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                username=sess["user"], password=sess["pass"],
                server_banner=sess["banner"]
            ))
    else:
        text_upper = text.upper()
        if text_upper.startswith("USER "):
            user = text[5:].strip().strip("\r\n")
            if user:
                sess["user"] = user
        elif text_upper.startswith("PASS "):
            pwd = text[5:].strip().strip("\r\n")
            if pwd:
                sess["pass"] = pwd
                if sess["user"] and sess["pass"] and not sess["logged"]:
                    sess["logged"] = True
                    results.add_ftp_credential(FTPCredential(
                        timestamp=timestamp,
                        src_ip=src_ip, src_port=src_port,
                        dst_ip=dst_ip, dst_port=dst_port,
                        username=sess["user"], password=sess["pass"],
                        server_banner=sess["banner"]
                    ))
