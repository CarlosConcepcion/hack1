from __future__ import annotations
import logging
import re
from typing import Optional

from netaudit.models import CaptureResults, TelnetCredential

logger = logging.getLogger("netaudit.telnet")

IAC = bytes([255])
DONT = bytes([254])
DO = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
SB = bytes([250])
SE = bytes([240])
TELOPT_ECHO = bytes([1])

_telnet_sessions: dict[str, dict] = {}


def parse_telnet(
    results: CaptureResults, src_ip: str, src_port: int,
    dst_ip: str, dst_port: int, payload: bytes, timestamp: float,
    is_server: bool
):
    if not payload:
        return

    clean = _strip_telnet_negotiation(payload)
    if not clean:
        return

    try:
        text = clean.decode("utf-8", errors="replace")
    except Exception:
        return

    text = text.strip("\r\n\t ")
    if not text:
        return

    session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

    sess = _telnet_sessions.get(session_key)
    if sess is None:
        sess = _telnet_sessions.get(rev_key)
        if sess is None:
            sess = {"state": "init", "buffer": "", "user": "", "pass": "",
                    "timestamp": 0, "src_ip": src_ip, "src_port": src_port,
                    "dst_ip": dst_ip, "dst_port": dst_port}
            _telnet_sessions[session_key] = sess

    text_lower = text.lower()

    if is_server:
        if sess["state"] == "init":
            if any(p in text_lower for p in ["login:", "login ", "username:", "username ",
                                              "user:", "user ", "account:"]):
                sess["state"] = "wait_user"
                sess["timestamp"] = timestamp
            elif any(p in text_lower for p in ["password:", "password ", "pass:", "pass "]):
                sess["state"] = "wait_pass"
                sess["timestamp"] = timestamp
        elif sess["state"] == "wait_pass":
            if any(p in text_lower for p in ["login:", "login ", "username:", "username ",
                                              "user:", "user ", "account:"]):
                _finalize_telnet(results, sess, timestamp)
                sess["state"] = "wait_user"
                sess["user"] = ""
                sess["pass"] = ""
                sess["buffer"] = ""
                sess["timestamp"] = timestamp
            else:
                sess["buffer"] += text
        elif sess["state"] == "wait_user":
            if any(p in text_lower for p in ["password:", "password ", "pass:", "pass "]):
                if sess["buffer"]:
                    sess["user"] = sess["buffer"].strip()
                sess["buffer"] = ""
                sess["state"] = "wait_pass"
                sess["timestamp"] = timestamp
            else:
                sess["buffer"] += text
    else:
        if sess["state"] == "wait_user" and text:
            sess["user"] = text.strip()
            sess["src_ip"] = src_ip
            sess["src_port"] = src_port
            sess["dst_ip"] = dst_ip
            sess["dst_port"] = dst_port
        elif sess["state"] == "wait_pass" and text:
            sess["pass"] = text.strip()
            sess["src_ip"] = src_ip
            sess["src_port"] = src_port
            sess["dst_ip"] = dst_ip
            sess["dst_port"] = dst_port
            _finalize_telnet(results, sess, timestamp)

    if len(sess["buffer"]) > 1024:
        sess["buffer"] = sess["buffer"][-1024:]


def _finalize_telnet(results: CaptureResults, sess: dict, timestamp: float):
    if sess["user"] and sess["pass"]:
        results.add_telnet_credential(TelnetCredential(
            timestamp=timestamp or sess["timestamp"],
            src_ip=sess.get("src_ip", ""), src_port=sess.get("src_port", 0),
            dst_ip=sess.get("dst_ip", ""), dst_port=sess.get("dst_port", 0),
            username=sess["user"], password=sess["pass"]
        ))
        logger.info(f"Telnet credential captured: {sess['user']}:{sess['pass']}")


def _strip_telnet_negotiation(data: bytes) -> bytes:
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 255:
            if i + 1 < len(data):
                cmd = data[i + 1]
                if cmd in (251, 252, 253, 254):
                    i += 3
                    continue
                elif cmd == 250:
                    i += 2
                    while i < len(data) and data[i] != 240:
                        i += 1
                    i += 1
                    continue
                elif cmd == 240:
                    i += 2
                    continue
                else:
                    i += 2
                    continue
            else:
                i += 1
                continue
        result.append(data[i])
        i += 1
    return bytes(result)
