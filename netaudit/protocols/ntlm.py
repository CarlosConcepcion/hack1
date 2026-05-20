from __future__ import annotations
import base64
import binascii
import logging
import struct
from typing import Optional

from netaudit.models import CaptureResults, NTLMCredential

logger = logging.getLogger("netaudit.ntlm")


def parse_ntlm_auth_header(
    results: CaptureResults, config,
    src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    header_value: str, timestamp: float
):
    if not header_value.upper().startswith("NTLM "):
        return

    try:
        raw = base64.b64decode(header_value[5:].strip())
    except Exception:
        return

    if len(raw) < 12:
        return

    if raw[:7] != b"NTLMSSP":
        return

    msg_type = struct.unpack("<I", raw[8:12])[0]

    if msg_type == 1:
        _parse_type1(results, src_ip, src_port, dst_ip, dst_port, raw, timestamp)
    elif msg_type == 2:
        _parse_type2(results, src_ip, src_port, dst_ip, dst_port, raw, timestamp)
    elif msg_type == 3:
        _parse_type3(results, src_ip, src_port, dst_ip, dst_port, raw, timestamp)


def _parse_type1(
    results: CaptureResults, src_ip, src_port, dst_ip, dst_port,
    raw: bytes, timestamp: float
):
    try:
        flags = struct.unpack("<I", raw[12:16])[0] if len(raw) > 16 else 0
        domain_info = _read_ntlm_field(raw, 16) if len(raw) > 20 else ("", None, None)
        workstation_info = _read_ntlm_field(raw, 24) if len(raw) > 28 else ("", None, None)

        domain = domain_info[0] if domain_info else ""
        workstation = workstation_info[0] if workstation_info else ""

        results.add_ntlm_credential(NTLMCredential(
            timestamp=timestamp,
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port,
            ntlm_type=1,
            domain=domain,
            workstation=workstation,
            raw_data=binascii.hexlify(raw).decode("ascii", errors="replace")
        ))
    except Exception as e:
        logger.debug(f"NTLM Type1 parse error: {e}")


def _parse_type2(
    results: CaptureResults, src_ip, src_port, dst_ip, dst_port,
    raw: bytes, timestamp: float
):
    try:
        if len(raw) < 40:
            return
        target_info = _read_ntlm_field(raw, 12)
        flags = struct.unpack("<I", raw[20:24])[0] if len(raw) > 24 else 0
        challenge = struct.unpack("<Q", raw[24:32])[0] if len(raw) > 32 else 0

        target_name = target_info[0] if target_info else ""
        challenge_hex = f"{challenge:016x}"

        results.add_ntlm_credential(NTLMCredential(
            timestamp=timestamp,
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port,
            ntlm_type=2,
            domain=target_name,
            challenge=challenge_hex,
            raw_data=binascii.hexlify(raw).decode("ascii", errors="replace")
        ))
    except Exception as e:
        logger.debug(f"NTLM Type2 parse error: {e}")


def _parse_type3(
    results: CaptureResults, src_ip, src_port, dst_ip, dst_port,
    raw: bytes, timestamp: float
):
    try:
        if len(raw) < 52:
            return
        lm_info = _read_ntlm_field(raw, 12)
        nt_info = _read_ntlm_field(raw, 20)
        domain_info = _read_ntlm_field(raw, 28)
        user_info = _read_ntlm_field(raw, 36)
        workstation_info = _read_ntlm_field(raw, 44)

        username = user_info[0] if user_info else ""
        domain = domain_info[0] if domain_info else ""
        workstation = workstation_info[0] if workstation_info else ""

        lm_response = ""
        if lm_info and len(lm_info) > 1 and lm_info[1] is not None and lm_info[2] is not None:
            start = lm_info[2]
            length = lm_info[1]
            if start + length <= len(raw):
                lm_response = binascii.hexlify(raw[start:start+length]).decode("ascii", errors="replace")

        nt_response = ""
        if nt_info and len(nt_info) > 1 and nt_info[1] is not None and nt_info[2] is not None:
            start = nt_info[2]
            length = nt_info[1]
            if start + length <= len(raw):
                nt_response = binascii.hexlify(raw[start:start+length]).decode("ascii", errors="replace")

        os_version = ""
        if len(raw) >= 72:
            try:
                os_ver_offset = 64
                major = raw[os_ver_offset]
                minor = raw[os_ver_offset + 1]
                build = struct.unpack("<H", raw[os_ver_offset + 2:os_ver_offset + 4])[0]
                if major > 0 or build > 0:
                    os_version = f"Windows {major}.{minor}.{build}"
            except Exception:
                pass

        session_key_info = _read_ntlm_field(raw, 52) if len(raw) > 56 else None
        session_key = ""
        if session_key_info and len(session_key_info) > 1 and session_key_info[1] is not None and session_key_info[2] is not None:
            start = session_key_info[2]
            length = session_key_info[1]
            if start + length <= len(raw):
                session_key = binascii.hexlify(raw[start:start+length]).decode("ascii", errors="replace")

        cred = NTLMCredential(
            timestamp=timestamp,
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port,
            username=username,
            domain=domain,
            workstation=workstation,
            ntlm_type=3,
            nt_response=nt_response,
            lm_response=lm_response,
            session_key=session_key,
            os_version=os_version,
            raw_data=binascii.hexlify(raw).decode("ascii", errors="replace")
        )
        results.add_ntlm_credential(cred)

        if username:
            logger.info(f"NTLMv2 credential captured: {domain}\\{username} ({workstation})")
    except Exception as e:
        logger.debug(f"NTLM Type3 parse error: {e}")


def _read_ntlm_field(data: bytes, offset: int) -> tuple:
    if offset + 8 > len(data):
        return ("", None, None)
    length = struct.unpack("<H", data[offset:offset+2])[0]
    max_len = struct.unpack("<H", data[offset+2:offset+4])[0]
    data_offset = struct.unpack("<I", data[offset+4:offset+8])[0]

    if data_offset + length > len(data) or length == 0:
        return ("", length, data_offset)

    raw_field = data[data_offset:data_offset+length]

    text = _decode_ntlm_string(raw_field)
    return (text, length, data_offset)


def _decode_ntlm_string(raw: bytes) -> str:
    if not raw:
        return ""

    null_even = all(i % 2 == 1 and raw[i] == 0 for i in range(1, len(raw), 2))
    has_null_odd = any(i % 2 == 1 and raw[i] == 0 for i in range(1, min(len(raw), 32), 2))

    if has_null_odd:
        try:
            return raw.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            pass

    try:
        return raw.decode("ascii", errors="replace").rstrip("\x00").strip()
    except Exception:
        try:
            return raw.decode("utf-8", errors="replace").rstrip("\x00").strip()
        except Exception:
            return raw.hex()
