from __future__ import annotations
import struct
import logging
from typing import Optional

from netaudit.models import CaptureResults, TLSInfo

logger = logging.getLogger("netaudit.tls")

TLS_VERSIONS = {
    0x0200: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

HANDSHAKE_TYPES = {
    1: "ClientHello",
    2: "ServerHello",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
}

CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
}

_tls_sessions: dict[str, dict] = {}


def parse_tls(
    results: CaptureResults, src_ip: str, src_port: int,
    dst_ip: str, dst_port: int, payload: bytes, timestamp: float
):
    if not payload or len(payload) < 5:
        return

    session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    sess = _tls_sessions.get(session_key)
    if sess is None:
        sess = _tls_sessions.get(rev_key)
        if sess is None:
            sess = {"sni": "", "tls_version": "", "subject": "", "issuer": ""}
            _tls_sessions[session_key] = sess

    try:
        offset = 0
        while offset + 5 <= len(payload):
            content_type = payload[offset]
            if content_type not in CONTENT_TYPES:
                if content_type == 0x16:
                    pass
                elif content_type == 0x03 and offset + 1 < len(payload) and (payload[offset + 1] & 0xf0) == 0x30:
                    pass
                else:
                    break

            if content_type == 0x16:
                _parse_tls_handshake(results, payload, offset, src_ip, src_port, dst_ip, dst_port, sess, timestamp)
                tls_len = struct.unpack(">H", payload[offset + 3:offset + 5])[0]
                offset += 5 + tls_len
            elif content_type == 0x03:
                version = struct.unpack(">H", payload[offset:offset + 2])[0]
                tls_ver = TLS_VERSIONS.get(version, f"TLS 0x{version:04x}")
                if not sess["tls_version"]:
                    sess["tls_version"] = tls_ver
                tls_len = struct.unpack(">H", payload[offset + 3:offset + 5])[0] if offset + 5 <= len(payload) else 0
                if tls_len > 0:
                    offset += 5 + tls_len
                else:
                    break
            else:
                tls_len = struct.unpack(">H", payload[offset + 3:offset + 5])[0] if offset + 5 <= len(payload) else 0
                if tls_len > 0:
                    offset += 5 + tls_len
                else:
                    break

    except Exception as e:
        logger.debug(f"TLS parse error: {e}")


def _parse_tls_handshake(results, payload, base, src_ip, src_port, dst_ip, dst_port, sess, timestamp):
    if base + 6 > len(payload):
        return
    hs_type = payload[base + 5]
    hs_len = struct.unpack(">I", b"\x00" + payload[base + 6:base + 9])[0]
    hs_start = base + 9

    if hs_type not in HANDSHAKE_TYPES:
        return
    hs_name = HANDSHAKE_TYPES[hs_type]

    tls_ver = TLS_VERSIONS.get(struct.unpack(">H", payload[base + 1:base + 3])[0], "TLS")
    if not sess["tls_version"]:
        sess["tls_version"] = tls_ver

    if hs_type == 1:
        _parse_client_hello(results, payload, hs_start, hs_len, src_ip, src_port, dst_ip, dst_port, tls_ver, sess, timestamp)
    elif hs_type == 2:
        _parse_server_hello(results, payload, hs_start, hs_len, src_ip, src_port, dst_ip, dst_port, tls_ver, sess, timestamp)
    elif hs_type == 11:
        _parse_certificate(results, payload, hs_start, hs_len, src_ip, src_port, dst_ip, dst_port, tls_ver, sess, timestamp)


def _parse_client_hello(results, payload, hs_start, hs_len, src_ip, src_port, dst_ip, dst_port, tls_ver, sess, timestamp):
    try:
        pos = hs_start + 2 + 32
        if pos + 1 > len(payload):
            return
        session_len = payload[pos]
        pos += 1 + session_len
        if pos + 2 > len(payload):
            return
        cipher_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_len
        if pos + 1 > len(payload):
            return
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return
        ext_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        sni = _extract_sni(payload, pos, ext_len)
        if sni:
            sess["sni"] = sni
            _emit_tls_info(results, src_ip, src_port, dst_ip, dst_port, "ClientHello", tls_ver, sess, timestamp)
    except Exception as e:
        logger.debug(f"ClientHello parse: {e}")

    except Exception as e:
        logger.debug(f"ClientHello parse: {e}")


def _parse_server_hello(results, payload, hs_start, hs_len, src_ip, src_port, dst_ip, dst_port, tls_ver, sess, timestamp):
    try:
        cipher_suite = ""
        if hs_start + 38 < len(payload):
            cs_bytes = payload[hs_start + 36:hs_start + 38]
            cipher_suite = f"0x{cs_bytes[0]:02x}{cs_bytes[1]:02x}"

        _emit_tls_info(results, src_ip, src_port, dst_ip, dst_port, "ServerHello", tls_ver, sess, timestamp)
    except Exception:
        pass


def _parse_certificate(results, payload, hs_start, hs_len, src_ip, src_port, dst_ip, dst_port, tls_ver, sess, timestamp):
    try:
        if hs_start + 3 > len(payload):
            return
        certs_len = (payload[hs_start] << 16) | (payload[hs_start + 1] << 8) | payload[hs_start + 2]
        pos = hs_start + 3

        while pos + 3 <= len(payload) and pos < hs_start + 3 + certs_len:
            cert_len = (payload[pos] << 16) | (payload[pos + 1] << 8) | payload[pos + 2]
            pos += 3
            if pos + cert_len > len(payload):
                break
            cert_data = payload[pos:pos + cert_len]
            _extract_cert_info(cert_data, sess)
            pos += cert_len
            break

        _emit_tls_info(results, src_ip, src_port, dst_ip, dst_port, "Certificate", tls_ver, sess, timestamp)
    except Exception as e:
        logger.debug(f"Certificate parse: {e}")


def _extract_sni(payload: bytes, pos: int, ext_len: int) -> str:
    end = pos + ext_len
    while pos + 4 <= end:
        ext_type = struct.unpack(">H", payload[pos:pos + 2])[0]
        ext_data_len = struct.unpack(">H", payload[pos + 2:pos + 4])[0]
        if pos + 4 + ext_data_len > end:
            break
        if ext_type == 0:
            if ext_data_len >= 7:
                name_type = payload[pos + 6]
                if name_type == 0:
                    name_len = struct.unpack(">H", payload[pos + 7:pos + 9])[0]
                    if name_len > 0 and pos + 9 + name_len <= end:
                        sni = payload[pos + 9:pos + 9 + name_len]
                        try:
                            return sni.decode("utf-8", errors="replace")
                        except Exception:
                            return ""
        pos += 4 + ext_data_len
    return ""


def _extract_cert_info(cert_data: bytes, sess: dict):
    try:
        pos = 0
        for _ in range(20):
            if pos + 4 > len(cert_data):
                break
            if cert_data[pos:pos + 2] == b"\x55\x1d":
                subj = _extract_cn_from_rdn(cert_data, pos)
                if subj and not sess.get("subject"):
                    sess["subject"] = subj
            if cert_data[pos:pos + 2] == b"\x30\x20" and pos + 5 < len(cert_data):
                if cert_data[pos + 3:pos + 5] == b"\x06\x03":
                    pos += 1
                    continue
            pos += 1

        cn = _extract_cn_from_rdn(cert_data, 0)
        if cn:
            sess["subject"] = cn

        issuer = _extract_issuer(cert_data)
        if issuer:
            sess["issuer"] = issuer

    except Exception:
        pass


def _extract_cn_from_rdn(data: bytes, start: int) -> str:
    patterns = [b"\x06\x03\x55\x04\x03\x0c", b"\x06\x03\x55\x04\x03\x13",
                b"\x06\x03\x55\x04\x03\x1e", b"CN="]
    for i in range(len(data) - 10):
        for p in patterns:
            if data[i:i + len(p)] == p:
                str_len = data[i + len(p)]
                if i + len(p) + str_len <= len(data):
                    try:
                        return data[i + len(p):i + len(p) + str_len].decode("utf-8", errors="replace")
                    except Exception:
                        pass
    return ""


def _extract_issuer(data: bytes) -> str:
    patterns = [b"\x06\x03\x55\x04\x0a\x0c", b"\x06\x03\x55\x04\x0a\x13",
                b"\x06\x03\x55\x04\x0a\x1e"]
    for i in range(len(data) - 10):
        for p in patterns:
            if data[i:i + len(p)] == p:
                str_len = data[i + len(p)]
                if i + len(p) + str_len <= len(data):
                    try:
                        return data[i + len(p):i + len(p) + str_len].decode("utf-8", errors="replace")
                    except Exception:
                        pass
    return ""


def _emit_tls_info(results, src_ip, src_port, dst_ip, dst_port, hs_type, tls_ver, sess, timestamp):
    results.add_tls_info(TLSInfo(
        timestamp=timestamp,
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        handshake_type=hs_type,
        tls_version=tls_ver,
        sni=sess.get("sni", ""),
        subject=sess.get("subject", ""),
        issuer=sess.get("issuer", ""),
    ))
