from __future__ import annotations
import logging
from typing import Optional

from netaudit.models import CaptureResults, KerberosAuth

logger = logging.getLogger("netaudit.kerberos")

KERBEROS_MSG_TYPES = {
    10: "AS-REQ",
    11: "AS-REP",
    12: "TGS-REQ",
    13: "TGS-REP",
    14: "AP-REQ",
    15: "AP-REP",
    16: "KRB-ERROR",
}

ENCTYPES = {
    3: "DES-CBC-MD5",
    8: "DES3-CBC-SHA1",
    16: "AES128-CTS-HMAC-SHA1-96",
    17: "AES256-CTS-HMAC-SHA1-96",
    18: "AES128-CTS-HMAC-SHA256-128",
    19: "AES256-CTS-HMAC-SHA384-192",
    23: "RC4-HMAC",
    24: "RC4-HMAC-EXP",
}


def parse_kerberos(
    results: CaptureResults, src_ip: str, src_port: int,
    dst_ip: str, dst_port: int, payload: bytes, timestamp: float
):
    if not payload or len(payload) < 20:
        return

    try:
        offset = 0
        if payload[0] == 0x00 and len(payload) >= 4:
            pdu_len = struct_pdu_len(payload)
            if pdu_len > 0:
                offset = 4
                if pdu_len + 4 <= len(payload):
                    payload = payload[offset:offset + pdu_len]
                else:
                    return

        if not payload or payload[0] != 0x60:
            return

        app_tag, pos_end = read_asn1_tag(payload, 0)
        if app_tag != 0x60:
            return

        tag_data = payload[2:pos_end]
        if not tag_data:
            return

        pos = 0
        _, pos = read_asn1_tag(tag_data, 0)
        tag, pos = read_asn1_tag(tag_data, pos)
        if tag == 0x30:
            seq_inner, _ = read_asn1_tag(tag_data, pos - 1) if pos > 0 else (b"", 0)
            pass

        pos = asn1_find_tag(tag_data, 0, 1)
        if pos is not None:
            msg_type = read_asn1_int(tag_data, pos + 2) if pos + 2 < len(tag_data) else -1

        msg_name = KERBEROS_MSG_TYPES.get(msg_type, f"KRB-{msg_type}")

        if msg_type in (10, 12):
            pass

        if msg_type in (10, 11, 12, 13):
            realm = ""
            client_name = ""
            service_name = ""
            realm_pos = asn1_find_tag(tag_data, 0, 2)
            if realm_pos is not None:
                realm = read_asn1_string(tag_data, realm_pos + 2) if realm_pos + 2 < len(tag_data) else ""

            cname_pos = asn1_find_tag(tag_data, 0, 3)
            if cname_pos is not None:
                cname_seq, _ = read_asn1_tag(tag_data, cname_pos + 2) if cname_pos + 2 < len(tag_data) else (b"", 0)
                name_string_pos = asn1_find_tag(tag_data, cname_pos + 2, 5)
                if name_string_pos is not None:
                    client_name = _extract_kerberos_strings(tag_data, name_string_pos)

            if msg_type in (11, 13):
                ticket_pos = asn1_find_tag(tag_data, 0, 4)
                if ticket_pos is not None:
                    sname_pos = tag_data.find(b"\x30\x1a\xa0\x03\x02\x01\x02")
                    if sname_pos == -1:
                        sname_pos = asn1_find_tag(tag_data, ticket_pos + 2, 3)
                    if sname_pos is None:
                        sname_pos = tag_data.find(b"\xa0\x07\x30\x05")
                    if sname_pos is not None and sname_pos + 1 < len(tag_data):
                        try:
                            ticket_realm_pos = asn1_find_tag(tag_data, ticket_pos + 2, 1)
                            if ticket_realm_pos is not None:
                                service_realm = read_asn1_string(tag_data, ticket_realm_pos + 2)
                                if service_realm and not realm:
                                    realm = service_realm
                        except Exception:
                            pass

            if msg_type in (12, 13):
                sname_pos = asn1_find_tag(tag_data, 0, 4)
                if sname_pos is not None:
                    sname_data = tag_data[sname_pos:sname_pos + 200]
                    name_seq = sname_data.find(b"\x30\x05\xa0\x03\xa1")
                    if name_seq == -1:
                        name_seq = sname_data.find(b"\xa0\x07\x30\x05")
                    try:
                        sp = asn1_find_tag(tag_data, sname_pos + 2, 3)
                        if sp is not None:
                            service_name = _extract_kerberos_strings(tag_data, sp)
                    except Exception:
                        pass

            enc = ""
            etype_pos = asn1_find_tag(tag_data, 0, 5) if msg_type in (11, 13) else None
            if etype_pos is None and msg_type in (10, 12):
                etype_pos = asn1_find_tag(tag_data, 0, 4) if msg_type == 10 else asn1_find_tag(tag_data, 0, 5)
            if etype_pos is not None:
                try:
                    enc_val = read_asn1_int(tag_data, etype_pos + 2)
                    enc = ENCTYPES.get(enc_val, f"etype={enc_val}")
                except Exception:
                    pass

        name_str = client_name or (service_name if msg_type in (11, 13) else "")
        results.add_kerberos_auth(KerberosAuth(
            timestamp=timestamp,
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port,
            msg_type=msg_name,
            realm=realm,
            client_name=client_name,
            service_name=service_name,
            ticket_encryption=enc,
        ))

    except Exception as e:
        logger.debug(f"Kerberos parse error: {e}")


def _extract_kerberos_strings(data: bytes, start_pos: int) -> str:
    result = []
    pos = start_pos
    max_len = min(len(data), start_pos + 500)
    while pos < max_len:
        while pos < max_len and data[pos] in (0x30, 0x31, 0xa0, 0xa1):
            tag = data[pos]
            if pos + 2 > max_len:
                break
            if data[pos + 1] < 0x80:
                pos += 2 + data[pos + 1]
            elif pos + 3 < max_len:
                pos += 3 + data[pos + 2]
            else:
                pos += 1
                break
        if pos < max_len and data[pos] == 0x1b:
            try:
                s = read_asn1_string(data, pos + 2)
                if s:
                    result.append(s)
            except Exception:
                pass
            if pos + 2 < max_len and data[pos + 1] < 0x80:
                pos += 2 + data[pos + 1]
            elif pos + 3 < max_len:
                pos += 3 + data[pos + 2]
            else:
                break
        elif pos < max_len and data[pos] == 0x1a:
            try:
                s = read_asn1_string(data, pos + 2)
                if s:
                    result.append(s)
            except Exception:
                pass
            if pos + 2 < max_len and data[pos + 1] < 0x80:
                pos += 2 + data[pos + 1]
            elif pos + 3 < max_len:
                pos += 3 + data[pos + 2]
            else:
                break
        else:
            if pos < max_len and data[pos] == 0x30:
                pos += 1
            elif pos < max_len and data[pos] == 0x00:
                pos += 1
            else:
                pos += 1
            if pos > start_pos + 300:
                break
    return "/".join(result) if result else ""


def struct_pdu_len(data: bytes) -> int:
    if len(data) < 4:
        return 0
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]


def read_asn1_tag(data: bytes, offset: int) -> tuple:
    if offset >= len(data):
        return (0, offset)
    tag = data[offset]
    if offset + 1 >= len(data):
        return (tag, offset + 1)
    length = data[offset + 1]
    if length & 0x80:
        num_bytes = length & 0x7f
        length = 0
        for i in range(num_bytes):
            if offset + 2 + i < len(data):
                length = (length << 8) | data[offset + 2 + i]
        value_start = offset + 2 + num_bytes
    else:
        value_start = offset + 2
    value_end = value_start + length
    if value_end > len(data):
        value_end = len(data)
    return (tag, value_end)


def asn1_find_tag(data: bytes, start: int, target_tag: int) -> Optional[int]:
    pos = start
    max_search = min(len(data), start + 500)
    while pos < max_search:
        if data[pos] == target_tag:
            return pos
        if data[pos] in (0x30, 0x31, 0xa0, 0xa1):
            _, new_pos = read_asn1_tag(data, pos)
            if new_pos > pos:
                pos = new_pos
                continue
        pos += 1
    return None


def read_asn1_int(data: bytes, offset: int) -> int:
    if offset >= len(data) - 1:
        return 0
    length = data[offset]
    if length & 0x80:
        num_bytes = length & 0x7f
        length = 0
        for i in range(num_bytes):
            if offset + 1 + i < len(data):
                length = (length << 8) | data[offset + 1 + i]
        return 0
    raw = data[offset + 1:offset + 1 + length]
    return int.from_bytes(raw, "big", signed=True) if raw else 0


def read_asn1_string(data: bytes, offset: int) -> str:
    if offset >= len(data) - 1:
        return ""
    length = data[offset]
    if length & 0x80:
        num_bytes = length & 0x7f
        length = 0
        for i in range(num_bytes):
            if offset + 1 + i < len(data):
                length = (length << 8) | data[offset + 1 + i]
        if length == 0:
            return ""
        value_start = offset + 1 + num_bytes
    else:
        value_start = offset + 1
    raw = data[value_start:value_start + length]
    try:
        return raw.decode("utf-8", errors="replace").rstrip("\x00")
    except Exception:
        return ""
