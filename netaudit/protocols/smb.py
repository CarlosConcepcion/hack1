from __future__ import annotations
import struct
import logging
from typing import Optional

from netaudit.models import CaptureResults, SMBInfo

logger = logging.getLogger("netaudit.smb")

SMB1_COMMANDS = {
    0x00: "SMB_COM_CREATE_DIRECTORY",
    0x01: "SMB_COM_DELETE_DIRECTORY",
    0x02: "SMB_COM_OPEN",
    0x03: "SMB_COM_CREATE",
    0x04: "SMB_COM_CLOSE",
    0x05: "SMB_COM_FLUSH",
    0x06: "SMB_COM_DELETE",
    0x07: "SMB_COM_RENAME",
    0x08: "SMB_COM_QUERY_INFORMATION",
    0x09: "SMB_COM_SET_INFORMATION",
    0x0a: "SMB_COM_READ",
    0x0b: "SMB_COM_WRITE",
    0x0d: "SMB_COM_LOCK_BYTE_RANGE",
    0x0e: "SMB_COM_UNLOCK_BYTE_RANGE",
    0x10: "SMB_COM_CREATE_TEMPORARY",
    0x11: "SMB_COM_CREATE_NEW",
    0x12: "SMB_COM_CHECK_DIRECTORY",
    0x13: "SMB_COM_PROCESS_EXIT",
    0x14: "SMB_COM_SEEK",
    0x15: "SMB_COM_LSEEK",
    0x16: "SMB_COM_FIND_CLOSE2",
    0x20: "SMB_COM_WRITE_AND_CLOSE",
    0x24: "SMB_COM_READ_ANDX",
    0x25: "SMB_COM_READ_RAW",
    0x2a: "SMB_COM_READ_MPX",
    0x2b: "SMB_COM_READ_MPX_SECONDARY",
    0x2c: "SMB_COM_WRITE_MPX",
    0x2d: "SMB_COM_WRITE_MPX_SECONDARY",
    0x2e: "SMB_COM_WRITE_RAW",
    0x2f: "SMB_COM_WRITE_COMPLETE",
    0x32: "SMB_COM_TRANSACTION",
    0x33: "SMB_COM_TRANSACTION_SECONDARY",
    0x34: "SMB_COM_NT_TRANSACT",
    0x35: "SMB_COM_NT_TRANSACT_SECONDARY",
    0x36: "SMB_COM_OPEN_PRINT_FILE",
    0x50: "SMB_COM_WRITE_AND_UNLOCK",
    0x51: "SMB_COM_READ_ANDX",
    0x52: "SMB_COM_READ_ANDX",
    0x53: "SMB_COM_READ_ANDX",
    0x60: "SMB_COM_QUERY_INFORMATION_DISK",
    0x61: "SMB_COM_SEARCH",
    0x62: "SMB_COM_FIND",
    0x63: "SMB_COM_FIND_UNIQUE",
    0x64: "SMB_COM_FIND_CLOSE",
    0x65: "SMB_COM_NT_TRANSACT",
    0x66: "SMB_COM_NT_TRANSACT",
    0x67: "SMB_COM_NT_TRANSACT",
    0x68: "SMB_COM_NT_CREATE_ANDX",
    0x69: "SMB_COM_NT_CANCEL",
    0x6a: "SMB_COM_NT_RENAME",
    0x70: "SMB_COM_SESSION_SETUP_ANDX",
    0x71: "SMB_COM_SESSION_SETUP_ANDX",
    0x72: "SMB_COM_SESSION_SETUP_ANDX",
    0x73: "SMB_COM_LOGOFF_ANDX",
    0x74: "SMB_COM_TREE_CONNECT_ANDX",
    0x75: "SMB_COM_TREE_DISCONNECT",
    0x76: "SMB_COM_NEGOTIATE",
    0x77: "SMB_COM_READ_ANDX",
    0x78: "SMB_COM_WRITE_ANDX",
    0x79: "SMB_COM_CLOSE",
    0x7a: "SMB_COM_TRANSACTION",
    0x7b: "SMB_COM_TRANSACTION",
    0x7c: "SMB_COM_TRANSACTION",
    0x7d: "SMB_COM_ECHO",
    0x7e: "SMB_COM_WRITE_AND_CLOSE",
    0xff: "SMB_COM_INVALID",
}

SMB2_COMMANDS = {
    0x0000: "SMB2 NEGOTIATE",
    0x0001: "SMB2 SESSION_SETUP",
    0x0002: "SMB2 LOGOFF",
    0x0003: "SMB2 TREE_CONNECT",
    0x0004: "SMB2 TREE_DISCONNECT",
    0x0005: "SMB2 CREATE",
    0x0006: "SMB2 CLOSE",
    0x0007: "SMB2 FLUSH",
    0x0008: "SMB2 READ",
    0x0009: "SMB2 WRITE",
    0x000a: "SMB2 LOCK",
    0x000b: "SMB2 IOCTL",
    0x000c: "SMB2 CANCEL",
    0x000d: "SMB2 ECHO",
    0x000e: "SMB2 QUERY_DIRECTORY",
    0x000f: "SMB2 CHANGE_NOTIFY",
    0x0010: "SMB2 QUERY_INFO",
    0x0011: "SMB2 SET_INFO",
    0x0012: "SMB2 OPLOCK_BREAK",
}

SMB2_DIALECTS = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

_smb_sessions: dict[str, dict] = {}


def parse_smb(
    results: CaptureResults, src_ip: str, src_port: int,
    dst_ip: str, dst_port: int, payload: bytes, timestamp: float,
    is_response: bool
):
    if not payload or len(payload) < 8:
        return

    session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    rev_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    sess = _smb_sessions.get(session_key)
    if sess is None:
        sess = _smb_sessions.get(rev_key)
        if sess is None:
            sess = {"dialect": "", "user": "", "domain": "", "share": ""}
            _smb_sessions[session_key] = sess

    try:
        offset = 0
        if len(payload) >= 4 and payload[0] == 0x00:
            nbss_len = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]
            offset = 4
            if nbss_len > len(payload) - 4:
                return
            payload = payload[4:4 + nbss_len]

        if len(payload) < 4:
            return

        if payload[0:4] == b"\xffSMB":
            _parse_smb1(results, payload, src_ip, src_port, dst_ip, dst_port, sess, timestamp, is_response)
        elif payload[0:4] == b"\xfeSMB":
            _parse_smb2(results, payload, src_ip, src_port, dst_ip, dst_port, sess, timestamp, is_response)
    except Exception as e:
        logger.debug(f"SMB parse error: {e}")


def _parse_smb1(results, payload, src_ip, src_port, dst_ip, dst_port, sess, timestamp, is_response):
    if len(payload) < 35:
        return
    try:
        cmd = payload[4]
        cmd_name = SMB1_COMMANDS.get(cmd, f"SMB1_CMD_{cmd:02x}")

        if cmd == 0x72:
            if len(payload) > 36:
                user_bytes = payload[36:36 + 20]
                user = user_bytes.split(b"\x00")[0].decode("utf-8", errors="replace").strip()
                if user:
                    sess["user"] = user

        results.add_smb_info(SMBInfo(
            timestamp=timestamp,
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port,
            smb_version="SMB 1.0",
            command=cmd_name,
            username=sess.get("user", ""),
            domain=sess.get("domain", ""),
        ))

        ntlm_start = payload.find(b"NTLMSSP")
        if ntlm_start >= 0:
            sess["ntlmssp_found"] = True
            ntlm_data = payload[ntlm_start:]
            from netaudit.protocols.ntlm import parse_ntlm_auth_header
            from netaudit.config import NetAuditConfig
            b64 = __import__("base64").b64encode(ntlm_data).decode()
            parse_ntlm_auth_header(results, NetAuditConfig(), src_ip, src_port, dst_ip, dst_port, "NTLM " + b64, timestamp)

    except Exception as e:
        logger.debug(f"SMB1 parse: {e}")


def _parse_smb2(results, payload, src_ip, src_port, dst_ip, dst_port, sess, timestamp, is_response):
    if len(payload) < 64:
        return
    try:
        smb2_header_len = 64
        struct_size = struct.unpack("<H", payload[4:6])[0]
        if struct_size != 64:
            smb2_header_len = struct_size

        nt_status = struct.unpack("<I", payload[8:12])[0] if len(payload) > 12 else 0
        command = struct.unpack("<H", payload[12:14])[0] if len(payload) > 14 else 0
        credits = struct.unpack("<H", payload[14:16])[0]
        flags = struct.unpack("<I", payload[16:20])[0] if len(payload) > 20 else 0
        message_id = struct.unpack("<Q", payload[20:28])[0]
        tree_id = struct.unpack("<I", payload[28:32])[0] if len(payload) > 32 else 0
        session_id = struct.unpack("<Q", payload[40:48])[0] if len(payload) > 48 else 0

        cmd_name = SMB2_COMMANDS.get(command, f"SMB2_CMD_{command:04x}")

        if command == 0x0000:
            body_start = smb2_header_len
            if len(payload) >= body_start + 38:
                dialect_count = struct.unpack("<H", payload[body_start + 2:body_start + 4])[0]
                for i in range(min(dialect_count, 10)):
                    off = body_start + 36 + (i * 2)
                    if off + 2 <= len(payload):
                        dialect = struct.unpack("<H", payload[off:off + 2])[0]
                        if dialect in SMB2_DIALECTS:
                            sess["dialect"] = SMB2_DIALECTS[dialect]

        if command == 0x0001:
            smb_ver = sess.get("dialect", "SMB 2.x")
            if len(payload) >= 72:
                sec_buf_off = struct.unpack("<H", payload[68:70])[0]
                sec_buf_len = struct.unpack("<H", payload[70:72])[0]
                if is_response:
                    if session_id:
                        sess["session_id"] = session_id

                ntlm_start = payload.find(b"NTLMSSP")
                if ntlm_start >= 0 and ntlm_start > smb2_header_len:
                    ntlm_data = payload[ntlm_start:]
                    from netaudit.protocols.ntlm import parse_ntlm_auth_header
                    from netaudit.config import NetAuditConfig
                    b64 = __import__("base64").b64encode(ntlm_data).decode()
                    parse_ntlm_auth_header(results, NetAuditConfig(), src_ip, src_port, dst_ip, dst_port, "NTLM " + b64, timestamp)
                    sess["ntlmssp_found"] = True

                    for c in results.ntlm_credentials:
                        if c.src_ip == src_ip:
                            sess["user"] = c.username
                            sess["domain"] = c.domain

        if command == 0x0003:
            if len(payload) >= 76:
                share_ofs = struct.unpack("<H", payload[70:72])[0]
                share_len = struct.unpack("<H", payload[72:74])[0]
                if share_ofs + share_len <= len(payload):
                    share_raw = payload[share_ofs:share_ofs + share_len]
                    share = share_raw.decode("utf-16-le", errors="replace").rstrip("\x00").strip()
                    if share:
                        sess["share"] = share

        smb_ver = sess.get("dialect", "SMB 2.x")
        results.add_smb_info(SMBInfo(
            timestamp=timestamp,
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port,
            smb_version=smb_ver,
            command=cmd_name,
            username=sess.get("user", ""),
            domain=sess.get("domain", ""),
            share=sess.get("share", ""),
            ntlmssp_detected=sess.get("ntlmssp_found", False),
        ))

    except Exception as e:
        logger.debug(f"SMB2 parse: {e}")
