from __future__ import annotations
import base64
import logging
from urllib.parse import unquote_plus

from netaudit.config import NetAuditConfig
from netaudit.models import CaptureResults, HTTPCredential, CapturedURL, HTTPRequest, HTTPCookie
from netaudit.protocols.ntlm import parse_ntlm_auth_header

logger = logging.getLogger("netaudit.http")


def parse_http(
    results: CaptureResults, config: NetAuditConfig,
    src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    payload: bytes, timestamp: float, is_request: bool
):
    if not payload:
        return

    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return

    if is_request:
        _parse_http_request(results, config, src_ip, src_port, dst_ip, dst_port, text, payload, timestamp)
    else:
        _parse_http_response(results, config, src_ip, src_port, dst_ip, dst_port, text, payload, timestamp)


def _parse_http_request(
    results: CaptureResults, config: NetAuditConfig,
    src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    text: str, raw: bytes, timestamp: float
):
    lines = text.split("\r\n")
    if not lines:
        return

    first_line = lines[0].strip()
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return

    method = parts[0].upper()
    path = parts[1]

    valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
    if method not in valid_methods:
        return

    headers = {}
    host = ""
    body_start = text.find("\r\n\r\n")
    if body_start != -1:
        header_lines = text[:body_start].split("\r\n")[1:]
        body = text[body_start + 4:]
    else:
        header_lines = lines[1:]
        body = ""

    for hdr in header_lines:
        hdr = hdr.strip()
        if ":" in hdr:
            key, value = hdr.split(":", 1)
            headers[key.strip().lower()] = value.strip()
            if key.strip().lower() == "host":
                host = value.strip()

    if host and not host.startswith("http"):
        full_url = f"http://{host}{path}"
    elif path.startswith("http"):
        full_url = path
    else:
        full_url = path

    user_agent = headers.get("user-agent", "")

    results.add_http_request(HTTPRequest(
        timestamp=timestamp,
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        method=method, host=host, path=path,
        user_agent=user_agent,
        headers=headers, body=body.encode("utf-8", errors="replace")
    ))

    results.add_url(CapturedURL(
        timestamp=timestamp,
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        method=method, host=host, path=path,
        full_url=full_url, user_agent=user_agent
    ))

    _check_http_auth(results, config, src_ip, src_port, dst_ip, dst_port, headers, full_url, method, timestamp)
    _check_post_creds(results, config, src_ip, src_port, dst_ip, dst_port, body, full_url, timestamp)
    _extract_cookies_from_request(results, config, src_ip, dst_ip, host, headers, timestamp)
    _check_ntlm_request(results, config, src_ip, src_port, dst_ip, dst_port, headers, timestamp)


def _parse_http_response(
    results: CaptureResults, config: NetAuditConfig,
    src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    text: str, raw: bytes, timestamp: float
):
    lines = text.split("\r\n")
    if not lines:
        return

    first_line = lines[0].strip()
    if not first_line.startswith("HTTP/"):
        return

    headers = {}
    body_start = text.find("\r\n\r\n")
    if body_start != -1:
        header_lines = text[:body_start].split("\r\n")[1:]
    else:
        header_lines = lines[1:]

    for hdr in header_lines:
        hdr = hdr.strip()
        if ":" in hdr:
            key, value = hdr.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    _extract_cookies_from_response(results, config, src_ip, dst_ip, headers, timestamp)
    _check_ntlm_response(results, config, src_ip, src_port, dst_ip, dst_port, headers, timestamp)


def _check_http_auth(
    results: CaptureResults, config: NetAuditConfig,
    src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    headers: dict, url: str, method: str, timestamp: float
):
    auth_header = headers.get("authorization", "")
    if not auth_header.lower().startswith("basic "):
        return

    try:
        encoded = auth_header[6:].strip()
        decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
        if ":" in decoded:
            username, password = decoded.split(":", 1)
            results.add_http_credential(HTTPCredential(
                timestamp=timestamp,
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                username=username, password=password,
                url=url, method=method, host=headers.get("host", "")
            ))
    except Exception as e:
        logger.debug(f"Failed to decode Basic auth: {e}")


def _check_ntlm_request(
    results: CaptureResults, config: NetAuditConfig,
    src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    headers: dict, timestamp: float
):
    auth = headers.get("authorization", "")
    if auth.upper().startswith("NTLM "):
        parse_ntlm_auth_header(results, config, src_ip, src_port, dst_ip, dst_port, auth, timestamp)


def _check_ntlm_response(
    results: CaptureResults, config: NetAuditConfig,
    src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    headers: dict, timestamp: float
):
    auth = headers.get("www-authenticate", "")
    if auth.upper().startswith("NTLM "):
        parse_ntlm_auth_header(results, config, src_ip, src_port, dst_ip, dst_port, auth, timestamp)


def _check_post_creds(
    results: CaptureResults, config: NetAuditConfig,
    src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    body: str, url: str, timestamp: float
):
    body_lower = body.lower()
    cred_fields = {"user", "username", "login", "email", "pass", "password", "pwd", "passwd"}
    found = {}
    if "&" in body:
        for param in body.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                key_clean = key.strip().lower()
                if key_clean in cred_fields and value.strip():
                    found[key_clean] = unquote_plus(value.strip())

        if "user" in found or "username" in found or "login" in found or "email" in found:
            if "pass" in found or "password" in found or "pwd" in found or "passwd" in found:
                username = found.get("user") or found.get("username") or found.get("login") or found.get("email", "")
                password = found.get("pass") or found.get("password") or found.get("pwd") or found.get("passwd", "")
                results.add_http_credential(HTTPCredential(
                    timestamp=timestamp,
                    src_ip=src_ip, src_port=src_port,
                    dst_ip=dst_ip, dst_port=dst_port,
                    username=username, password=password,
                    url=url, method="POST"
                ))


def _extract_cookies_from_request(
    results: CaptureResults, config: NetAuditConfig,
    src_ip: str, dst_ip: str, host: str,
    headers: dict, timestamp: float
):
    cookie_header = headers.get("cookie", "")
    if not cookie_header:
        return

    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, value = pair.split("=", 1)
            name = name.strip()
            value = value.strip()
            if name and value:
                results.add_cookie(HTTPCookie(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    domain=host,
                    path="",
                    name=name,
                    value=value[:256],
                    source="request"
                ))


def _extract_cookies_from_response(
    results: CaptureResults, config: NetAuditConfig,
    src_ip: str, dst_ip: str,
    headers: dict, timestamp: float
):
    set_cookie = headers.get("set-cookie", "")
    if not set_cookie:
        set_cookie = headers.get("set-cookie2", "")
    if not set_cookie:
        return

    for cookie_part in set_cookie.split(","):
        cookie_part = cookie_part.strip()
        if "=" not in cookie_part:
            continue

        name_value = cookie_part.split(";")[0].strip()
        if "=" not in name_value:
            continue

        name, value = name_value.split("=", 1)
        name = name.strip()
        value = value.strip()

        domain = headers.get("host", dst_ip)
        path = "/"
        secure = False
        http_only = False

        for attr in cookie_part.split(";")[1:]:
            attr = attr.strip().lower()
            if attr == "secure":
                secure = True
            elif attr == "httponly":
                http_only = True
            elif attr.startswith("domain="):
                domain = attr.split("=", 1)[1].strip()
            elif attr.startswith("path="):
                path = attr.split("=", 1)[1].strip()

        if name and value:
            results.add_cookie(HTTPCookie(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                domain=domain,
                path=path,
                name=name,
                value=value[:256],
                secure=secure,
                http_only=http_only,
                source="response"
            ))
