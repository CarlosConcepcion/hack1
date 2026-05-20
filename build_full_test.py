import base64, struct, sys
sys.stdout.reconfigure(encoding='utf-8')
from scapy.all import *

packets = []

# 1. HTTP Basic Auth
encoded = base64.b64encode(b'admin:supersecret123').decode()
http_auth = f"GET /admin HTTP/1.1\r\nHost: admin.example.com\r\nAuthorization: Basic {encoded}\r\nCookie: session=abc123\r\n\r\n".encode()
packets.append(IP(src='192.168.1.100', dst='10.0.0.1')/TCP(sport=54321, dport=80)/Raw(load=http_auth))

# HTTP response with cookies
http_resp = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nSet-Cookie: PHPSESSID=abc123; Path=/; HttpOnly; Secure\r\n\r\n<body>OK</body>".encode()
packets.append(IP(src='10.0.0.1', dst='192.168.1.100')/TCP(sport=80, dport=54321)/Raw(load=http_resp))

# 2. SMB2 Negotiate (client request)
def make_smb2_header(command, credits=1, message_id=0, session_id=0, status=0, flags=0):
    hdr = b'\xfeSMB'                       # 0-3: Protocol ID
    hdr += struct.pack('<H', 64)            # 4-5: StructureSize
    hdr += struct.pack('<H', 0)             # 6-7: CreditCharge
    hdr += struct.pack('<I', status)        # 8-11: NTStatus / ChannelSequence
    hdr += struct.pack('<H', command)       # 12-13: Command
    hdr += struct.pack('<H', credits)       # 14-15: Credits
    hdr += struct.pack('<I', flags)         # 16-19: Flags
    hdr += struct.pack('<I', 0)             # 20-23: NextCommand
    hdr += struct.pack('<Q', message_id)    # 24-31: MessageID
    hdr += struct.pack('<I', 0)             # 32-35: ProcessID / Reserved
    hdr += struct.pack('<I', 0)             # 36-39: TreeID
    hdr += struct.pack('<Q', session_id)    # 40-47: SessionID
    hdr += struct.pack('<Q', 0)             # 48-55: Signature (first 8)
    hdr += struct.pack('<Q', 0)             # 56-63: Signature (second 8)
    return hdr

def make_smb2_negotiate():
    body = struct.pack('<H', 36)           # StructureSize
    body += struct.pack('<H', 3)           # DialectCount
    body += struct.pack('<H', 1)           # SecurityMode
    body += struct.pack('<H', 0)           # Reserved
    body += struct.pack('<I', 0)           # Capabilities
    body += b'\x00' * 16                  # ClientGuid
    body += b'\x00' * 8                   # ClientStartTime
    body += struct.pack('<H', 0x0311)     # SMB 3.1.1
    body += struct.pack('<H', 0x0300)     # SMB 3.0
    body += struct.pack('<H', 0x0202)     # SMB 2.0.2
    hdr = make_smb2_header(command=0, credits=256)
    total_len = 4 + len(hdr) + len(body)
    nbss = struct.pack('>I', total_len - 4)
    return nbss + hdr + body

smb_neg = make_smb2_negotiate()
packets.append(IP(src='192.168.1.100', dst='10.0.0.50')/TCP(sport=49152, dport=445)/Raw(load=smb_neg))

# 3. SMB2 Session Setup with NTLM Type 3 (Authenticate)
def make_smb2_session_setup_ntlm():
    user = "administrator"
    domain = "WORKGROUP"
    workstation = "PC-01"
    nt_proof = b'\xaa' * 16
    nt_hash = nt_proof + b'\x00' * 16

    user_enc = user.encode('utf-16-le')
    domain_enc = domain.encode('utf-16-le')
    ws_enc = workstation.encode('utf-16-le')

    # Payload layout: LMresp | NTresp | Domain | User | Workstation
    lm_resp = b'\x00' * 24
    nt_resp = nt_hash  # 32 bytes
    session_key = b'\x00' * 16

    # Offsets: start after fixed header (52 bytes for Type 3 w/o OS version, or 60 with)
    base_off = 72  # NTLM Type 3 fixed header size with OS version
    lm_off = base_off
    nt_off = lm_off + len(lm_resp)
    dom_off = nt_off + len(nt_resp)
    user_off = dom_off + len(domain_enc)
    ws_off = user_off + len(user_enc)
    skey_off = ws_off + len(ws_enc)

    flags = 0x02890205  # typical NTLMv2 flags

    ntlm3 = b'NTLMSSP\x00'
    ntlm3 += struct.pack('<I', 3)  # Type 3
    ntlm3 += struct.pack('<HHI', len(lm_resp), len(lm_resp), lm_off)  # LM
    ntlm3 += struct.pack('<HHI', len(nt_resp), len(nt_resp), nt_off)  # NT
    ntlm3 += struct.pack('<HHI', len(domain_enc), len(domain_enc), dom_off)  # Domain
    ntlm3 += struct.pack('<HHI', len(user_enc), len(user_enc), user_off)  # User
    ntlm3 += struct.pack('<HHI', len(ws_enc), len(ws_enc), ws_off)  # Workstation
    ntlm3 += struct.pack('<HHI', len(session_key), len(session_key), skey_off)  # Session key
    ntlm3 += struct.pack('<I', flags)
    ntlm3 += struct.pack('<BBH', 10, 0, 19041) + b'\x00\x00\x00\x0f'  # OS Version (Windows 10.0.19041, 8 bytes)
    ntlm3 += lm_resp
    ntlm3 += nt_resp
    ntlm3 += domain_enc
    ntlm3 += user_enc
    ntlm3 += ws_enc
    ntlm3 += session_key
    sec_buf = ntlm3

    struct_size = 25
    flags = 0
    sec_mode = 1
    capabs = 0
    channel = 0
    sec_buf_offset = 64 + struct_size  # after SMB2 header + SESSION_SETUP fixed part
    sec_buf_len = len(sec_buf)
    prev_session_id = 0

    setup = struct.pack('<H', struct_size)
    setup += struct.pack('<B', flags)
    setup += struct.pack('<B', sec_mode)
    setup += struct.pack('<I', capabs)
    setup += struct.pack('<I', channel)
    setup += struct.pack('<H', sec_buf_offset)
    setup += struct.pack('<H', sec_buf_len)
    setup += struct.pack('<Q', prev_session_id)

    hdr = make_smb2_header(command=1, message_id=1)
    body = setup + sec_buf
    total_len = 4 + len(hdr) + len(body)
    nbss = struct.pack('>I', total_len - 4)
    return nbss + hdr + body

smb_sess = make_smb2_session_setup_ntlm()
packets.append(IP(src='192.168.1.100', dst='10.0.0.50')/TCP(sport=49152, dport=445)/Raw(load=smb_sess))

# 4. Kerberos AS-REQ (simplified encoding matching parser expectations)
def make_kerberos_asreq():
    realm_bytes = b'DOMAIN.LOCAL'
    cname_bytes = b'jdoe'

    name_entry = bytes([0x1b, 0x05, 0x04]) + cname_bytes
    name_strings = bytes([0x05, len(name_entry)]) + name_entry
    cname = bytes([0x03, len(name_strings)]) + name_strings

    realm = bytes([0x02, 0x0D, 0x0C]) + realm_bytes
    msg_type = bytes([0x01, 0x02, 0x01, 0x0A])
    etype = bytes([0x04, 0x02, 0x01, 0x12])

    app_data = realm + msg_type + etype + cname
    app_tag = bytes([0x60, len(app_data)]) + app_data
    pdu = struct.pack('>I', len(app_tag)) + app_tag
    return pdu

krb = make_kerberos_asreq()
packets.append(IP(src='192.168.1.100', dst='10.0.0.55')/TCP(sport=50000, dport=88)/Raw(load=krb))

# 5. TLS ClientHello with SNI
def make_tls_clienthello():
    sni = b'www.example.com'
    ext_sni = b'\x00\x00'
    ext_sni += struct.pack('>H', len(sni) + 5)
    ext_sni += struct.pack('>H', len(sni) + 3)
    ext_sni += b'\x00' + struct.pack('>H', len(sni)) + sni

    random = b'\x01' * 32
    ciphers = b'\x00\x02\xc0\x2b'  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    session = b'\x20' + b'\x02' * 32

    ext_data = ext_sni
    ext_len = struct.pack('>H', len(ext_data))

    total_handshake_body = 2 + 32 + 1 + len(session[1:]) + 2 + len(ciphers) + 2 + 2 + len(ext_data)
    body = struct.pack('>H', 0x0303)
    body += random
    body += bytes([session[0]])
    body += session[1:]
    body += struct.pack('>H', len(ciphers))
    body += ciphers
    body += bytes([1, 0])
    body += ext_len
    body += ext_data

    handshake = bytes([1, 0, 0]) + struct.pack('B', len(body))
    handshake += body

    tls_len = struct.pack('>H', len(handshake))
    record = bytes([0x16, 0x03, 0x01]) + tls_len + handshake
    return record

tls_ch = make_tls_clienthello()
packets.append(IP(src='192.168.1.100', dst='93.184.216.34')/TCP(sport=54321, dport=443)/Raw(load=tls_ch))

# 6. SSL Certificate (simplified)
def make_tls_serverhello_cert():
    random = b'\x02' * 32
    ciphers = b'\xc0\x2b'
    session = b'\x20' + b'\x03' * 32

    body = bytes([2, 0, 0])
    body += struct.pack('B', 2 + 32 + len(session) + 2 + 2)
    body += struct.pack('>H', 0x0303)
    body += random
    body += bytes([session[0]])
    body += session[1:]
    body += struct.pack('>H', len(ciphers))
    body += ciphers
    body += struct.pack('>H', 0)

    handshake = bytes([2, 0, 0]) + struct.pack('B', len(body))
    handshake += body
    tls_len = struct.pack('>H', len(handshake))
    record = bytes([0x16, 0x03, 0x03]) + tls_len + handshake
    return record

tls_sh = make_tls_serverhello_cert()
packets.append(IP(src='93.184.216.34', dst='192.168.1.100')/TCP(sport=443, dport=54321)/Raw(load=tls_sh))

# Certificate
def make_certificate():
    cert_der = bytearray(200)
    cert_der[0:4] = b'\x30\x82\x00\xc4'
    cert_der[10:14] = b'\x30\x82\x00\x30'
    # Subject CN
    cn = b'www.example.com'
    cert_der[80:86] = b'\x06\x03\x55\x04\x03\x0c'
    cert_der[86] = len(cn)
    cert_der[87:87 + len(cn)] = cn
    # Issuer
    issuer = b'Let\'s Encrypt'
    cert_der[130:136] = b'\x06\x03\x55\x04\x0a\x0c'
    cert_der[136] = len(issuer)
    cert_der[137:137 + len(issuer)] = issuer

    total_len = len(bytes(cert_der))
    body = struct.pack('>I', total_len)[1:] + bytes(cert_der)
    handshake = bytes([11, 0, 0]) + struct.pack('B', len(body))
    handshake += body
    tls_len = struct.pack('>H', len(handshake))
    record = bytes([0x16, 0x03, 0x03]) + tls_len + handshake
    return record

tls_cert = make_certificate()
packets.append(IP(src='93.184.216.34', dst='192.168.1.100')/TCP(sport=443, dport=54321)/Raw(load=tls_cert))

# 7. FTP
packets.append(IP(src='10.0.0.5', dst='192.168.1.100')/TCP(sport=21, dport=50001)/Raw(load=b'220 FTP Ready\r\n'))
packets.append(IP(src='192.168.1.100', dst='10.0.0.5')/TCP(sport=50001, dport=21)/Raw(load=b'USER auditor\r\n'))
packets.append(IP(src='192.168.1.100', dst='10.0.0.5')/TCP(sport=50001, dport=21)/Raw(load=b'PASS P@ssw0rd!\r\n'))

# 8. Telnet
packets.append(IP(src='10.0.0.3', dst='192.168.1.100')/TCP(sport=23, dport=60000)/Raw(load=b'login: '))
packets.append(IP(src='192.168.1.100', dst='10.0.0.3')/TCP(sport=60000, dport=23)/Raw(load=b'admin'))
packets.append(IP(src='10.0.0.3', dst='192.168.1.100')/TCP(sport=23, dport=60000)/Raw(load=b'\r\npassword: '))
packets.append(IP(src='192.168.1.100', dst='10.0.0.3')/TCP(sport=60000, dport=23)/Raw(load=b'telnetpass'))

# 9. DNS
packets.append(IP(src='192.168.1.100', dst='8.8.8.8')/UDP(sport=44444, dport=53)/DNS(rd=1, qd=DNSQR(qname='example.com', qtype='A')))

# 10. Banners
packets.append(IP(src='10.0.0.2', dst='192.168.1.100')/TCP(sport=22, dport=40000)/Raw(load=b'SSH-2.0-OpenSSH_9.0p1\r\n'))
packets.append(IP(src='10.0.0.10', dst='192.168.1.100')/TCP(sport=3306, dport=40010)/Raw(load=b'\x0a' + b'8.0.36-0ubuntu0.22.04.1\x00' + b'\x00' * 20))
packets.append(IP(src='10.0.0.11', dst='192.168.1.100')/TCP(sport=6379, dport=40011)/Raw(load=b'+PONG\r\n'))

wrpcap('test_full.pcap', packets)
print(f"Created test_full.pcap with {len(packets)} packets")
