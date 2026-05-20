import json
d = json.load(open('report_full.json'))

print("=== SMB ===")
for s in d.get('smb_traffic', []):
    print(f"  {s['smb_version']:12s} {s['command']:25s} user={s['username']} share={s['share']}")

print("\n=== Kerberos ===")
for k in d.get('kerberos_authentication', []):
    print(f"  {k['msg_type']:12s} realm={k['realm']:15s} client={k['client_name']}")

print("\n=== TLS ===")
for t in d.get('tls_handshakes', []):
    print(f"  {t['tls_version']:12s} {t['handshake_type']:15s} SNI={t['sni']:25s} CN={t['subject']:30s} issuer={t['issuer']}")

print("\n=== Credentials ===")
for c in d.get('credentials', []):
    print(f"  {c['type']:20s} {c['username']:20s} {c.get('password',''):25s}")

print("\n=== Banners ===")
for b in d.get('service_banners', []):
    print(f"  {b['service']:12s} {b['banner'][:60]}")

print("\n=== Cookies ===")
for c in d.get('http_cookies', []):
    print(f"  {c['name']:25s} {c['value'][:30]:30s}")
