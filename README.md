# NetAudit

**Analizador de tráfico de red para auditorías de seguridad.**

NetAudit captura y analiza tráfico en vivo o archivos PCAP para extraer credenciales, banners de servicios, consultas DNS, tráfico SMB/Kerberos/TLS, cookies HTTP y más.

---

## Características

- **Credenciales:** HTTP Basic Auth, HTTP POST forms, FTP, Telnet, NTLMv2
- **Protocolos:** HTTP/HTTPS, DNS, FTP, Telnet, SMB, Kerberos, TLS, SSH, SMTP, POP3, IMAP, MySQL, PostgreSQL, Redis, MongoDB, VNC, RDP
- **Banners:** Detecta versiones de servicios (Apache, OpenSSH, MySQL, etc.)
- **TLS:** Extrae SNI (dominios), CN del certificado, emisor, versión TLS
- **SMB:** Versión, comandos, usuarios, shares, detección de NTLMSSP
- **Kerberos:** AS-REQ/REP, TGS-REQ/REP, realm, client/service names, tipo de encriptación
- **DNS:** Consultas y respuestas A, AAAA, MX, CNAME, etc.
- **Cookies:** Captura cookies de request y response
- **OS Fingerprint:** Estimación de SO por TTL y window size
- **Dashboard en vivo:** Interfaz TUI con Rich actualizada en tiempo real
- **Exportación:** JSON (completo) y CSV (credenciales + DNS)

---

## Instalación

### Windows

```powershell
# Instalar Npcap (necesario para captura en vivo)
# Descargar de: https://npcap.com

# Clonar e instalar
git clone https://github.com/CarlosConcepcion/hack1.git
cd hack1
pip install -r requirements.txt
pip install -e .
```

### Linux (Debian/Ubuntu)

```bash
# Instalar libpcap
sudo apt install libpcap-dev

# Clonar e instalar
git clone https://github.com/CarlosConcepcion/hack1.git
cd hack1
pip install -r requirements.txt
pip install -e .
```

### Linux (Fedora/RHEL)

```bash
sudo dnf install libpcap-devel
git clone https://github.com/CarlosConcepcion/hack1.git
cd hack1
pip install -r requirements.txt
pip install -e .
```

Después de `pip install -e .`, el comando `netaudit` estará disponible globalmente.

---

## Uso

### Ver interfaces disponibles

```bash
netaudit list-interfaces
```

### Captura en vivo

```bash
# Captura completa en interfaz específica
netaudit capture -i eth0 -o reporte.json --csv reporte.csv

# Solo credenciales (HTTP Basic, FTP, Telnet) - más rápido, menos ruido
netaudit capture -i eth0 --creds-only -o credenciales.json

# Con filtro BPF
netaudit capture -i eth0 --bpf "host 192.168.1.100" -o reporte.json

# Solo HTTP/HTTPS
netaudit capture -i eth0 --bpf "tcp port 80 or tcp port 443" -o web.json
```

### Analizar archivo PCAP

```bash
netaudit capture -r captura.pcap -o analisis.json --csv analisis.csv
```

### Opciones disponibles

| Opción | Descripción |
|---|---|
| `-i, --interface` | Interfaz de red para capturar |
| `-r, --read` | Leer archivo PCAP |
| `-o, --output` | Exportar resultados a JSON |
| `--csv` | Exportar credenciales y DNS a CSV |
| `--bpf` | Filtro BPF (ej. `tcp port 80`) |
| `--creds-only` | Solo capturar credenciales |
| `--no-resolve` | Omitir resolución DNS |
| `--stats-every` | Intervalo de actualización (segundos, por defecto 2) |
| `--quiet` | Suprimir logs de depuración |
| `-h, --help` | Mostrar ayuda |

---

## Ejemplos de salida

### JSON

```json
{
  "tool": "NetAudit v1.0.0",
  "statistics": {
    "total_packets": 10000,
    "tcp_packets": 8500,
    "udp_packets": 1500,
    "unique_sources": 12,
    "unique_destinations": 45
  },
  "credentials": [
    {
      "type": "HTTP Basic Auth",
      "source": "192.168.1.100:54321",
      "target": "10.0.0.1:80",
      "username": "admin",
      "password": "supersecret123"
    }
  ],
  "dns_queries": [...],
  "service_banners": [...],
  "smb_traffic": [...],
  "kerberos_authentication": [...],
  "tls_handshakes": [...]
}
```

### CSV

Se generan dos archivos:
- `reporte_credentials.csv` — credenciales capturadas
- `reporte_dns.csv` — consultas DNS

---

## Requisitos

- Python 3.8+
- [Npcap](https://npcap.com) (Windows, para captura en vivo)
- libpcap (Linux, para captura en vivo)
- Dependencias Python: scapy, rich, click, colorama

---

## Uso en auditoría real

### 1. Preparación

```bash
# Ver interfaces disponibles
netaudit list-interfaces

# Probar análisis con PCAP de prueba
netaudit capture -r test_full.pcap
```

### 2. Captura sigilosa (solo credenciales)

```bash
netaudit capture -i eth0 --creds-only -o evidencias.json --csv evidencias.csv
```

### 3. Captura completa con filtro

```bash
# Tráfico de un host específico
netaudit capture -i eth0 --bpf "host 10.0.0.100" -o host.json

# Tráfico de servicios específicos
netaudit capture -i eth0 --bpf "tcp port 21 or tcp port 23 or tcp port 80 or port 443"
```

### 4. Post-análisis de PCAP

```bash
netaudit capture -r captura_wireshark.pcap -o analisis_completo.json
```

> **Nota:** En Linux, para captura en vivo necesitás `sudo` o capacidad `CAP_NET_RAW`. Para analizar archivos PCAP no se requieren privilegios.

---

## Estructura del proyecto

```
netaudit/
├── cli.py               # CLI con Click
├── config.py            # Configuración
├── models.py            # Modelos de datos
├── core/
│   ├── sniffer.py       # Captura de paquetes (Scapy)
│   └── packet_handler.py# Despacho de protocolos
├── protocols/
│   ├── http.py          # HTTP (auth, cookies, forms)
│   ├── ftp.py           # FTP (credenciales)
│   ├── telnet.py        # Telnet (credenciales)
│   ├── smb.py           # SMB (versión, comandos, usuarios)
│   ├── kerberos.py      # Kerberos (tickets, realm)
│   ├── tls.py           # TLS/SSL (SNI, certificados)
│   ├── ntlm.py          # NTLM (Type 1/2/3)
│   ├── banners.py       # Banners de servicios
│   └── dns.py           # DNS
├── analysis/
│   ├── stats.py         # Estadísticas de tráfico
│   ├── conversations.py # Conversaciones por IP:puerto
│   ├── credentials.py   # Reporte de credenciales
│   └── os_fingerprint.py# Fingerprint por TTL/window
└── output/
    ├── console.py       # Dashboard TUI con Rich
    ├── json_exporter.py # Exportación a JSON
    └── csv_exporter.py  # Exportación a CSV
```

---

## Licencia

Uso educativo y auditorías de seguridad autorizadas.
