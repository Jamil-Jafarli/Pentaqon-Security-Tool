# Pentagon SOC Platform

Web-based Security Operations Center assistant with AI-powered SIEM query generation, endpoint scanning, and threat intelligence lookup.

---

## Tech Stack

### Backend
| Component | Detail |
|-----------|--------|
| Language | Python 3.13 |
| Framework | Flask 3.1.3 |
| CORS | flask-cors 6.0.2 |
| AI / LLM | Groq SDK 1.2.0 — model `openai/gpt-oss-120b` |
| SIEM integration | Splunk REST API (port 8089, HTTPS) |
| DNS resolution | dnspython 2.8.0 |
| WHOIS | python-whois 0.9.6 |
| HTTP client | requests 2.32.3 |

### Frontend
| Component | Detail |
|-----------|--------|
| HTML/CSS/JS | Vanilla (no framework) |
| Themes | Dark · Viper (green) · Light — persisted via `localStorage` |
| Sidebar | Collapsible numbered sections (1 SIEM / 2 ENDPOINT / 3 THREAT INTEL), state persisted |
| SIEM selector | Splunk · Elastic/ELK · Microsoft Sentinel · IBM QRadar · Wazuh · ArcSight |

### Endpoint Agent
| Component | Detail |
|-----------|--------|
| Language | C++17 (1 247 lines) |
| Target | Windows x64 PE32+ executable |
| Compiler | MinGW-w64 GCC 13 (`x86_64-w64-mingw32-g++`) |
| Transport | WinHTTP — POSTs JSON report to `/api/postdata` |
| Scans | Running processes · loaded DLLs · System32 baseline diff · scheduled tasks · network connections |
| Build | Dynamic — server IP/port injected at compile time via `-DSOC_HOST` / `-DSOC_PORT` |

### Threat Intelligence Integrations
| Service | Usage |
|---------|-------|
| VirusTotal | File hash / domain / IP / URL reputation |
| AbuseIPDB | IP abuse score and report count |
| Shodan InternetDB | Open ports and tags (free, no key) |
| Shodan API | Full host data (requires API key) |
| URLhaus | Malware URL / hash lookup |
| crt.sh | Certificate transparency / subdomain enumeration |
| RBL / DNSBL | Spam blacklist check (Spamhaus ZEN, Barracuda, SORBS, etc.) |
| WHOIS | Domain registrar, creation/expiry dates |
| SPF / DMARC / MX | Email domain security posture |
| SSL/TLS | Certificate issuer, validity, SAN |

---

## Project Structure

```
soc-assistant/
├── app.py                  # Flask backend — all API routes
├── endpoint_scan.cpp       # Windows endpoint agent source
├── start.sh                # Launch script (sets GROQ_API_KEY)
├── settings.json           # API keys (VT, AbuseIPDB, Shodan)
├── static/
│   ├── index.html          # Single-page app shell
│   ├── app.js              # Frontend logic
│   └── style.css           # Viper theme + all component styles
└── venv/                   # Python virtual environment
```

---

## API Reference

### SIEM
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/nl-to-splunk` | Natural language → SPL query + auto-execute |
| POST | `/api/run-spl` | Execute raw SPL query |
| GET  | `/api/alerts` | Fetch recent Splunk alerts |
| POST | `/api/analyze-alert` | AI analysis of a single alert |
| POST | `/api/chat` | Free-form AI SOC chat |

### Endpoint
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/agent/info` | Server IP, compiler availability |
| POST | `/api/agent/build` | Compile and download agent `.exe` |
| POST | `/api/postdata` | Receive scan report from agent |
| GET  | `/api/reports` | List all endpoint reports |
| GET  | `/api/reports/<id>` | Get single report detail |

### Threat Intelligence
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ti/domain` | Full domain intel (DNS/WHOIS/SSL/crt.sh/VT) |
| POST | `/api/ti/mail` | Email domain posture (SPF/DMARC/MX/RBL) |
| POST | `/api/ti/ioc` | IOC lookup — IP / domain / hash / URL |

### Settings
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/settings` | Read current API key config |
| POST | `/api/settings` | Save API key config |
| POST | `/api/settings/test` | Test Splunk connectivity |

---

## Running

```bash
# First time
python3 -m venv venv
./venv/bin/pip install flask flask-cors groq requests dnspython python-whois

# Start server
GROQ_API_KEY=<key> ./start.sh
# or
./start.sh <key>

# Access
http://<server-ip>:5000
```

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | — | Required. Groq API key |
| `SPLUNK_HOST` | `https://localhost:8089` | Splunk management URL |
| `SPLUNK_USER` | `admin` | Splunk username |
| `SPLUNK_PASS` | — | Splunk password |

### API Keys (Settings tab)
| Key | Source |
|-----|--------|
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | https://www.abuseipdb.com/account/api |
| Shodan | https://account.shodan.io |

---

## Endpoint Agent Build

The agent is compiled on-demand from the Deploy Agent tab. The server IP and port are baked into the binary at compile time.

**Manual build:**
```bash
x86_64-w64-mingw32-g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ \
  -DSOC_HOST='"192.168.x.x"' -DSOC_PORT=5000 \
  -o soc_agent.exe endpoint_scan.cpp \
  -lwinhttp -liphlpapi -lpsapi -ltaskschd \
  -lole32 -loleaut32 -luuid -ladvapi32 -lws2_32
```

**Agent scan scope:**
- Running processes and their loaded DLLs
- System32 file baseline diff (known-clean baseline of 500+ files excluded)
- Scheduled tasks — non-Microsoft authors or suspicious commands
- Active network connections (TCP/UDP)
- Report is POSTed as JSON to `/api/postdata` and stored server-side

---

## Themes

| Theme | Key | Description |
|-------|-----|-------------|
| Dark | `dark` | Default dark navy/blue |
| Viper | `viper` | Deep black with green accent (`#0eb85e`) |
| Light | `light` | Light grey/white |

Toggle via the theme switcher in the top bar. Choice persisted in `localStorage`.
# Pentaqon-Security-Tool
# Pentaqon-Security-Tool
