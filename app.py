import os
import re
import json
import time
import shutil
import socket
import ssl
import ipaddress
import base64
import tempfile
import subprocess
import requests
import urllib3
import dns.resolver
import whois as _whois_lib
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from groq import Groq

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder="static")
CORS(app)

client = Groq(api_key=os.environ.get("GROQ_API_KEY", ""))
MODEL = "openai/gpt-oss-120b"

SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "https://localhost:8089")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "Salam123Salam123!")

SPLUNK_INDEXES = ["main", "wineventlog", "_audit", "_internal"]
SPLUNK_SOURCETYPES = [
    "WinEventLog:Security", "WinEventLog:System",
    "WinEventLog:Application", "WinEventLog:Setup"
]

SYSTEM_PROMPT = """You are an expert SOC analyst specializing in Splunk SPL queries.
Available indexes: main, wineventlog, _audit, _internal, and any others via index=*
Available sourcetypes: WinEventLog:Security, WinEventLog:System, WinEventLog:Application, WinEventLog:Setup

Rules:
- If the user does NOT specify an index, always use: index=*
- If the user specifies an index, use exactly that index
- NEVER include time modifiers (earliest=, latest=) — time is controlled externally
- NEVER add | table or | stats unless the user explicitly asks for a table or aggregation
- For raw/event queries: just filter with WHERE conditions (EventCode=X, keyword searches, etc.)
- For table queries (user says "table", "summarize", "count", "stats"): add appropriate | table or | stats
- Use real Splunk field names: EventCode, ComputerName, Account_Name, src_ip, dest_ip, User, Message, _raw
- Keep queries practical and executable
- Respond ONLY with valid JSON, no markdown"""

SOC_CHAT_SYSTEM = """You are an expert SOC analyst and threat hunter.
Help with: threat hunting, incident response, MITRE ATT&CK, Splunk SPL, detection rules, IOC analysis.
Use markdown formatting. Be concise and actionable."""

DEMO_ALERTS = [
    {
        "id": "INC-2024-001", "title": "Brute Force Attack Detected",
        "severity": "HIGH", "source": "Windows Security", "timestamp": "2024-05-23 09:14:32",
        "events": 847, "src_ip": "185.220.101.45", "user": "administrator",
        "description": "847 failed login attempts in 5 minutes from single IP targeting domain administrator account",
        "mitre": "T1110.001"
    },
    {
        "id": "INC-2024-002", "title": "Suspicious PowerShell Execution",
        "severity": "CRITICAL", "source": "EDR", "timestamp": "2024-05-23 10:22:17",
        "events": 3, "src_ip": "10.0.1.55", "user": "jsmith",
        "description": "Encoded PowerShell command executed with -EncodedCommand flag, spawned from Word document",
        "mitre": "T1059.001"
    },
    {
        "id": "INC-2024-003", "title": "Data Exfiltration - Large Upload",
        "severity": "CRITICAL", "source": "Network DLP", "timestamp": "2024-05-23 11:45:03",
        "events": 12, "src_ip": "10.0.2.88", "user": "mwilson",
        "description": "2.3GB data uploaded to external cloud storage (mega.nz) outside business hours",
        "mitre": "T1048"
    },
    {
        "id": "INC-2024-004", "title": "Lateral Movement - Pass-the-Hash",
        "severity": "HIGH", "source": "SIEM Correlation", "timestamp": "2024-05-23 12:10:44",
        "events": 28, "src_ip": "10.0.1.55", "user": "SYSTEM",
        "description": "NTLM authentication anomaly detected - same hash used across 7 systems within 3 minutes",
        "mitre": "T1550.002"
    },
    {
        "id": "INC-2024-005", "title": "DNS Tunneling Suspected",
        "severity": "MEDIUM", "source": "DNS Firewall", "timestamp": "2024-05-23 13:30:19",
        "events": 1240, "src_ip": "10.0.3.12", "user": "N/A",
        "description": "Unusually high DNS query volume with long subdomain strings to uncommon TLD (.xyz)",
        "mitre": "T1071.004"
    }
]


# ── Splunk helpers ────────────────────────────────────────────────────────────

def splunk_login():
    r = requests.post(
        f"{SPLUNK_HOST}/services/auth/login",
        data={"username": SPLUNK_USER, "password": SPLUNK_PASS},
        verify=False, timeout=10
    )
    r.raise_for_status()
    import xml.etree.ElementTree as ET
    root = ET.fromstring(r.text)
    key = root.find(".//sessionKey")
    if key is None:
        raise ValueError("Login failed — check credentials")
    return key.text


def splunk_run(spl: str, max_results: int = 200,
               earliest: str = "0", latest: str = "now") -> dict:
    """Run SPL via async job, return {columns, rows, total, duration_ms}"""
    token = splunk_login()
    headers = {"Authorization": f"Splunk {token}"}
    search = spl.strip()
    if not search.lower().startswith("search "):
        search = "search " + search

    t0 = time.time()

    # Create job
    r = requests.post(
        f"{SPLUNK_HOST}/services/search/jobs",
        headers=headers,
        data={
            "search": search,
            "earliest_time": earliest,
            "latest_time": latest,
        },
        verify=False, timeout=30
    )
    r.raise_for_status()

    import xml.etree.ElementTree as ET
    sid = ET.fromstring(r.text).findtext(".//sid")
    if not sid:
        raise ValueError("Could not create search job")

    # Poll until done (max 55s)
    for _ in range(55):
        time.sleep(1)
        status = requests.get(
            f"{SPLUNK_HOST}/services/search/jobs/{sid}",
            headers=headers, params={"output_mode": "json"},
            verify=False, timeout=10
        ).json()
        state = status["entry"][0]["content"]["dispatchState"]
        if state in ("DONE", "FAILED"):
            break

    duration_ms = int((time.time() - t0) * 1000)

    if state == "FAILED":
        raise ValueError("Splunk job failed")

    # Fetch results
    res = requests.get(
        f"{SPLUNK_HOST}/services/search/jobs/{sid}/results",
        headers=headers,
        params={"output_mode": "json", "count": max_results},
        verify=False, timeout=30
    ).json()

    results = res.get("results", [])
    is_raw = not is_table_query(spl)
    columns = []
    rows = []
    for result in results:
        if not columns:
            if is_raw:
                # Raw mode: return ALL fields — frontend handles display
                # Order: _time, host, source, sourcetype, extracted fields, _raw
                priority = ["_time", "host", "source", "sourcetype"]
                columns = [k for k in priority if k in result]
                columns += sorted(k for k in result
                                  if not k.startswith("_") and k not in columns)
                if "_raw" in result:
                    columns.append("_raw")
            else:
                # Table mode: _time first, then non-underscore fields
                columns = (["_time"] if "_time" in result else []) + \
                          [k for k in result if not k.startswith("_")]
        rows.append({k: result.get(k, "") for k in columns})

    # Cleanup job
    requests.delete(
        f"{SPLUNK_HOST}/services/search/jobs/{sid}",
        headers=headers, verify=False, timeout=5
    )

    return {
        "spl": spl,
        "is_raw": is_raw,
        "columns": columns,
        "rows": rows,
        "total": len(rows),
        "duration_ms": duration_ms,
        "truncated": len(rows) >= max_results
    }


def is_table_query(spl: str) -> bool:
    """True if SPL ends with | table, | stats, | chart, | timechart, | top, | rare etc."""
    import re
    return bool(re.search(
        r'\|\s*(table|stats|chart|timechart|top|rare|eventstats|tstats)\b',
        spl, re.IGNORECASE
    ))


# ── Groq helpers ──────────────────────────────────────────────────────────────

def groq_json(user_msg: str, schema: str) -> dict:
    prompt = f"{user_msg}\n\nRespond ONLY with valid JSON:\n{schema}"
    r = client.chat.completions.create(
        model=MODEL, max_tokens=2048,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt}
        ]
    )
    text = r.choices[0].message.content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return json.loads(text)


def groq_chat(messages: list) -> str:
    r = client.chat.completions.create(
        model=MODEL, max_tokens=2048,
        messages=[{"role": "system", "content": SOC_CHAT_SYSTEM}] + messages
    )
    return r.choices[0].message.content


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/run-spl", methods=["POST"])
def run_spl_direct():
    """Execute SPL directly (no AI generation)."""
    data = request.json
    spl = data.get("spl", "").strip()
    if not spl:
        return jsonify({"success": False, "error": "Empty SPL"}), 400
    earliest = data.get("earliest_time", "0")
    latest   = data.get("latest_time",   "now")
    try:
        result = splunk_run(spl, earliest=earliest, latest=latest)
        return jsonify({
            "success": True,
            "spl": result["spl"],
            "is_raw": result["is_raw"],
            "explanation": "",
            "mitre_techniques": [],
            "notes": "",
            "exec_error": None,
            "columns": result["columns"],
            "rows":    result["rows"],
            "total":   result["total"],
            "duration_ms": result["duration_ms"],
            "truncated":   result["truncated"],
        })
    except Exception as e:
        return jsonify({
            "success": True,
            "spl": spl, "is_raw": True, "explanation": "", "mitre_techniques": [],
            "notes": "", "exec_error": str(e),
            "columns": [], "rows": [], "total": 0, "duration_ms": 0, "truncated": False
        })


@app.route("/api/nl-to-splunk", methods=["POST"])
def nl_to_splunk():
    data = request.json
    nl_query = data.get("query", "").strip()
    if not nl_query:
        return jsonify({"success": False, "error": "Empty query"}), 400
    earliest = data.get("earliest_time", "0")
    latest   = data.get("latest_time",   "now")

    wants_table = any(w in nl_query.lower()
                      for w in ["table", "cədvəl", "count", "stats", "summarize",
                                "top ", "rare ", "chart", "timechart"])

    schema = """{
  "spl": "complete SPL query without time modifiers",
  "explanation": "one sentence what this query does",
  "mitre_techniques": ["T1234"],
  "notes": "optional caveats or tuning tips"
}"""

    hint = (
        "User wants a TABLE/aggregation — use | table or | stats at the end."
        if wants_table else
        "User wants RAW events — do NOT add | table or | stats. Just filter conditions."
    )

    try:
        ai_result = groq_json(
            f"Generate a Splunk SPL query for: \"{nl_query}\"\nHint: {hint}",
            schema
        )
    except Exception as e:
        return jsonify({"success": False, "error": f"AI error: {e}"}), 500

    spl = ai_result.get("spl", "")

    try:
        exec_result = splunk_run(spl, earliest=earliest, latest=latest)
    except Exception as e:
        # Return the query even if execution fails
        return jsonify({
            "success": True,
            "spl": spl,
            "explanation": ai_result.get("explanation", ""),
            "mitre_techniques": ai_result.get("mitre_techniques", []),
            "notes": ai_result.get("notes", ""),
            "exec_error": str(e),
            "columns": [],
            "rows": [],
            "total": 0,
            "duration_ms": 0,
            "truncated": False
        })

    return jsonify({
        "success": True,
        "spl": exec_result["spl"],
        "is_raw": exec_result["is_raw"],
        "explanation": ai_result.get("explanation", ""),
        "mitre_techniques": ai_result.get("mitre_techniques", []),
        "notes": ai_result.get("notes", ""),
        "exec_error": None,
        "columns": exec_result["columns"],
        "rows": exec_result["rows"],
        "total": exec_result["total"],
        "duration_ms": exec_result["duration_ms"],
        "truncated": exec_result["truncated"]
    })


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    return jsonify({"success": True, "data": DEMO_ALERTS})


@app.route("/api/analyze-alert", methods=["POST"])
def analyze_alert():
    alert = request.json.get("alert", {})
    schema = """{
  "summary": "2-3 sentence summary",
  "attack_chain": ["step1","step2"],
  "mitre_technique": "T-code and name",
  "mitre_tactic": "tactic name",
  "iocs": [{"type":"ip|hash|domain|user","value":"...","threat_level":"high|medium|low"}],
  "false_positive_probability": "low|medium|high",
  "false_positive_reasoning": "reasoning",
  "immediate_actions": ["action1","action2"],
  "remediation_steps": ["step1","step2"],
  "forensic_queries": {"splunk":"SPL query","kql":"KQL query"},
  "related_alerts": ["type1","type2"]
}"""
    try:
        result = groq_json(
            f"Analyze this security alert:\n{json.dumps(alert, indent=2)}",
            schema
        )
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/correlate", methods=["POST"])
def correlate_events():
    alert_ids = request.json.get("alert_ids", [])
    alerts = [a for a in DEMO_ALERTS if a["id"] in alert_ids]
    schema = """{
  "campaign_name": "name",
  "confidence": "high|medium|low",
  "attack_narrative": "narrative",
  "timeline": [{"time":"...","event":"...","significance":"..."}],
  "threat_actor_profile": "profile",
  "kill_chain_stage": "stage",
  "pivot_points": ["ip:...","user:..."],
  "blast_radius": "scope",
  "priority_actions": ["action1"],
  "detection_gaps": ["gap1"]
}"""
    try:
        result = groq_json(
            f"Correlate these alerts:\n{json.dumps(alerts, indent=2)}",
            schema
        )
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/reduce-fp", methods=["POST"])
def reduce_false_positives():
    alert = request.json.get("alert", {})
    context = request.json.get("context", "")
    schema = """{
  "verdict": "true_positive|false_positive|benign_true_positive",
  "confidence_score": 85,
  "reasoning": "reasoning",
  "whitelist_recommendation": "recommendation",
  "tuning_suggestions": [{"field":"...","operator":"...","value":"...","reason":"..."}],
  "risk_if_whitelisted": "low|medium|high",
  "similar_fp_patterns": ["pattern1"],
  "recommended_threshold": "threshold recommendation"
}"""
    try:
        result = groq_json(
            f"False positive analysis:\nAlert: {json.dumps(alert, indent=2)}\nContext: {context}",
            schema
        )
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/chat", methods=["POST"])
def chat():
    message = request.json.get("message", "")
    history = request.json.get("history", [])
    msgs = [{"role": h["role"], "content": h["content"]} for h in history[-10:]]
    msgs.append({"role": "user", "content": message})
    try:
        reply = groq_chat(msgs)
        return jsonify({"success": True, "response": reply})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── Agent build config ────────────────────────────────────────────────────────

CPP_SRC     = os.path.join(os.path.dirname(__file__), "endpoint_scan.cpp")
MINGW_CXX   = shutil.which("x86_64-w64-mingw32-g++") or "x86_64-w64-mingw32-g++"
MINGW_FLAGS = [
    "-std=c++17", "-O2", "-static-libgcc", "-static-libstdc++",
]
MINGW_LIBS  = [
    "-lwinhttp", "-liphlpapi", "-lpsapi", "-ltaskschd",
    "-lole32", "-loleaut32", "-luuid", "-ladvapi32", "-lws2_32",
]

def _server_ip() -> str:
    """Best-guess of this server's LAN IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── In-memory store for endpoint reports ─────────────────────────────────────
_endpoint_reports: list[dict] = []


def _parse_report(body: str) -> dict:
    """Extract structured fields and risk score from a plain-text triage report."""
    lines = body.splitlines()

    def field(key):
        for ln in lines:
            if ln.strip().startswith(key + " "):
                return ln.split(":", 1)[1].strip() if ":" in ln else ""
        return ""

    def section_lines(header_marker):
        """Yield lines that belong to a section (stops at next === header)."""
        in_sec = False
        for ln in lines:
            if header_marker in ln:
                in_sec = True
                continue
            if in_sec and ln.startswith("===") and header_marker not in ln:
                break
            if in_sec:
                yield ln

    # ── Registry: severity-weighted count ───────────────────
    # AUTORUN-HIGH / IFEO HIJACK / WINLOGON TAMPER / SILENT_EXIT = high weight
    # AUTORUN-INFO = low weight (unknown vendor, not clearly malicious)
    REG_HIGH_TAGS = {"[AUTORUN-HIGH]", "[IFEO HIJACK]", "[WINLOGON TAMPER]", "[SILENT_EXIT"}
    registry_high = 0
    registry_info = 0
    for ln in section_lines("SUSPICIOUS REGISTRY"):
        stripped = ln.strip()
        if any(stripped.startswith(t) for t in REG_HIGH_TAGS):
            registry_high += 1
        elif stripped.startswith("[AUTORUN-INFO]"):
            registry_info += 1
    registry_hits = registry_high + registry_info

    # ── Ports: count listening / established ────────────────
    port_hits = sum(
        1 for ln in section_lines("OPEN PORTS")
        if "LISTEN" in ln or "ESTABLISHED" in ln or "  UDP" in ln
    )

    # ── System32 unusual files ──────────────────────────────
    sys32_hits = sum(
        1 for ln in section_lines("UNUSUAL SYSTEM32")
        if ln.strip().startswith("[")
    )

    # ── Services: weight RUNNING higher ─────────────────────
    service_running = sum(
        1 for ln in section_lines("UNUSUAL SERVICES")
        if "[RUNNING]" in ln
    )
    service_stopped = sum(
        1 for ln in section_lines("UNUSUAL SERVICES")
        if "[STOPPED]" in ln
    )
    service_hits = service_running + service_stopped

    # ── Scheduled tasks ─────────────────────────────────────
    task_hits = sum(
        1 for ln in section_lines("UNUSUAL SCHEDULED TASKS")
        if ln.strip().startswith("[TASK]")
    )

    # ── Weighted risk score ──────────────────────────────────
    # High-severity registry findings and running services carry more weight
    score = (registry_high * 3 + registry_info * 1 +
             sys32_hits * 2 +
             service_running * 3 + service_stopped * 1 +
             task_hits * 2)

    if score >= 6:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
    elif score >= 1:
        risk = "LOW"
    else:
        risk = "CLEAN"

    # Also expose high-severity registry count for UI badge
    registry_high_count = registry_high

    return {
        "host":    field("Host"),
        "user":    field("User"),
        "os":      field("OS"),
        "dt":      field("DateTime"),
        "server":  field("Server"),
        "build":   field("Build"),
        "risk":    risk,
        "score":   score,
        "counts": {
            "registry":      registry_hits,
            "registry_high": registry_high,
            "ports":         port_hits,
            "sys32":         sys32_hits,
            "services":      service_hits,
            "svc_running":   service_running,
            "tasks":         task_hits,
        },
    }


@app.route("/api/postdata", methods=["POST"])
def receive_endpoint_report():
    body = request.get_data(as_text=True)
    if not body:
        return jsonify({"success": False, "error": "Empty body"}), 400

    parsed = _parse_report(body)
    entry = {
        "id":          f"EP-{int(time.time())}",
        "received_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "remote_addr": request.remote_addr,
        "report":      body,
        **parsed,
    }
    _endpoint_reports.append(entry)
    if len(_endpoint_reports) > 100:
        _endpoint_reports.pop(0)

    print(f"[agent] {entry['id']}  host={parsed['host'] or '?'}  "
          f"risk={parsed['risk']}  from={request.remote_addr}")
    return jsonify({"success": True, "id": entry["id"]}), 200


@app.route("/api/reports", methods=["GET"])
def list_reports():
    meta = []
    for r in reversed(_endpoint_reports):
        meta.append({
            "id":          r["id"],
            "received_at": r["received_at"],
            "remote_addr": r["remote_addr"],
            "host":        r.get("host", ""),
            "user":        r.get("user", ""),
            "os":          r.get("os", ""),
            "dt":          r.get("dt", ""),
            "risk":        r.get("risk", "UNKNOWN"),
            "score":       r.get("score", 0),
            "counts":      r.get("counts", {}),
            "size":        len(r["report"]),
        })
    return jsonify({"success": True, "data": meta})


@app.route("/api/reports/<report_id>", methods=["GET"])
def get_report(report_id):
    for r in _endpoint_reports:
        if r["id"] == report_id:
            return jsonify({"success": True, "data": r})
    return jsonify({"success": False, "error": "Not found"}), 404


# ── Agent deployment ──────────────────────────────────────────────────────────

@app.route("/api/agent/info", methods=["GET"])
def agent_info():
    """Return detected server IP and compiler availability."""
    compiler_ok = os.path.isfile(MINGW_CXX) or bool(shutil.which("x86_64-w64-mingw32-g++"))
    return jsonify({
        "success": True,
        "server_ip": _server_ip(),
        "server_port": 5000,
        "compiler": MINGW_CXX,
        "compiler_available": compiler_ok,
        "cpp_source": os.path.basename(CPP_SRC),
    })


@app.route("/api/agent/build", methods=["POST"])
def build_agent():
    """
    Compile endpoint_scan.cpp with injected server IP/port.
    Body (JSON): { "host": "1.2.3.4", "port": 5000 }
    Returns: application/octet-stream  (the .exe binary)
    """
    data     = request.json or {}
    soc_host = data.get("host", _server_ip()).strip()
    soc_port = int(data.get("port", 5000))

    # Validate inputs
    if not re.match(r'^[\w.\-]+$', soc_host):
        return jsonify({"success": False, "error": "Invalid host"}), 400
    if not (1 <= soc_port <= 65535):
        return jsonify({"success": False, "error": "Invalid port"}), 400
    if not os.path.isfile(CPP_SRC):
        return jsonify({"success": False, "error": "Source file not found"}), 500

    build_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    tmpdir   = tempfile.mkdtemp(prefix="soc_build_")
    out_exe  = os.path.join(tmpdir, "soc_agent.exe")

    try:
        # Each element goes directly to execve — no shell escaping needed.
        # String macros need the quotes to be part of the value seen by the preprocessor.
        cmd = [
            MINGW_CXX,
            *MINGW_FLAGS,
            f'-DSOC_HOST="{soc_host}"',
            f"-DSOC_PORT={soc_port}",
            f'-DBUILD_TS="{build_ts}"',
            "-o", out_exe,
            CPP_SRC,
            *MINGW_LIBS,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=120, cwd=tmpdir,
        )
        if result.returncode != 0:
            return jsonify({
                "success": False,
                "error": "Compilation failed",
                "stderr": result.stderr[-3000:],
            }), 500

        filename = f"soc_agent_{soc_host.replace('.', '_')}_{soc_port}.exe"
        return send_file(
            out_exe,
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=filename,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Compile timeout (>120s)"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        # cleanup on a delay so send_file can stream first
        import threading
        def _rm():
            time.sleep(5)
            shutil.rmtree(tmpdir, ignore_errors=True)
        threading.Thread(target=_rm, daemon=True).start()



# ══════════════════════════════════════════════════════════
#  SETTINGS
# ══════════════════════════════════════════════════════════

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.json')

def _load_settings():
    try:
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_settings(s):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(s, f, indent=2)

@app.route("/api/settings", methods=["GET"])
def settings_get():
    s = _load_settings()
    masked = {}
    for k, v in s.items():
        if k.endswith("_key") and v:
            masked[k] = v[:4] + "●●●●●●●●" + v[-2:] if len(v) > 6 else "●●●●●●"
        else:
            masked[k] = v
    return jsonify({"data": masked})

@app.route("/api/settings", methods=["POST"])
def settings_save():
    incoming = request.json or {}
    s = _load_settings()
    for field in ("virustotal_key", "abuseipdb_key", "shodan_key"):
        val = incoming.get(field, "")
        if val and not set(val) <= {"●"}:   # don't overwrite with masked value
            s[field] = val.strip()
        elif field in incoming and val == "":
            s[field] = ""
    _save_settings(s)
    return jsonify({"ok": True})

@app.route("/api/settings/test", methods=["POST"])
def settings_test():
    service = (request.json or {}).get("service")
    key     = (request.json or {}).get("key", "").strip()
    if not key:
        return jsonify({"ok": False, "message": "No key provided"})
    try:
        if service == "virustotal":
            r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                             headers={"x-apikey": key}, timeout=10)
            ok = r.status_code == 200
            return jsonify({"ok": ok, "message": "✓ Valid key" if ok else f"✗ HTTP {r.status_code}"})
        if service == "abuseipdb":
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             headers={"Key": key, "Accept": "application/json"},
                             params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1},
                             timeout=10)
            ok = r.status_code == 200
            return jsonify({"ok": ok, "message": "✓ Valid key" if ok else f"✗ HTTP {r.status_code}"})
        if service == "shodan":
            r = requests.get(f"https://api.shodan.io/api-info?key={key}", timeout=10)
            ok = r.status_code == 200
            msg = "✓ " + r.json().get("plan","Valid key") if ok else f"✗ HTTP {r.status_code}"
            return jsonify({"ok": ok, "message": msg})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)})
    return jsonify({"ok": False, "message": "Unknown service"})


# ══════════════════════════════════════════════════════════
#  THREAT INTEL  helpers
# ══════════════════════════════════════════════════════════

def _dns_resolve(domain, rtype, timeout=5):
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=timeout)
        if rtype == "MX":
            return sorted(
                [{"pref": int(str(r).split()[0]), "host": str(r).split()[1]} for r in answers],
                key=lambda x: x["pref"]
            )
        if rtype == "SOA":
            return str(list(answers)[0])
        return [str(r).strip('"') for r in answers]
    except dns.resolver.NXDOMAIN:
        return None
    except Exception:
        return []

def _spf_analyze(txt_records):
    for rec in (txt_records or []):
        r = rec.strip('"')
        if r.lower().startswith("v=spf1"):
            if "-all" in r:   pol, desc = "hardfail",   "Hard Fail (-all) — unauthorized senders rejected"
            elif "~all" in r: pol, desc = "softfail",   "Soft Fail (~all) — unauthorized marked as spam"
            elif "?all" in r: pol, desc = "neutral",    "Neutral (?all) — no enforcement"
            elif "+all" in r: pol, desc = "pass_all",   "DANGER: +all allows any server to send mail"
            else:             pol, desc = "incomplete", "No 'all' mechanism — policy incomplete"
            return {"found": True, "record": r, "policy": pol, "desc": desc}
    return {"found": False, "record": None, "policy": "missing", "desc": "No SPF record found"}

def _dmarc_analyze(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for r in answers:
            rec = str(r).strip('"')
            if "v=dmarc1" in rec.lower():
                parts = {p.strip().split("=", 1)[0].lower(): p.strip().split("=", 1)[1]
                         for p in rec.split(";") if "=" in p}
                pol  = parts.get("p", "none").lower()
                desc = {"none": "Monitor only — no enforcement",
                        "quarantine": "Quarantine — suspicious mail goes to spam",
                        "reject": "Reject — unauthorized mail blocked"}.get(pol, "Unknown policy")
                return {"found": True, "record": rec, "policy": pol, "desc": desc,
                        "rua": parts.get("rua"), "pct": parts.get("pct", "100")}
    except Exception:
        pass
    return {"found": False, "record": None, "policy": "missing", "desc": "No DMARC record found"}

def _ssl_check(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=6), server_hostname=domain
        ) as s:
            cert = s.getpeercert()
        subj   = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer",  []))
        not_after = cert.get("notAfter", "")
        days_left, expiry_str = None, not_after
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left  = (exp - datetime.utcnow()).days
                expiry_str = exp.strftime("%Y-%m-%d")
            except Exception:
                pass
        san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        return {"valid": True, "subject_cn": subj.get("commonName",""),
                "issuer_o": issuer.get("organizationName",""),
                "issuer_cn": issuer.get("commonName",""),
                "expiry": expiry_str, "days_left": days_left,
                "san": san[:12], "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": str(e), "days_left": None}
    except Exception as e:
        return {"valid": None, "error": str(e), "days_left": None}

def _whois_check(domain):
    try:
        w = _whois_lib.whois(domain)
        def _fmt(d):
            if isinstance(d, list): d = d[0]
            return d.strftime("%Y-%m-%d") if isinstance(d, datetime) else (str(d) if d else None)
        ns = w.name_servers or []
        return {"registrar": str(w.registrar) if w.registrar else None,
                "created": _fmt(w.creation_date), "expires": _fmt(w.expiration_date),
                "updated": _fmt(w.updated_date),
                "nameservers": [str(n).lower() for n in ns][:6],
                "status": ([str(s) for s in w.status] if isinstance(w.status, list)
                           else [str(w.status)] if w.status else []),
                "org": str(w.org) if hasattr(w, "org") and w.org else None}
    except Exception as e:
        return {"error": str(e)}

def _detect_ioc_type(ioc):
    if re.match(r'^[a-fA-F0-9]{64}$', ioc): return "sha256"
    if re.match(r'^[a-fA-F0-9]{40}$', ioc): return "sha1"
    if re.match(r'^[a-fA-F0-9]{32}$', ioc): return "md5"
    try: ipaddress.ip_address(ioc); return "ip"
    except Exception: pass
    if re.match(r'^https?://', ioc): return "url"
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', ioc):
        return "domain"
    return "unknown"

def _urlhaus_check(ioc, ioc_type):
    try:
        if ioc_type == "url":
            r = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                              data={"url": ioc}, timeout=8)
        elif ioc_type in ("domain", "ip"):
            r = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                              data={"host": ioc}, timeout=8)
        elif ioc_type in ("md5", "sha256"):
            r = requests.post("https://urlhaus-api.abuse.ch/v1/payload/",
                              data={ioc_type + "_hash": ioc}, timeout=8)
        else:
            return {"query_status": "not_checked"}
        return r.json()
    except Exception as e:
        return {"query_status": "error", "error": str(e)}

def _shodan_internetdb(ip):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
        return r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def _shodan_full(ip, key):
    if not key:
        return None
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}", timeout=12)
        if r.status_code == 401: return {"error": "invalid_key"}
        if r.status_code == 404: return {"error": "not_found"}
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def _ipapi_check(ip):
    try:
        fields = "status,message,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting,mobile,query"
        r = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=8)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def _virustotal_check(ioc, ioc_type, key):
    if not key:
        return {"error": "no_key"}
    headers = {"x-apikey": key, "Accept": "application/json"}
    try:
        if ioc_type == "ip":
            r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
                             headers=headers, timeout=12)
        elif ioc_type == "domain":
            r = requests.get(f"https://www.virustotal.com/api/v3/domains/{ioc}",
                             headers=headers, timeout=12)
        elif ioc_type == "url":
            uid = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
                             headers=headers, timeout=12)
        elif ioc_type in ("md5", "sha1", "sha256"):
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{ioc}",
                             headers=headers, timeout=12)
        else:
            return {"error": "unsupported_type"}
        if r.status_code == 401: return {"error": "invalid_key"}
        if r.status_code == 404: return {"error": "not_found"}
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def _abuseipdb_check(ip, key):
    if not key:
        return {"error": "no_key"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if r.status_code == 401: return {"error": "invalid_key"}
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def _crtsh_check(domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                         headers={"User-Agent": "SOC-Assistant"}, timeout=12)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        certs = r.json()
        seen, names = set(), []
        for c in certs:
            for n in c.get("common_name","").split("\n"):
                n = n.strip().lower()
                if n and n not in seen:
                    seen.add(n)
                    names.append({"name": n,
                                  "issuer": c.get("issuer_name","")[:60],
                                  "logged": (c.get("entry_timestamp") or "")[:10]})
        names.sort(key=lambda x: x["logged"], reverse=True)
        dates = [c.get("not_before","") for c in certs if c.get("not_before")]
        return {"total_certs": len(certs), "unique_names": len(names),
                "names": names[:40],
                "first_seen": min(dates)[:10] if dates else None,
                "last_seen":  max(dates)[:10] if dates else None}
    except Exception as e:
        return {"error": str(e)}

def _rbl_check(ip):
    """DNS-based blacklist check (MXToolbox equivalent)"""
    try:
        octets = ip.split(".")
        if len(octets) != 4: return {"error": "invalid_ip"}
        rev = ".".join(reversed(octets))
    except Exception:
        return {"error": "invalid_ip"}
    rbls = [
        ("zen.spamhaus.org",        "Spamhaus ZEN"),
        ("sbl.spamhaus.org",        "Spamhaus SBL"),
        ("xbl.spamhaus.org",        "Spamhaus XBL"),
        ("pbl.spamhaus.org",        "Spamhaus PBL"),
        ("bl.spamcop.net",          "SpamCop"),
        ("dnsbl.sorbs.net",         "SORBS"),
        ("spam.dnsbl.sorbs.net",    "SORBS SPAM"),
        ("b.barracudacentral.org",  "Barracuda"),
        ("dnsbl-1.uceprotect.net",  "UCEPROTECT L1"),
        ("cbl.abuseat.org",         "CBL"),
        ("dnsbl.abuse.ch",          "abuse.ch DNSBL"),
    ]
    listed, checked = [], 0
    for zone, name in rbls:
        try:
            dns.resolver.resolve(f"{rev}.{zone}", "A", lifetime=3)
            listed.append(name)
            checked += 1
        except dns.resolver.NXDOMAIN:
            checked += 1
        except Exception:
            pass
    return {"listed": listed, "listed_count": len(listed),
            "checked": checked, "clean_count": checked - len(listed)}

def _ai_json(prompt, max_tokens=600):
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens, temperature=0.15,
        )
        raw = resp.choices[0].message.content.strip()
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        return json.loads(m.group()) if m else {"summary": raw}
    except Exception as e:
        return {"error": str(e)}


# ── /api/ti/domain ────────────────────────────────────────
@app.route("/api/ti/domain", methods=["POST"])
def ti_domain():
    raw = (request.json or {}).get("domain", "").strip()
    if not raw:
        return jsonify({"error": "domain required"}), 400
    domain = re.sub(r'^https?://', '', raw).split('/')[0].lower()

    dns_data = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        dns_data[rtype] = _dns_resolve(domain, rtype)

    txt = dns_data.get("TXT") or []
    spf   = _spf_analyze(txt)
    dmarc = _dmarc_analyze(domain)

    dkim_found = []
    for sel in ["default","google","mail","dkim","k1","s1","s2","selector1","selector2"]:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=3)
            dkim_found.append(sel)
        except Exception:
            pass

    ssl_info   = _ssl_check(domain)
    whois_info = _whois_check(domain)
    crt_info   = _crtsh_check(domain)

    settings = _load_settings()
    vt_key   = settings.get("virustotal_key","")
    vt_info  = _virustotal_check(domain, "domain", vt_key) if vt_key else {"error": "no_key"}

    data = {"domain": domain, "dns": dns_data, "spf": spf, "dmarc": dmarc,
            "dkim_selectors": dkim_found, "ssl": ssl_info, "whois": whois_info,
            "crt": crt_info, "virustotal": vt_info}

    data["ai"] = _ai_json(
        f"""SOC domain intelligence (respond with compact single-line JSON only, no markdown):

Domain: {domain}
A records: {dns_data.get('A')}  NS: {dns_data.get('NS')}
SPF:   {spf['policy']} — {spf['desc']}
DMARC: {dmarc['policy']} — {dmarc['desc']}
DKIM selectors found: {dkim_found or 'none'}
SSL: {'valid, expires in ' + str(ssl_info.get('days_left','?')) + ' days' if ssl_info.get('valid') else 'INVALID — ' + str(ssl_info.get('error',''))}
WHOIS: registrar={whois_info.get('registrar','?')}, created={whois_info.get('created','?')}, expires={whois_info.get('expires','?')}
Cert Transparency: {crt_info.get('unique_names',0)} unique names seen, first seen {crt_info.get('first_seen','?')}

Return JSON: {{"risk":"LOW","summary":"2-3 sentences","email_security":"brief","concerns":["..."],"actions":["..."]}}"""
    )
    return jsonify({"data": data})


# ── /api/ti/mail ──────────────────────────────────────────
@app.route("/api/ti/mail", methods=["POST"])
def ti_mail():
    email = (request.json or {}).get("email", "").strip()
    if not email:
        return jsonify({"error": "email required"}), 400

    valid_fmt = bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email))
    if not valid_fmt:
        return jsonify({"data": {"email": email, "valid_format": False,
                                 "error": "Invalid email format"}})

    local, domain = email.rsplit("@", 1)
    domain = domain.lower()

    mx  = _dns_resolve(domain, "MX") or []
    txt = _dns_resolve(domain, "TXT") or []
    a   = _dns_resolve(domain, "A")  or []
    spf   = _spf_analyze(txt)
    dmarc = _dmarc_analyze(domain)

    disposable = {
        "mailinator.com","guerrillamail.com","tempmail.com","yopmail.com",
        "trashmail.com","trashmail.me","dispostable.com","getairmail.com",
        "maildrop.cc","throwam.com","getnada.com","spam4.me","fakeinbox.com",
        "discard.email","tempr.email","mohmal.com","sharklasers.com",
    }
    free_providers = {
        "gmail.com","yahoo.com","hotmail.com","outlook.com","live.com",
        "icloud.com","protonmail.com","proton.me","tutanota.com","aol.com",
        "msn.com","yandex.com","mail.ru","zoho.com","fastmail.com",
    }

    data = {"email": email, "local": local, "domain": domain,
            "valid_format": True, "mx_records": mx, "mx_exists": len(mx) > 0,
            "a_records": a, "spf": spf, "dmarc": dmarc,
            "is_disposable": domain in disposable,
            "is_free_provider": domain in free_providers}

    data["ai"] = _ai_json(
        f"""SOC email security (compact single-line JSON only, no markdown):

Email: {email}  Domain: {domain}
MX: {mx or 'NONE'}  SPF: {spf['policy']}  DMARC: {dmarc['policy']}
Disposable: {data['is_disposable']}  Free provider: {data['is_free_provider']}

Return JSON: {{"risk":"LOW","verdict":"one sentence","spoofing_risk":"LOW","phishing_risk":"LOW","notes":["note1","note2"]}}"""
    )
    return jsonify({"data": data})


# ── /api/ti/ioc ───────────────────────────────────────────
@app.route("/api/ti/ioc", methods=["POST"])
def ti_ioc():
    ioc = (request.json or {}).get("ioc", "").strip()
    if not ioc:
        return jsonify({"error": "ioc required"}), 400

    ioc_type = _detect_ioc_type(ioc)
    settings = _load_settings()
    vt_key   = settings.get("virustotal_key","")
    ab_key   = settings.get("abuseipdb_key","")
    sh_key   = settings.get("shodan_key","")

    data = {"ioc": ioc, "type": ioc_type, "sources": {}}

    if ioc_type == "ip":
        data["sources"]["urlhaus"]  = _urlhaus_check(ioc, "ip")
        data["sources"]["abuseipdb"]= _abuseipdb_check(ioc, ab_key)
        data["sources"]["virustotal"]= _virustotal_check(ioc, "ip", vt_key)
        # Shodan: full API if key, else InternetDB
        sh = _shodan_full(ioc, sh_key)
        data["sources"]["shodan"]   = sh if sh is not None else _shodan_internetdb(ioc)
        data["sources"]["ipapi"]    = _ipapi_check(ioc)
        data["sources"]["rbl"]      = _rbl_check(ioc)
        try:    data["rdns"] = socket.gethostbyaddr(ioc)[0]
        except: data["rdns"] = None

    elif ioc_type == "domain":
        data["sources"]["urlhaus"]   = _urlhaus_check(ioc, "domain")
        data["sources"]["virustotal"]= _virustotal_check(ioc, "domain", vt_key)
        data["sources"]["crt"]       = _crtsh_check(ioc)
        data["dns"]   = {k: _dns_resolve(ioc, k) for k in ["A","MX","NS","TXT"]}
        data["whois"] = _whois_check(ioc)

    elif ioc_type == "url":
        data["sources"]["urlhaus"]   = _urlhaus_check(ioc, "url")
        data["sources"]["virustotal"]= _virustotal_check(ioc, "url", vt_key)
        m = re.match(r'^https?://([^/:]+)', ioc)
        if m:
            h = m.group(1)
            data["dns"] = {"A": _dns_resolve(h, "A")}
            try:    ipaddress.ip_address(h)
            except: data["whois"] = _whois_check(h)

    elif ioc_type in ("md5", "sha256", "sha1"):
        data["sources"]["urlhaus"]   = _urlhaus_check(ioc, ioc_type)
        data["sources"]["virustotal"]= _virustotal_check(ioc, ioc_type, vt_key)

    src_sum = json.dumps(data.get("sources", {}), default=str)[:2000]
    dns_sum = json.dumps(data.get("dns", {}), default=str)[:400] if "dns" in data else ""

    data["ai"] = _ai_json(
        f"""SOC threat intel IOC (compact single-line JSON only, no markdown):

IOC: {ioc}  Type: {ioc_type}
Sources: {src_sum}
DNS: {dns_sum}

Return JSON: {{"verdict":"CLEAN|SUSPICIOUS|MALICIOUS","confidence":"LOW|MEDIUM|HIGH","summary":"2 sentences","threat_context":"brief","actions":["..."],"tags":["phishing","c2","scanner"]}}"""
    )
    return jsonify({"data": data})


# ══════════════════════════════════════════════════════════════
#  INSIDER THREAT DETECTION
# ══════════════════════════════════════════════════════════════

INSIDER_FILE = os.path.join(os.path.dirname(__file__), "insider_data.json")


def _insider_load():
    try:
        with open(INSIDER_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _insider_save(data):
    try:
        with open(INSIDER_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _spl_count(spl):
    try:
        rows = splunk_run(spl, max_results=1)['rows']
        if not rows:
            return 0
        row = rows[0]
        for k in ('count', 'unique_files', 'dc(Object_Name)'):
            if k in row:
                return int(float(row[k]))
        return len(rows)
    except Exception:
        return 0


def _insider_analyze_user(username, days=30):
    since = f"-{days}d"
    u = re.sub(r'["\'\\\n]', '', username)

    def cnt(spl):
        return _spl_count(spl)

    # Most frequent workstation for this user
    try:
        rows = splunk_run(
            f'index=wineventlog EventCode=4624 Account_Name="{u}" earliest={since}'
            f' | stats count by Workstation_Name | sort -count | head 1',
            max_results=1)['rows']
        machine = (rows[0].get('Workstation_Name') or '').strip() if rows else ''
        machine = machine if machine not in ('', '-', 'N/A', 'NULL') else ''
    except Exception:
        machine = ''

    off = cnt(f'index=wineventlog EventCode=4624 Account_Name="{u}" earliest={since} | eval h=tonumber(strftime(_time,"%H")) | where h<7 OR h>=22 | stats count')
    fail = cnt(f'index=wineventlog EventCode=4625 Account_Name="{u}" earliest={since} | stats count')

    try:
        rows = splunk_run(f'index=wineventlog EventCode=4663 Subject_Account_Name="{u}" earliest={since} | stats dc(Object_Name) as unique_files', max_results=1)['rows']
        file_cnt = int(float(rows[0].get('unique_files', 0))) if rows else 0
    except Exception:
        file_cnt = 0

    usb   = cnt(f'index=wineventlog (EventCode=6416 OR EventCode=20001 OR EventCode=6423) Account_Name="{u}" earliest={since} | stats count')
    arc   = cnt(f'index=wineventlog EventCode=4688 Account_Name="{u}" earliest={since} (Process_Command_Line="*zip*" OR Process_Command_Line="*7z*" OR Process_Command_Line="*rar*" OR Process_Command_Line="*tar*") | stats count')
    priv  = cnt(f'index=wineventlog EventCode=4672 Account_Name="{u}" earliest={since} | stats count')
    exfil = cnt(f'index=wineventlog EventCode=4688 Account_Name="{u}" earliest={since} (New_Process_Name="*git.exe*" OR New_Process_Name="*scp*" OR New_Process_Name="*winscp*" OR Process_Command_Line="*wget*" OR Process_Command_Line="*curl*") | stats count')
    proc  = cnt(f'index=wineventlog EventCode=4688 Account_Name="{u}" earliest={since} (New_Process_Name="*psexec*" OR New_Process_Name="*mimikatz*" OR New_Process_Name="*procdump*" OR Process_Command_Line="* -enc *" OR Process_Command_Line="*IEX(*" OR Process_Command_Line="*bypass*") | stats count')

    def sev(val, lo, hi):
        if val == 0:   return 'NONE'
        if val < lo:   return 'LOW'
        if val < hi:   return 'MEDIUM'
        return 'HIGH'

    findings = {
        'off_hours':     {'count': off,      'label': 'Off-hours logins',             'sev': sev(off,      3,  15)},
        'failed_logins': {'count': fail,     'label': 'Failed login attempts',        'sev': sev(fail,     5,  20)},
        'file_access':   {'count': file_cnt, 'label': 'Unique files accessed',        'sev': sev(file_cnt, 100, 500)},
        'usb_activity':  {'count': usb,      'label': 'USB / removable media events', 'sev': sev(usb,      1,   5)},
        'archive':       {'count': arc,      'label': 'Archive / compression cmds',   'sev': sev(arc,      2,  10)},
        'privilege_use': {'count': priv,     'label': 'Privileged logon events',      'sev': sev(priv,     10, 50)},
        'exfil_tools':   {'count': exfil,    'label': 'Exfil / data transfer tools',  'sev': sev(exfil,    1,   5)},
        'abnormal_proc': {'count': proc,     'label': 'Suspicious process execution', 'sev': sev(proc,     1,   3)},
    }

    SEV_PTS = {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
    W = {'abnormal_proc': 3.0, 'exfil_tools': 2.5, 'usb_activity': 2.0,
         'archive': 1.5, 'file_access': 1.5, 'off_hours': 1.2,
         'failed_logins': 1.0, 'privilege_use': 0.8}
    raw   = sum(SEV_PTS[findings[k]['sev']] * W[k] for k in W)
    max_r = sum(3 * w for w in W.values())
    score = int(round(raw / max_r * 100))

    if   score >= 70: risk = 'CRITICAL'
    elif score >= 45: risk = 'HIGH'
    elif score >= 20: risk = 'MEDIUM'
    elif score >  0:  risk = 'LOW'
    else:             risk = 'CLEAN'

    return {
        'username':    username,
        'machine':     machine,
        'risk':        risk,
        'score':       score,
        'findings':    findings,
        'analyzed_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'days':        days,
    }


def _insider_ai(result):
    active = {k: v for k, v in result['findings'].items() if v['count'] > 0}
    ftxt = '\n'.join(f"- {v['label']}: {v['count']} events ({v['sev']})" for v in active.values()) \
           if active else 'No significant activity detected.'
    prompt = f"""SOC insider threat assessment. Compact JSON only, no markdown.

User: {result['username']}  Score: {result['score']}/100  Risk: {result['risk']}
Window: last {result['days']} days

Findings:
{ftxt}

Return JSON: {{"summary":"2-sentence executive summary","key_concerns":["up to 3 specific concerns, empty if none"],"likely_cause":"benign or malicious explanation in 1 sentence","recommended_actions":["1-3 concrete SOC actions"],"confidence":"low|medium|high"}}"""
    return _ai_json(prompt, max_tokens=400)


@app.route("/api/insider/users", methods=["GET"])
def insider_users():
    try:
        spl = r'''index=wineventlog (EventCode=4624 OR EventCode=4688) earliest=-30d
| stats count by Account_Name, Workstation_Name
| where Account_Name!="" AND Account_Name!="-" AND Account_Name!="SYSTEM"
  AND NOT match(Account_Name,"\$$") AND NOT match(Account_Name,"^ANONYMOUS")
  AND NOT match(Account_Name,"^DWM-") AND NOT match(Account_Name,"^UMFD-")
  AND NOT match(Account_Name,"^MSSQL") AND Account_Name!="LOCAL SERVICE"
  AND Account_Name!="NETWORK SERVICE"
| stats sum(count) as total, values(Workstation_Name) as machines by Account_Name
| sort -total | head 50'''
        rows = splunk_run(spl, max_results=50)['rows']
        users = []
        for r in rows:
            name = r.get('Account_Name', '').strip()
            if not name:
                continue
            raw_machine = r.get('machines') or r.get('Workstation_Name') or ''
            if isinstance(raw_machine, list):
                raw_machine = raw_machine[0] if raw_machine else ''
            machine = str(raw_machine).strip()
            if machine in ('', '-', 'N/A', 'NULL', 'null'):
                machine = ''
            users.append({'username': name, 'machine': machine})
        return jsonify({'success': True, 'data': users})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/api/insider/analyze", methods=["POST"])
def insider_analyze_route():
    data     = request.json or {}
    username = data.get('username', '').strip()
    days     = max(1, min(90, int(data.get('days', 30))))
    if not username:
        return jsonify({'success': False, 'error': 'username required'}), 400
    try:
        result       = _insider_analyze_user(username, days)
        result['ai'] = _insider_ai(result)
        store        = _insider_load()
        store[username] = result
        _insider_save(store)
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/api/insider/list", methods=["GET"])
def insider_list_route():
    return jsonify({'success': True, 'data': list(_insider_load().values())})


@app.route("/api/insider/delete", methods=["POST"])
def insider_delete_route():
    username = (request.json or {}).get('username', '').strip()
    store = _insider_load()
    store.pop(username, None)
    _insider_save(store)
    return jsonify({'success': True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
