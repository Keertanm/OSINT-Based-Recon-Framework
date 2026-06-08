#!/usr/bin/env python3
import subprocess
import threading
import webbrowser
import os
import json
import re
import queue
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

output_queue = queue.Queue()
scan_running = False
last_domain = ""
spiderfoot_process = None
spiderfoot_running = False

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>OSINT Recon Framework</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Syne:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e13;--surface:#111820;--border:#1e2d3d;
  --accent:#00d4ff;--accent2:#ff6b35;--green:#00ff9d;
  --red:#ff3b5c;--amber:#ffaa00;--text:#c9d8e8;--muted:#4a6280;
  --purple:#aa44ff;
  --font:'Syne',sans-serif;--mono:'JetBrains Mono',monospace
}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;padding:24px;min-height:100vh}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;padding-bottom:18px;border-bottom:1px solid var(--border)}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#0066ff);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px}
.logo-text{font-size:20px;font-weight:700;letter-spacing:-0.5px}
.logo-sub{font-size:11px;color:var(--muted);letter-spacing:1px;text-transform:uppercase;margin-top:2px}
.header-right{display:flex;align-items:center;gap:10px}
.status-badge{display:flex;align-items:center;gap:6px;font-size:12px;font-family:var(--mono);color:var(--green);background:rgba(0,255,157,0.08);border:1px solid rgba(0,255,157,0.2);padding:5px 14px;border-radius:20px}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
.dot.purple{background:var(--purple)}
.dot.off{background:var(--muted);animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
.domain-bar{display:flex;gap:10px;margin-bottom:8px}
.domain-input{flex:1;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:11px 16px;font-family:var(--mono);font-size:13px;color:var(--text);outline:none;transition:border-color 0.2s}
.domain-input:focus{border-color:var(--accent)}
.btn{padding:11px 22px;border-radius:8px;border:none;font-family:var(--font);font-weight:600;font-size:13px;cursor:pointer;letter-spacing:0.3px;transition:all 0.2s;white-space:nowrap}
.btn-primary{background:var(--accent);color:#000}
.btn-primary:hover{background:#00bbdd}
.btn-primary:disabled{opacity:0.4;cursor:not-allowed}
.btn-report{background:var(--accent2);color:#fff}
.btn-report:hover{background:#e05a28}
.btn-report:disabled{opacity:0.4;cursor:not-allowed}
.btn-spiderfoot{background:var(--purple);color:#fff}
.btn-spiderfoot:hover{background:#8833dd}
.btn-spiderfoot.running{background:rgba(170,68,255,0.15);color:var(--purple);border:1px solid var(--purple)}
.btn-spiderfoot:disabled{opacity:0.4;cursor:not-allowed}
.btn-stop{background:var(--red);color:#fff;font-size:12px;padding:11px 16px}
.btn-stop:hover{background:#cc2244}
.progress-bar{height:3px;background:var(--border);border-radius:2px;margin-bottom:20px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),#0066ff);border-radius:2px;width:0%;transition:width 0.4s}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:12px}
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:12px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px}
.card-label{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:10px}
.card-value{font-size:30px;font-weight:700;font-family:var(--mono)}
.card-value.blue{color:var(--accent)}
.card-value.amber{color:var(--amber)}
.card-value.red{color:var(--red)}
.card-value.green{color:var(--green)}
.card-sub{font-size:11px;color:var(--muted);margin-top:5px}
.terminal{background:#060a0f;border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:12px}
.terminal-bar{display:flex;align-items:center;gap:6px;padding:10px 14px;background:var(--surface);border-bottom:1px solid var(--border)}
.t-dot{width:10px;height:10px;border-radius:50%}
.terminal-title{margin-left:8px;font-size:11px;color:var(--muted);font-family:var(--mono);flex:1}
.sf-status{font-size:10px;font-family:var(--mono);padding:2px 8px;border-radius:10px}
.sf-status.on{color:var(--purple);background:rgba(170,68,255,0.12);border:1px solid rgba(170,68,255,0.3)}
.sf-status.off{color:var(--muted);background:rgba(74,98,128,0.12);border:1px solid rgba(74,98,128,0.2)}
.terminal-body{padding:14px;font-family:var(--mono);font-size:12px;line-height:1.9;max-height:220px;overflow-y:auto}
.t-ok{color:var(--green)}
.t-info{color:var(--accent)}
.t-warn{color:var(--amber)}
.t-err{color:var(--red)}
.t-muted{color:var(--muted)}
.t-sf{color:var(--purple)}
.findings{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:12px}
.findings-header{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--border)}
.findings-title{font-size:13px;font-weight:600;letter-spacing:0.3px}
.finding-row{display:flex;align-items:center;gap:12px;padding:11px 16px;border-bottom:1px solid var(--border)}
.finding-row:last-child{border-bottom:none}
.sev{font-size:10px;font-weight:600;padding:3px 8px;border-radius:4px;font-family:var(--mono);min-width:70px;text-align:center}
.sev.critical{background:rgba(255,59,92,0.12);color:var(--red);border:1px solid rgba(255,59,92,0.25)}
.sev.high{background:rgba(255,170,0,0.1);color:var(--amber);border:1px solid rgba(255,170,0,0.22)}
.sev.medium{background:rgba(0,212,255,0.08);color:var(--accent);border:1px solid rgba(0,212,255,0.18)}
.finding-name{flex:1;font-size:13px}
.finding-count{font-family:var(--mono);font-size:12px;color:var(--muted)}
.empty-state{color:var(--muted);font-size:13px;padding:20px 16px;font-family:var(--mono)}
.tools-bar{display:flex;gap:10px;margin-bottom:12px;align-items:center}
.tools-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;white-space:nowrap}
</style>
</head>
<body>

<div class="header">
  <div class="logo">
    <div class="logo-icon">⬡</div>
    <div>
      <div class="logo-text">OSINT Recon Framework</div>
      <div class="logo-sub">VAPT Laboratory &middot; 23CYL65 &middot; MSRIT</div>
    </div>
  </div>
  <div class="header-right">
    <div class="status-badge" id="sfBadge" style="color:var(--muted);background:rgba(74,98,128,0.08);border-color:rgba(74,98,128,0.2)">
      <span class="dot off" id="sfDot"></span>
      <span id="sfBadgeText">SpiderFoot: off</span>
    </div>
    <div class="status-badge"><span class="dot"></span>localhost:8080</div>
  </div>
</div>

<div class="domain-bar">
  <input class="domain-input" id="domainInput" placeholder="Enter target domain (e.g. msrit.edu)" value=""/>
  <button class="btn btn-primary" id="scanBtn" onclick="startScan()">&#9654; Run Scan</button>
  <button class="btn btn-report" id="reportBtn" disabled onclick="openReport()">&#10697; Open Report</button>
</div>

<div class="tools-bar">
  <span class="tools-label">Tools:</span>
  <button class="btn btn-spiderfoot" id="sfBtn" onclick="toggleSpiderFoot()">&#9189; Launch SpiderFoot</button>
  <button class="btn btn-stop" id="sfStopBtn" style="display:none" onclick="stopSpiderFoot()">&#9632; Stop SpiderFoot</button>
  <span style="font-size:11px;color:var(--muted);font-family:var(--mono)" id="sfNote">Starts web UI at http://127.0.0.1:5001</span>
</div>

<div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>

<div class="grid-3">
  <div class="card">
    <div class="card-label">IPs Discovered</div>
    <div class="card-value blue" id="v-ips">—</div>
    <div class="card-sub">DNSRecon + theHarvester</div>
  </div>
  <div class="card">
    <div class="card-label">Emails Found</div>
    <div class="card-value amber" id="v-emails">—</div>
    <div class="card-sub">theHarvester sources</div>
  </div>
  <div class="card">
    <div class="card-label">Open Ports</div>
    <div class="card-value red" id="v-ports">—</div>
    <div class="card-sub">Shodan API</div>
  </div>
</div>

<div class="grid-2">
  <div class="card">
    <div class="card-label">Subdomains</div>
    <div class="card-value green" id="v-subs">—</div>
    <div class="card-sub" id="v-subs-detail">awaiting scan</div>
  </div>
  <div class="card">
    <div class="card-label">Interesting URLs</div>
    <div class="card-value blue" id="v-urls">—</div>
    <div class="card-sub">urlscan + rapiddns</div>
  </div>
</div>

<div class="terminal">
  <div class="terminal-bar">
    <div class="t-dot" style="background:#ff5f56"></div>
    <div class="t-dot" style="background:#ffbd2e"></div>
    <div class="t-dot" style="background:#27c93f"></div>
    <span class="terminal-title">python main.py</span>
    <span class="sf-status off" id="sfTermStatus">SpiderFoot: stopped</span>
  </div>
  <div class="terminal-body" id="terminalBody">
    <span class="t-muted">Waiting for scan...</span>
  </div>
</div>

<div class="findings">
  <div class="findings-header">
    <div class="findings-title">Key Findings</div>
    <span style="font-size:11px;color:var(--muted);font-family:var(--mono)" id="scanMeta">No scan run yet</span>
  </div>
  <div id="findingsBody"><div class="empty-state">Run a scan to see findings.</div></div>
</div>

<script>
let pollInterval = null;
let lastLine = 0;
let currentDomain = '';
let sfRunning = false;
let sfPollInterval = null;

function startScan() {
  const domain = document.getElementById('domainInput').value.trim();
  if (!domain) { alert('Enter a target domain first.'); return; }
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9\-\.]+[a-zA-Z0-9]$/;
  if (!domainRegex.test(domain)) { alert('Invalid domain format.'); return; }

  currentDomain = domain;
  lastLine = 0;
  document.getElementById('terminalBody').innerHTML = '';
  document.getElementById('findingsBody').innerHTML = '<div class="empty-state">Scanning...</div>';
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('reportBtn').disabled = true;
  document.getElementById('progressFill').style.width = '5%';
  ['v-ips','v-emails','v-ports','v-subs','v-urls'].forEach(id => document.getElementById(id).textContent = '...');

  fetch('/scan', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({domain})
  });

  pollInterval = setInterval(pollOutput, 800);
}

function pollOutput() {
  fetch(`/output?from=${lastLine}`)
    .then(r => r.json())
    .then(data => {
      const tb = document.getElementById('terminalBody');
      data.lines.forEach(line => {
        const d = document.createElement('div');
        d.textContent = line.text;
        if (line.text.includes('[+]') && line.text.includes('completed')) d.className = 't-ok';
        else if (line.text.includes('[-]') || line.text.includes('ERROR')) d.className = 't-err';
        else if (line.text.includes('[+]')) d.className = 't-info';
        else if (line.text.includes('✓') || line.text.includes('🎉')) d.className = 't-ok';
        else d.className = 't-muted';
        tb.appendChild(d);
        tb.scrollTop = tb.scrollHeight;
      });
      lastLine += data.lines.length;
      const pct = Math.min(5 + (lastLine * 4), 95);
      document.getElementById('progressFill').style.width = pct + '%';
      if (data.done) {
        clearInterval(pollInterval);
        document.getElementById('progressFill').style.width = '100%';
        document.getElementById('scanBtn').disabled = false;
        loadReport(currentDomain);
        setTimeout(() => document.getElementById('progressFill').style.width = '0%', 1500);
      }
    });
}

function loadReport(domain) {
  fetch(`/report-data?domain=${encodeURIComponent(domain)}`)
    .then(r => r.json())
    .then(data => {
      if (data.error) return;
      const findings = data.findings || [];
      let ips = 0, emails = 0, ports = 0, subs = 0, urls = 0, subNames = [];
      findings.forEach(f => {
        if (f.type.includes('IP')) ips = f.count;
        if (f.type.includes('Email')) emails = f.count;
        if (f.type.includes('Port')) ports = f.count;
        if (f.type.includes('Subdomain')) { subs = f.count; subNames = f.details || []; }
        if (f.type.includes('URL')) urls = f.count;
      });
      document.getElementById('v-ips').textContent = ips || '0';
      document.getElementById('v-emails').textContent = emails || '0';
      document.getElementById('v-ports').textContent = ports || '0';
      document.getElementById('v-subs').textContent = subs || '0';
      document.getElementById('v-urls').textContent = urls || '0';
      if (subNames.length) document.getElementById('v-subs-detail').textContent = subNames.slice(0,3).join(' · ');
      document.getElementById('scanMeta').textContent = `Last scan: ${domain} · ${new Date().toLocaleTimeString()}`;
      const sevMap = {Critical:'critical', High:'high', Medium:'medium'};
      const fb = document.getElementById('findingsBody');
      if (!findings.length) { fb.innerHTML = '<div class="empty-state">No findings.</div>'; return; }
      fb.innerHTML = findings.map(f => `
        <div class="finding-row">
          <span class="sev ${(sevMap[f.severity]||'medium')}">${f.severity.toUpperCase()}</span>
          <span class="finding-name">${f.type}</span>
          <span class="finding-count">${f.count} found</span>
        </div>`).join('');
      document.getElementById('reportBtn').disabled = false;
    });
}

function openReport() {
  fetch(`/open-report?domain=${encodeURIComponent(currentDomain)}`)
    .then(r => r.json())
    .then(data => { if (!data.ok) alert('Report not found. Run a scan first.'); });
}

function toggleSpiderFoot() {
  if (sfRunning) {
    window.open('http://127.0.0.1:5001', '_blank');
    return;
  }
  document.getElementById('sfBtn').disabled = true;
  document.getElementById('sfNote').textContent = 'Starting SpiderFoot...';
  addTerminalLine('t-sf', '[+] Starting SpiderFoot web UI on port 5001...');

  fetch('/start-spiderfoot', { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      if (data.ok) {
        sfPollInterval = setInterval(checkSpiderFoot, 1500);
      } else {
        document.getElementById('sfBtn').disabled = false;
        document.getElementById('sfNote').textContent = data.error || 'Failed to start SpiderFoot';
        addTerminalLine('t-err', '[-] SpiderFoot failed to start: ' + (data.error || 'unknown error'));
      }
    });
}

function checkSpiderFoot() {
  fetch('/spiderfoot-status')
    .then(r => r.json())
    .then(data => {
      if (data.running) {
        clearInterval(sfPollInterval);
        sfRunning = true;
        setSfRunning(true);
        addTerminalLine('t-sf', '[+] SpiderFoot is running → http://127.0.0.1:5001');
        setTimeout(() => window.open('http://127.0.0.1:5001', '_blank'), 500);
      } else if (data.failed) {
        clearInterval(sfPollInterval);
        document.getElementById('sfBtn').disabled = false;
        document.getElementById('sfNote').textContent = 'SpiderFoot failed — check spiderfoot/ directory exists';
        addTerminalLine('t-err', '[-] SpiderFoot failed to start');
      }
    });
}

function stopSpiderFoot() {
  fetch('/stop-spiderfoot', { method: 'POST' })
    .then(r => r.json())
    .then(() => {
      sfRunning = false;
      setSfRunning(false);
      addTerminalLine('t-sf', '[+] SpiderFoot stopped');
    });
}

function setSfRunning(running) {
  const btn = document.getElementById('sfBtn');
  const stopBtn = document.getElementById('sfStopBtn');
  const badge = document.getElementById('sfBadge');
  const dot = document.getElementById('sfDot');
  const badgeText = document.getElementById('sfBadgeText');
  const termStatus = document.getElementById('sfTermStatus');
  const note = document.getElementById('sfNote');

  btn.disabled = false;
  if (running) {
    btn.textContent = '⬡ Open SpiderFoot';
    btn.className = 'btn btn-spiderfoot running';
    stopBtn.style.display = 'inline-block';
    badge.style.color = 'var(--purple)';
    badge.style.background = 'rgba(170,68,255,0.08)';
    badge.style.borderColor = 'rgba(170,68,255,0.25)';
    dot.className = 'dot purple';
    badgeText.textContent = 'SpiderFoot: running';
    termStatus.textContent = 'SpiderFoot: running';
    termStatus.className = 'sf-status on';
    note.textContent = 'Click to open SpiderFoot UI at http://127.0.0.1:5001';
  } else {
    btn.textContent = '⬡ Launch SpiderFoot';
    btn.className = 'btn btn-spiderfoot';
    stopBtn.style.display = 'none';
    badge.style.color = 'var(--muted)';
    badge.style.background = 'rgba(74,98,128,0.08)';
    badge.style.borderColor = 'rgba(74,98,128,0.2)';
    dot.className = 'dot off';
    badgeText.textContent = 'SpiderFoot: off';
    termStatus.textContent = 'SpiderFoot: stopped';
    termStatus.className = 'sf-status off';
    note.textContent = 'Starts web UI at http://127.0.0.1:5001';
  }
}

function addTerminalLine(cls, text) {
  const tb = document.getElementById('terminalBody');
  const d = document.createElement('div');
  d.className = cls;
  d.textContent = text;
  tb.appendChild(d);
  tb.scrollTop = tb.scrollHeight;
}
</script>
</body>
</html>
"""

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode())

        elif self.path.startswith('/output'):
            params = parse_qs(urlparse(self.path).query)
            from_idx = int(params.get('from', ['0'])[0])
            temp = []
            while not output_queue.empty():
                try:
                    temp.append(output_queue.get_nowait())
                except:
                    break
            all_lines = getattr(self.server, '_lines', [])
            all_lines.extend(temp)
            self.server._lines = all_lines
            new_lines = all_lines[from_idx:]
            self.send_json({'lines': [{'text': l} for l in new_lines], 'done': not scan_running and from_idx >= len(all_lines) and len(all_lines) > 0})

        elif self.path.startswith('/report-data'):
            params = parse_qs(urlparse(self.path).query)
            domain = params.get('domain', [''])[0]
            report_path = f"reports/{domain}_report.json"
            if os.path.exists(report_path):
                with open(report_path) as f:
                    self.send_json(json.load(f))
            else:
                self.send_json({'error': 'not found'})

        elif self.path.startswith('/open-report'):
            params = parse_qs(urlparse(self.path).query)
            domain = params.get('domain', [''])[0]
            report_path = os.path.abspath(f"reports/{domain}_report.html")
            if os.path.exists(report_path):
                webbrowser.open(f"file://{report_path}")
                self.send_json({'ok': True})
            else:
                self.send_json({'ok': False})

        elif self.path == '/spiderfoot-status':
            global spiderfoot_running, spiderfoot_process
            # check if process is alive and port 5001 is responding
            running = False
            failed = False
            if spiderfoot_process is not None:
                if spiderfoot_process.poll() is not None:
                    # process died
                    failed = True
                    spiderfoot_running = False
                else:
                    # process alive — check if port is up
                    import socket
                    try:
                        s = socket.create_connection(('127.0.0.1', 5001), timeout=1)
                        s.close()
                        running = True
                        spiderfoot_running = True
                    except:
                        running = False
            self.send_json({'running': running, 'failed': failed})

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global spiderfoot_process, spiderfoot_running
        if self.path == '/scan':
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            domain = body.get('domain', '').strip()
            if domain and re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+[a-zA-Z0-9]$', domain):
                self.server._lines = []
                threading.Thread(target=run_scan_thread, args=(domain,), daemon=True).start()
            self.send_json({'ok': True})

        elif self.path == '/start-spiderfoot':
            sf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spiderfoot', 'sf.py')
            if not os.path.exists(sf_path):
                self.send_json({'ok': False, 'error': f'spiderfoot/sf.py not found at {sf_path}'})
                return
            sf_dir = os.path.dirname(sf_path)
            try:
                spiderfoot_process = subprocess.Popen(
                    ['python3', 'sf.py', '-l', '127.0.0.1:5001'],
                    cwd=sf_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                spiderfoot_running = True
                self.send_json({'ok': True})
            except Exception as e:
                self.send_json({'ok': False, 'error': str(e)})

        elif self.path == '/stop-spiderfoot':
            if spiderfoot_process is not None:
                try:
                    spiderfoot_process.terminate()
                    spiderfoot_process.wait(timeout=5)
                except:
                    try:
                        spiderfoot_process.kill()
                    except:
                        pass
            spiderfoot_process = None
            spiderfoot_running = False
            self.send_json({'ok': True})

    def send_json(self, data):
        payload = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(payload)


def run_scan_thread(domain):
    global scan_running, last_domain
    scan_running = True
    last_domain = domain

    from dotenv import load_dotenv
    import shodan
    from modules.dns_parser import parse_dnsrecon
    from modules.harvester_parser import parse_harvester
    from modules.report import generate_report
    load_dotenv()

    def emit(line):
        output_queue.put(line)

    os.makedirs("outputs/dns", exist_ok=True)
    os.makedirs("outputs/harvester", exist_ok=True)

    emit(f"[+] Starting OSINT Framework → {domain}")

    emit("[+] Running DNSRecon...")
    try:
        result = subprocess.run(
            f"dnsrecon -d {domain} -t std -x outputs/dns/dnsrecon_std.xml",
            shell=True, timeout=360, capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if any(k in line for k in ["INFO", "A ", "MX ", "NS ", "TXT ", "SOA ", "Completed"]):
                emit(f"    {line.strip()}")
        emit("[+] DNSRecon completed successfully")
    except Exception as e:
        emit(f"[-] DNSRecon error: {e}")

    dns_data = parse_dnsrecon("outputs/dns/dnsrecon_std.xml")

    emit("[+] Running theHarvester...")
    try:
        result = subprocess.run(
            f"theHarvester -d {domain} -b duckduckgo,crtsh,rapiddns,urlscan -l 200 -f outputs/harvester.xml",
            shell=True, timeout=360, capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if line.strip():
                emit(f"    {line.strip()}")
        emit("[+] theHarvester completed successfully")
    except Exception as e:
        emit(f"[-] theHarvester error: {e}")

    harvester_data = parse_harvester("outputs/harvester.xml")

    emit("[+] Querying Shodan using Python library...")
    shodan_data = {"status": "Processed"}
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        emit("    [-] SHODAN_API_KEY not set in .env — skipping")
    else:
        try:
            api = shodan.Shodan(api_key)
            for ip in dns_data.get("ips", [])[:3]:
                try:
                    host = api.host(ip)
                    ports = host.get("ports", [])
                    shodan_data[ip] = {"ports": ports}
                    emit(f"    ✓ {ip} → {len(ports)} open ports found")
                except:
                    pass
        except Exception as e:
            emit(f"    [-] Shodan query failed: {e}")

    generate_report(domain, dns_data, harvester_data, shodan_data)
    emit(f"[+] Report generated → reports/{domain}_report.html")
    emit("🎉 Framework Complete!")

    scan_running = False


def main():
    port = 8080
    server = HTTPServer(('localhost', port), DashboardHandler)
    server._lines = []
    print(f"\n🚀 OSINT Dashboard running at http://localhost:{port}")
    print(f"   Opening browser automatically...")
    print(f"   Press Ctrl+C to stop\n")
    threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{port}")).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        global spiderfoot_process
        if spiderfoot_process:
            try:
                spiderfoot_process.terminate()
            except:
                pass
        print("\n[+] Dashboard stopped.")


if __name__ == "__main__":
    main()
