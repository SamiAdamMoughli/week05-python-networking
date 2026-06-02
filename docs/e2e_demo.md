# End-to-End Demo — Mini Penetration Test Against Local Flask App

**Date:** 2026-06-02
**Target:** 127.0.0.1 (localhost — own infrastructure)
**Tools:** MarcoPolo, BannerGrabber, NetworkMonitor, tcpdump, PCAPAnalyser, ReconToolkit
**Authorisation:** Own machine. Educational exercise only.

---

## Objective

Run every Week 5 tool against a real target — the Week 4 Flask app — and document what each tool reveals. Then answer the question a defender must always ask: *if an attacker had this output, what could they do with it?*

---

## Setup

| Component | Details |
|---|---|
| Flask app | `week04-python-web/flask_app/`, running on `0.0.0.0:5000` |
| Monitor | `network_monitor.py --interface lo --alert-threshold 20` |
| Capture | `tcpdump -i lo -w login_capture.pcap port 5000` |
| Scanner | `marco_polo.py --target 127.0.0.1 --top 100` |
| Banner grabber | `recon_toolkit.py grab --target 127.0.0.1 --ports 22,80,5000` |
| PCAP analyser | `pcap_analyser.py --file login_capture.pcap --report --http` |

---

## Step 1 — Port Scan

**Command:**
```bash
sudo python scripts/marco_polo.py --target 127.0.0.1 --top 100
```

**Findings:**

| Port | State | Service | Confidence |
|---|---|---|---|
| 22 | open | ssh | high |
| 80 | open | http | high |
| 5000 | open | unknown | — |

**What this tells an attacker:**
- Port 22 is open — SSH is running and accessible. Version fingerprinting is possible.
- Port 80 is open — a web server is present on the standard HTTP port.
- Port 5000 is open — a non-standard port with an unknown service. This is unusual and warrants further investigation.

---

## Step 2 — Banner Grabbing

**Command:**
```bash
sudo python scripts/recon_toolkit.py grab --target 127.0.0.1 --ports 22,80,5000
```

**Findings:**

| Port | Service | Version | Confidence |
|---|---|---|---|
| 22 | ssh | 2.0 | high |
| 80 | http | — | high |
| 5000 | unknown | — | low |

**Analysis:**

**Port 22 (SSH):** Protocol version 2.0 confirmed with high confidence. The SSH banner reveals the protocol version immediately on connection without authentication. An attacker now knows SSH is running and can attempt credential attacks or check for known CVEs against the identified SSH daemon.

**Port 80 (HTTP):** HTTP confirmed but no server header returned on a bare HEAD request — the web server is not leaking its implementation details on port 80.

**Port 5000 (Flask/Werkzeug):** The banner grabber returned `unknown` with low confidence. Werkzeug does not respond to a bare TCP probe or HTTP HEAD request in a way that exposes its identity — it requires a properly formed HTTP request with a valid path. This is accidental OPSEC: Flask doesn't advertise itself on raw connection. However, the open port is still a signal — port 5000 is strongly associated with development web servers (Flask, development APIs). An experienced attacker would send a GET request next.

---

## Step 3 — Live Monitor During Port Scan

**Command:**
```bash
# Terminal 1
sudo python scripts/network_monitor.py --interface lo --alert-threshold 20

# Terminal 2
sudo python scripts/marco_polo.py --target 127.0.0.1 --top 100
```

**Monitor output (Alerts panel):**
```
▸ PORT SCAN 127.0.0.1 → 20 ports in 10s
▸ LARGE PACKET 127.0.0.1 — 21,384 bytes (>9,000)
▸ LARGE PACKET 127.0.0.1 — 54,850 bytes (>9,000)
▸ LARGE PACKET 127.0.0.1 — 65,535 bytes (>9,000)
```

**Analysis:**

The port scan was detected within the first 10 seconds. Any host running the network monitor would see the scan in real time and could immediately begin incident response — blocking the source IP, alerting on-call, or triggering automated countermeasures.

The large packet alerts are a Scapy loopback artifact — on Linux, loopback packets are reported at the full buffer size rather than the actual payload size. In a real network, large packet alerts would flag potential data exfiltration, jumbo frame misconfigurations, or buffer overflow attempts.

**Key insight:** A concurrent TCP scanner hitting 100 ports generates a distinctive traffic signature. 20 unique destination ports from one source IP in 10 seconds is not normal user behaviour. The monitor caught it with a simple counter — no ML, no complex heuristics.

---

## Step 4 — Packet Sniffer During Login

**Commands:**
```bash
# Terminal 1 — capture
sudo tcpdump -i lo -w docs/login_capture.pcap port 5000

# Terminal 2 — browser
# Navigate to http://127.0.0.1:5000
# Log in, browse dashboard, log out

# Ctrl+C to stop capture
```

**Capture summary:**
- **204 packets** captured
- **All TCP** — no UDP or ICMP on this interface/filter
- **Single host pair:** 127.0.0.1 ↔ 127.0.0.1 (loopback)
- **36 TCP conversations** — each browser resource request opens a separate connection
- **Largest response:** 78,392 bytes (dashboard page with static assets)
- **Longest conversation:** 2,827ms (Flask debug reloader holding connection)

**HTTP requests extracted:**

```
GET  /dashboard
GET  /static/blueprint.css
GET  /static/blueprint-icons.css
GET  /static/logo.png
GET  /logout
GET  /
GET  /login
POST /login          ← credentials submitted here
GET  /dashboard      ← 302 redirect after successful auth
```

**What the sniffer reveals:**

The `POST /login` request is visible in the capture. The PCAP analyser correctly identifies it as an HTTP request — on an unencrypted HTTP connection, the request body (containing the username and password) would be fully readable in the raw packet payload. The analyser's `find_http_requests()` method only extracts headers, not the body — but a raw `tcpdump -A` or Wireshark session would show the credentials in plaintext.

The session cookie set after login would appear in subsequent GET requests in the `Cookie` header — also readable in plaintext on HTTP.

**The browser (Firefox 151.0 on Ubuntu)** is identified in every request via the `User-Agent` header — `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0`. This is visible to any passive observer on the network.

---

## Step 5 — PCAP Analysis

**Command:**
```bash
python scripts/pcap_analyser.py --file docs/login_capture.pcap --report --http
```

**Key findings:**

**Traffic pattern:** All 204 packets are between `127.0.0.1` and `127.0.0.1` on port 5000. This is a single browser session — one user, one application, loopback only.

**Port breakdown:** Port 5000 dominates with 120 packets to/from the Flask server. The remaining packets are from ephemeral client ports (35150–44864 range) — one per browser connection.

**Conversation analysis:** Each page load opens multiple short-lived TCP connections — one per static asset. The `/dashboard` page alone triggers four separate connections (HTML + CSS + icons + logo). This is HTTP/1.1 behaviour — each resource is fetched on its own connection. HTTP/2 would multiplex these over a single connection.

**The POST /login conversation:** The login form submission appears as a `POST /login` in the HTTP extraction, followed immediately by a `GET /dashboard` (the 302 redirect after successful authentication). This two-request pattern is the fingerprint of a successful login — visible to any observer with network access.

---

## Findings Summary

| Finding | Severity | Detail |
|---|---|---|
| Flask running in debug mode | Critical | Werkzeug debugger PIN exposed in terminal (419-323-562). Anyone who can reach port 5000 can use this PIN to execute arbitrary Python on the server via the interactive debugger at `/?__debugger__`. |
| HTTP — no TLS | High | All traffic including login credentials and session cookies is transmitted in plaintext. Any observer on the network path can read credentials. |
| SSH exposed on port 22 | Medium | SSH accessible from any interface. No evidence of fail2ban, port knocking, or IP allowlisting. |
| Server fingerprint via User-Agent reflection | Low | The browser's OS and version are leaked in every request. Not a vulnerability, but contributes to attacker reconnaissance. |
| Port 5000 publicly bound | Medium | Flask is bound to `0.0.0.0` — accessible from any network interface, not just localhost. Any device on the same network (192.168.64.0/24) can reach the app. |

---

## What I Would Change About the Flask App

**1. Disable debug mode immediately.**
```python
# Never in production
app.run(debug=False)
```
Debug mode exposes remote code execution via the Werkzeug PIN. This is the most critical finding.

**2. Bind to localhost only.**
```python
app.run(host="127.0.0.1", port=5000)
```
There is no reason for a development app to be accessible on all interfaces.

**3. Add TLS — even for local development.**
Use `flask-talisman` or run behind a local nginx proxy with a self-signed cert. Without TLS, credentials and session cookies are readable to any network observer.

**4. Restrict SSH.**
Move SSH to a non-standard port or restrict it with firewall rules to known source IPs only. Fail2ban should be active on any SSH-exposed host.

**5. Add security headers.**
The Week 4 header auditor should be run against the final app before any deployment. HSTS, CSP, X-Frame-Options, and Referrer-Policy should all be present.

**6. Use a production WSGI server.**
Replace `flask run` with `gunicorn` or `waitress`. Development servers are not hardened for production traffic.

---

## Conclusion

Every tool built this week had a clear output. When combined, they form a complete picture of a target — what's running, what version, what traffic flows, and what that traffic contains.

The Flask app passed its own security checklist (headers, CSRF, bcrypt passwords). But it failed at the infrastructure level: debug mode enabled, no TLS, publicly bound. Security is not just about application code. It's about how the application is deployed, what the network exposes, and what a passive observer can learn from traffic alone.

**The one-sentence lesson:** A tool that logs everything teaches you to expose nothing.