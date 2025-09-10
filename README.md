# GTPDoor-Aes 

> **Responsible Use**  
> Run only on systems and networks where you have explicit permission. This project is intended for educational/research use in closed labs. Do **not** expose services to the public Internet.

---

## Legal/Ethical Notice (Read First)

This content is provided strictly for educational and informational purposes only. It does not condone, promote, or encourage violence, unlawful activities, or unethical conduct in any form.

All users and viewers are expected to comply fully with all applicable federal, state, and international laws. The authors and publishers of this material do not accept liability for any misuse, misinterpretation, or unauthorized application of the information provided.

Always operate within legal and ethical boundaries.

### ⚠️ Disclaimer
The creator is not responsible for any of the following:
- Illegal use of the project.
- Legal infringement by third parties and users.
- Malicious acts capable of causing damage to third parties, promoted by the user through this software.

---

## Table of Contents
- [Overview](#overview)
- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Components](#components)
- [Prerequisites](#prerequisites)
- [Quickstart](#quickstart)
- [Verify & Outputs](#verify--outputs)
- [Detection Content (Snort/Suricata)](#detection-content-snortsuricata)
- [Modular Packet Handler Model](#modular-packet-handler-model)
- [Safety, Legal & Troubleshooting](#safety-legal--troubleshooting)
- [Repository Layout](#repository-layout)

---

## Overview
This lab brings up two containers:

- **listener** — binds **UDP/2123**, captures traffic to **PCAP** (via `tcpdump`), and processes incoming packets.  
- **simulator** — sends crafted control-plane messages to produce reproducible traces.

The purpose is to generate repeatable **telecom control-plane traffic** for **packet analysis** (Wireshark) and **offline detection** experiments (Suricata/Snort).

---

## Capabilities

- **Control-plane backdoor simulation over GTP-C (UDP/2123) with AES-encrypted comms.**  
  Encrypted (AES) payloads flow between simulator and listener to emulate command/response behavior in an authorized lab. All traffic is captured to PCAPs for **IDS/IPS testing**.

- **PCAP generation for defender workflows.**  
  The listener writes session PCAPs under `./pcaps/`, enabling reproducible replay and rule evaluation (Wireshark, Suricata, Snort).

- **Modular packet processing.**  
  Processing follows a staged pipeline (receive → parse header → **AES decrypt** → normalize/log → capture), exposing clear **extension points** for handlers (metrics, tagging, transforms).

---

## Architecture
```
+------------+        UDP/2123         +------------+
| simulator  |  --------------------->  |  listener  |
| (sends)    |                         | (captures) |
+------------+                         +------------+
                                              |
                                              | tcpdump -> PCAP
                                              v
                                       ./pcaps/session_*.pcap
```

Default container names:
- `gtpdoor_simulator` (sender)
- `gtpdoor_listener`  (receiver)

---

## Components
- **docker-compose.yml** — defines services and volume mounts.
- **listener/** — Python app + image that listens on UDP/2123, decrypts AES payloads, and writes PCAPs.
- **simulator/** — Python app + image that generates AES-encrypted lab traffic.
- **rules/** — *add-only* Snort/Suricata rules for **offline** analysis of PCAPs.

> PCAPs are mounted to the host for Wireshark and offline IDS/IPS evaluation.

---

## Prerequisites
- **Docker** (Engine or Desktop) with **Docker Compose v2**
- ~1 GB free disk space for captures (depends on run duration)
- Optional tools for analysis:
  - **Wireshark** (view PCAPs)
  - **Suricata** and/or **Snort** (offline IDS runs)

---

## Quickstart
```bash
# Build & start (detached)
docker compose up -d --build

# Follow logs (separate terminals if preferred)
docker logs -f gtpdoor_listener
docker logs -f gtpdoor_simulator

# Stop & clean when done
docker compose down -v
```

**Wireshark tip:** Use display filter `udp.port == 2123`.

---

## Verify & Outputs

**Verify containers are up**
```bash
docker ps --format "table {{.Names}}	{{.Status}}	{{.Ports}}"
```

**Check that a PCAP was created**
```bash
# On host
ls -lah pcaps/

# Or inside the listener
docker exec -it gtpdoor_listener ls -lah /pcaps
```

**Outputs**
- **PCAPs** → `./pcaps/` (from the listener container)  
- **Logs** → `docker logs -f gtpdoor_listener` and `docker logs -f gtpdoor_simulator`

---

## Detection Content (Snort/Suricata)

**Authored rules** (kept separate so runtime is unchanged):

- Suricata: `rules/suricata/gtpdoor_lab.rules`  
- Snort   : `rules/snort/gtpdoor_lab.rules`

**Run rules offline against your PCAPs**
```bash
# Suricata (PCAP mode)
suricata -S rules/suricata/gtpdoor_lab.rules -r pcaps/*.pcap -k none

# Snort (PCAP mode, 2.x simple run)
snort -A console -q -k none -r pcaps/*.pcap -c rules/snort/gtpdoor_lab.rules
```

**Tuning tips**
- Adjust rule thresholds (`count/seconds`) to match your traffic rate.
- If using a base64-like payload heuristic rule, tune the `{64,}` length to your payload size.
- Start in Wireshark with `udp.port == 2123`.

---

## Modular Packet Handler Model

The listener’s processing is organized into **composable stages** so defenders can extend behavior without rewriting core logic:

1. **Ingress** — receive UDP/2123 packet  
2. **Header Parse/Validate** — parse minimal GTP-C context used by the lab  
3. **Crypto Stage (AES)** — decrypt payload for downstream use  
4. **Normalize/Log** — convert to structured record, tag metadata (timestamps, ports)  
5. **Capture** — persist to PCAP + console logs  
6. **Extension Hooks (optional)** — plug-in style handlers (e.g., counters, tagging, format converters)

> This layout enables experiments like feature extraction or labeling while keeping the capture pipeline intact.

---

## Safety, Legal & Troubleshooting

> **Operate only in authorized, isolated lab environments.** You are responsible for compliance with laws, institutional policies, and terms of service.

**Troubleshooting**
- **No PCAPs appear** → confirm `pcaps/` exists and is mounted; on Windows/macOS, enable file-sharing for the project path in Docker Desktop.  
- **Port conflict `2123/udp`** → stop the conflicting service or adjust host mapping in `docker-compose.yml`.  
- **Permission/capture issues** → packet capture may require default Docker network capabilities; avoid extra restrictions.  
- **Can’t see traffic in Wireshark** → filter `udp.port == 2123`; verify both containers are up via `docker logs -f ...`.  
- **PCAPs too large** → limit run time; rotate or move older captures out of `pcaps/`.

---

## Repository Layout
```
.
├─ docker-compose.yml
├─ listener/
│  ├─ Dockerfile
│  ├─ gtpdoor.py
│  └─ requirements.txt
├─ simulator/
│  ├─ Dockerfile
│  ├─ simulator.py
│  └─ requirements.txt
├─ pcaps/
│  └─ .gitkeep
├─ rules/
│  ├─ gtpdoor_lab_suricata.rule
│  └─ gtpdoor_lab_snort.rule
├─ .gitignore
├─ .dockerignore
└─ README.md

```

---

**Note:** This repository is for educational and research lab use only. Do not deploy on networks where you lack explicit permission.
