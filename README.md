## Overview

Investigation of DNS activity from a small office network. One host generates a burst of lookups for random, nonexistent domain names before one of them resolves, a behavior pattern of malware using a **domain generation algorithm (DGA)** to locate its **command-and-control (C2)** server. A Splunk dashboard was built to surface this kind of pattern visually, not just through one-off searches.

## Environment

| Item | Value |
|---|---|
| Index | `dns_practice_log` |
| Sourcetype | `generic_single_line` (key=value format) |
| Log date | 2026-09-21 |
| Suspect host | `10.1.1.27` |
| Suspicious domain / IP | `xkqzvtplmwbdrhy.top` / `185.243.115.61` |

## Methodology

### 1. Baseline volume

```spl
index="dns_practice_log"
| stats count dc(client)
```
**Result:** 797 total DNS events across 20 distinct clients.

<img width="1483" height="204" alt="Screenshot 2026-10-01 070542" src="https://github.com/user-attachments/assets/abb77509-6cdc-4bfe-baca-245f7d22c726" />

---

### 2. Result code breakdown

```spl
index="dns_practice_log"
| stats count by rcode
```
**Result:** 637 `NOERROR`, 160 `NXDOMAIN

<img width="1485" height="257" alt="Screenshot 2026-10-01 070635" src="https://github.com/user-attachments/assets/2aeb764b-7a9b-48d2-9d0b-84f569f36352" />

---

### 3. Which client is failing the most

```spl
index="dns_practice_log" rcode="nxdomain" 
| top client
```
**Result:** `10.1.1.27` accounts for 144 of the 160 total `NXDOMAIN` events. Every other client has 1-2 (ordinary typos).

<img width="1487" height="514" alt="Screenshot 2026-10-01 071119" src="https://github.com/user-attachments/assets/e2bb3b98-8448-4506-b2be-748d8807a083" />

---

### 4. What the failed lookups look like

```spl
index="dns_practice_log" rcode="nxdomain" 10.1.1.27
| table _time, query
```
**Result:** Random 12-18 character strings across `.com`, `.net`, `.xyz`, and `.top` — not typos of real sites, consistent with algorithmically generated domain names.

<img width="1485" height="750" alt="Screenshot 2026-10-01 071406" src="https://github.com/user-attachments/assets/4aabd8e5-43b9-4423-a0d1-d19775d7f350" />

---

### 5. Burst window

```spl
index="dns_practice_log" rcode="nxdomain" 10.1.1.27 
| stats count earliest(_time) as first_seen, latest(_time) as last_seen 
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```
**Result:** 144 failed lookups from 14:30:00 to 14:51:30, consistent, automated timing rather than human typing.

<img width="1487" height="186" alt="Screenshot 2026-10-01 071955" src="https://github.com/user-attachments/assets/b229ff28-91d3-4d7c-a45b-b08dcc415f08" />

---

### 6. Successful resolution after the burst

```spl
index="dns_practice_log" rcode="noerror" 10.1.1.27 earliest="09/21/2026:14:30:00" latest="09/21/2026:15:15:00" 
| table _time, query, answer
| sort -_time
```
**Result:** At 14:51:37, `xkqzvtplmwbdrhy.top` resolved to `185.243.115.61`. The same domain was queried again at 14:56:12 and 15:11:40, consistent with periodic Command and Control check-ins.

<img width="1487" height="290" alt="Screenshot 2026-10-01 072525" src="https://github.com/user-attachments/assets/dcc366a9-524f-44fa-8783-659e907bbec8" />

---

### 7. Scope check — is anyone else affected

```spl
index="dns_practice_log" (query="xkqzvtplmwbdrhy.top" OR answer=185.243.115.61)
| stats count by client
```
**Result:** Only `10.1.1.27` ever queried this domain, in this dataset.

<img width="1485" height="205" alt="Screenshot 2026-10-01 072757" src="https://github.com/user-attachments/assets/1ca2de9b-00c1-4d6c-a8f3-7af1d98b55de" />

---

## Dashboard

A six-panel dashboard was built to make this kind of pattern visible without needing to run each search manually.

| Panel | SPL | Purpose |
|---|---|---|
| Top queried domains | `index="dns_practice_log" \| top query` | Baseline of normal destinations (`mail.google.com`, `teams.microsoft.com`, etc. lead) |
| Query type breakdown | `index="dns_practice_log" \| stats count by qtype` | `A` (703) dominates, as expected; `AAAA`/`MX`/`TXT` are a small minority |
| Traffic volume by hour | `index="dns_practice_log" \| timechart span=1h count` | Overall hourly trend — the 2 PM hour visibly spikes above the normal 30-50/hour range |
| Result code by hour | `index="dns_practice_log" \| timechart span=1h count by rcode` | Shows the `NXDOMAIN` spike concentrated in one hour |
| Volume by client, by hour | `index="dns_practice_log" \| timechart span=1h count by client` | `10.1.1.27`'s line spikes sharply above all other clients during the incident hour |
| NXDOMAIN count by client | `index="dns_practice_log" rcode=NXDOMAIN \| stats count by client` | Isolates `10.1.1.27` as the dominant source of failed lookups |

<img width="1636" height="430" alt="db1" src="https://github.com/user-attachments/assets/c14746be-1231-4ebe-b8bf-4798420689d4" />
<img width="1634" height="731" alt="db2" src="https://github.com/user-attachments/assets/6ad2b949-2bf3-4308-a76e-f8b43ad009d5" />


## Timeline

| Time | Event |
|---|---|
| 07:00 – 18:xx | Normal office DNS traffic across 20 clients |
| 14:30:00 | `10.1.1.27` begins rapid lookups of random, nonexistent domains |
| 14:30:00 – 14:51:30 | 144 `NXDOMAIN` responses, one every 6-12 seconds |
| 14:51:37 | `xkqzvtplmwbdrhy.top` resolves successfully to `185.243.115.61`; failures stop |
| 14:56:12 | Repeat lookup of the same domain |
| 15:11:40 | Repeat lookup of the same domain |

## Findings summary

| Item | Finding |
|---|---|
| Suspect host | `10.1.1.27` |
| Share of all failures | 10.1.1.27 accounts for 144 of the 160 total NXDOMAIN events in the log (90%) |
| Behavior | Rapid, evenly-spaced lookups of algorithmically-generated domain names, ending the moment one resolves |
| Suspicious domain / IP | `xkqzvtplmwbdrhy.top` / `185.243.115.61` |
| Scope | No other client in this dataset queried the domain |
| Likely cause | Malware using a DGA to locate its C2 server, followed by periodic check-ins |

DNS logs alone show the pattern, not what is actually running on the host, this is strong behavioral evidence, not proof of infection.

## Recommendations

- Isolate `10.1.1.27` from the network and scan it for malware
- Block `xkqzvtplmwbdrhy.top` and `185.243.115.61` at the DNS resolver and firewall
- Cross-reference firewall/proxy logs for `10.1.1.27` → `185.243.115.61` to check whether any data was actually transferred
- Alert on hosts with a high `NXDOMAIN` rate combined with short, regular query intervals — the general signature of DGA behavior
- Extend the dashboard with a 5-minute-resolution NXDOMAIN-by-client panel to catch bursts like this without manual cross-referencing

---

*Logs analyzed in Splunk (index `dns_practice_log`). SPL queries and results above reproduce the investigation steps for reference. All data is synthetic and generated for practice purposes.*
