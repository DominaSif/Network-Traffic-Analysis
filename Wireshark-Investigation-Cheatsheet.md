# Wireshark Display Filters for SOC Analysis

This repository contains a curated collection of **Wireshark Display Filters** designed to accelerate network traffic analysis (PCAP) and facilitate rapid incident detection.

These filters are categorized by threat type and investigation scenario, focusing on noise reduction and anomaly detection.

## 1. Noise Reduction (Sanitary Filters)
*Before starting an investigation, it is crucial to eliminate broadcast and background traffic that masks real incidents.*

| Filter | Description for SOC Analyst |
| :--- | :--- |
| `!arp && !ssdp && !mdns && !icmp` | Excludes ~90% of local network background noise (ARP requests, SSDP/mDNS discovery, and ICMP pings). |
| `!tcp.analysis.retransmission` | Hides TCP retransmission packets. Useful when focusing on payload content rather than network quality issues. |
| `ip.dst == 255.255.255.255` | Shows only broadcast traffic. Used to spot anomalous broadcasting spikes. |

## 2. Scanning & Reconnaissance Detection
*Filters to identify potential network mapping and port scanning attempts.*

| Filter | Description for SOC Analyst |
| :--- | :--- |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | Isolates **SYN Scan** patterns. Shows only the initial connection request without acknowledgment. |
| `tcp.flags.fin==1 && tcp.flags.ack==0` | Detects **FIN Scans**. Often used to bypass traditional firewalls. |
| `icmp.type == 8` | Isolates **Echo Requests (Ping)**. Useful for detecting Ping Sweeps. |
| `http.response.code == 404` | Isolates "Not Found" errors. A high volume from a single IP often indicates web directory enumeration (e.g., Gobuster/Dirb). |
| `dns.qry.name matches "(\\d{1,3}\\.){3}\\d{1,3}"` | Detects **DNS Reverse Lookups**. Often part of the reconnaissance phase. |

## 3. Data Exfiltration Detection
*Filters aimed at spotting data leaving the network.*

| Filter | Description for SOC Analyst |
| :--- | :--- |
| `http.request.method == "POST"` | **Critical Filter.** Isolates data transmission (logins, file uploads, form submissions). High priority for investigation. |
| `http contains "password" || http contains "login"` | Keyword search in cleartext HTTP traffic (identifies credential leaks). |
| `http.request.method == "PUT"` | Isolates file uploads via PUT method (less common, but suspicious). |
| `tcp.len > 10000` | Detects packets with unusually large payloads. Potential indicator of file exfiltration. |

## 4. Command & Control (C2) Traffic Analysis
*Filters to spot potential beaconing or communication with malicious infrastructure.*

| Filter | Description for SOC Analyst |
| :--- | :--- |
| `tcp.port in {4444 1337 6667}` | Checks for common default ports used by frameworks like Metasploit or older trojans. |
| `tls.handshake.type == 1 && !tls.handshake.extensions_server_name` | Finds HTTPS connections **missing SNI**. Typical for non-browser malware agents. |
| `dns.flags.rcode == 3` | Detects **NXDomain** responses. High volume indicates DGA (Domain Generation Algorithms) or DNS Tunneling attempts. |

## 5. TLS/HTTPS Metadata Analysis (Encrypted Traffic)
*Extracting intelligence from encrypted streams without decryption.*

| Filter | Description for SOC Analyst |
| :--- | :--- |
| `tls.handshake.type == 1` | Isolates **Client Hello** packets. Reveals the **SNI (Server Name Indication)** — the target domain name. |
| `tls.alert_message` | Shows TLS alerts. May indicate certificate issues or interception attempts. |

---
*Usage: Combine these filters with logical operators (`&&`, `||`, `!`) to create custom investigation profiles.*
