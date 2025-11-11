# MitM Lab — ARP Poisoning & Selective DNS Spoofing

**Author:** Thomas Sa Capucho
**Course / Assignment:** DAT505 - ETHICAL HACKING / University of Stavanger
---

## Overview

This repository contains scripts, captures and notes from a controlled lab demonstrating:
- **Task 1:** ARP spoofing (transparent Man-in-the-Middle) — `arp_spoof.py`
- **Task 2:** Traffic capture & analysis — `pcap_parser.py` + PCAP files
- **Task 3:** Selective DNS spoofing — `dns_spoof.py` with `hosts.txt`

All experiments were performed inside an **isolated VirtualBox host-only/internal network** (Attacker, Victim and Gateway VMs). Do **not** run these tools on networks you do not control. See **Safety & Ethics** below.
