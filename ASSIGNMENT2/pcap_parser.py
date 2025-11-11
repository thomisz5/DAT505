#!/usr/bin/env python3
"""
pcap_parser.py - fixed: casts packet times to float to handle Scapy EDecimal timestamps
Usage: python3 pcap_parser.py attacker_run.pcap --out attacker_analysis
"""
import sys
import argparse
import datetime
from collections import Counter
import csv
from scapy.all import rdpcap, IP, UDP, DNS, DNSQR, TCP, Raw

def parse_pcap(pcapfile):
    pkts = rdpcap(pcapfile)
    dns_rows = []
    urls_rows = []
    talkers = Counter()
    proto = Counter()
    for p in pkts:
        # Top talkers by IP src
        if IP in p:
            talkers[p[IP].src] += 1
            proto[p.lastlayer().name] += 1

        # get a safe ISO timestamp (cast to float)
        try:
            ts = datetime.datetime.fromtimestamp(float(p.time)).isoformat()
        except Exception:
            ts = str(p.time)

        # DNS queries (qr == 0)
        if p.haslayer(DNS) and getattr(p.getlayer(DNS), "qr", 1) == 0:
            qd = p[DNS].qd
            if qd:
                qname = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
                dns_rows.append({
                    "time": ts,
                    "src": p[IP].src if IP in p else "",
                    "qname": qname.rstrip(".")
                })

        # HTTP: raw TCP payload with GET or Host header
        if p.haslayer(TCP) and p.haslayer(Raw):
            try:
                data = p[Raw].load.decode(errors="ignore")
                if data.startswith("GET ") or "HTTP/1.1" in data or "Host:" in data:
                    lines = data.splitlines()
                    get_line = next((l for l in lines if l.startswith("GET ")), None)
                    host_line = next((l for l in lines if l.lower().startswith("host:")), "")
                    path = get_line.split()[1] if get_line else ""
                    host = host_line.split(":",1)[1].strip() if ":" in host_line else ""
                    urls_rows.append({
                        "time": ts,
                        "src": p[IP].src if IP in p else "",
                        "host": host,
                        "path": path
                    })
            except Exception:
                pass

    return dns_rows, urls_rows, talkers, proto

def save_csv(rows, filename, fieldnames):
    with open(filename, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", help="pcap file to analyze")
    ap.add_argument("--out", default="analysis", help="output prefix")
    args = ap.parse_args()

    dns_rows, urls_rows, talkers, proto = parse_pcap(args.pcap)

    # ensure output dir exists
    outprefix = args.out
    save_csv(dns_rows, f"{outprefix}_dns.csv", ["time","src","qname"])
    save_csv(urls_rows, f"{outprefix}_urls.csv", ["time","src","host","path"])

    with open(f"{outprefix}_talkers.csv","w",newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip","packets"])
        for ip,count in talkers.most_common():
            w.writerow([ip,count])

    with open(f"{outprefix}_protocols.txt","w") as f:
        for proto_name, c in proto.most_common():
            f.write(f"{proto_name}: {c}\n")

    print(f"Written: {outprefix}_dns.csv, {outprefix}_urls.csv, {outprefix}_talkers.csv, {outprefix}_protocols.txt")

if __name__ == "__main__":
    main()
