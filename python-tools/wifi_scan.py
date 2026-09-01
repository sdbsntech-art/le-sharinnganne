#!/usr/bin/env python3
"""
SHARINNGANNE - Advanced WiFi Scanner
=====================================
Enumerates wireless networks across platforms.

Usage:
    python3 wifi_scan.py                    # Auto-detect platform
    python3 wifi_scan.py --interface wlan0  # Specify interface (Linux)
    python3 wifi_scan.py --verbose          # Verbose output
    python3 wifi_scan.py --json             # Output as JSON

Requires:
    Linux:  nmcli (NetworkManager) or iwlist (wireless-tools)
            Optional: scapy for passive monitor-mode sniffing
    Windows: netsh
"""

import argparse
import json
import re
import subprocess
import sys
import time


def run(cmd):
    """Run a command and return its stdout, or None on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


def scan_windows_networks():
    """Enumerate WiFi networks on Windows using netsh."""
    out = run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'])
    if not out:
        print("[!] Unable to enumerate networks (netsh not available or no WiFi adapter).")
        return []

    networks = []
    current = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            if current:
                networks.append(current)
                current = {}
            continue
        ssid_match = re.match(r'SSID\s*\d+\s*:\s*(.*)', line)
        if ssid_match:
            current = {'ssid': ssid_match.group(1).strip().strip('"')}
            continue
        for key, field in [('bssid', 'BSSID'), ('signal', 'Signal'),
                           ('channel', 'Channel'), ('encryption', 'Authentication'),
                           ('cipher', 'Cipher'), ('band', 'Radio type')]:
            m = re.search(re.escape(field) + r'\s*:\s*(.*)', line)
            if m and key not in current:
                current[key] = m.group(1).strip()
    if current:
        networks.append(current)
    return networks


def scan_linux_nmcli(interface=None):
    """Enumerate WiFi networks on Linux using nmcli."""
    cmd = ['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY', 'dev', 'wifi', 'list']
    if interface:
        cmd.append('ifname')
        cmd.append(interface)
    out = run(cmd)
    if not out:
        return None

    networks = []
    for line in out.splitlines():
        parts = line.split(':')
        if len(parts) < 6:
            continue
        networks.append({
            'ssid': parts[0],
            'bssid': parts[1],
            'channel': parts[2],
            'frequency': parts[3],
            'signal': parts[4],
            'encryption': parts[5],
        })
    return networks


def scan_linux_iwlist(interface='wlan0'):
    """Enumerate WiFi networks on Linux using iwlist (requires sudo)."""
    out = run(['sudo', 'iwlist', interface, 'scan'])
    if not out:
        return None

    networks = []
    cell = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('Cell '):
            if cell:
                networks.append(cell)
            cell = {}
        elif cell is not None:
            m = re.search(r'ESSID:"(.*?)"', line)
            if m:
                cell['ssid'] = m.group(1)
            m = re.search(r'Address: (\S+)', line)
            if m:
                cell['bssid'] = m.group(1)
            m = re.search(r'Channel:(\d+)', line)
            if m:
                cell['channel'] = m.group(1)
            m = re.search(r'Signal level=(-\d+) dBm', line)
            if m:
                cell['signal'] = m.group(1) + ' dBm'
            m = re.search(r'Encryption key:(on|off)', line)
            if m:
                cell['encryption'] = 'WPA/WPA2' if m.group(1) == 'on' else 'Open'
    if cell:
        networks.append(cell)
    return networks


def scan_scapy(interface='wlan0mon', timeout=10):
    """Passive WiFi scanning using scapy monitor mode."""
    try:
        from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, sniff
    except ImportError:
        print("[!] scapy not installed. Run: pip install scapy")
        return None

    print(f"[*] Sniffing on {interface} for {timeout}s (monitor mode required)...")
    networks = {}

    def handler(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr2
            ssid = ''
            channel = 0
            for elt in pkt[Dot11Elt].iterpayload():
                if isinstance(elt, Dot11Elt):
                    if elt.ID == 0 and elt.info:
                        ssid = elt.info.decode(errors='ignore')
                    elif elt.ID == 3 and elt.info:
                        channel = elt.info[0]
            if bssid not in networks:
                networks[bssid] = {'ssid': ssid or '<hidden>', 'channel': channel}
                print(f"  [NET] {networks[bssid]['ssid']} (ch {channel}) BSSID {bssid}")

    try:
        sniff(iface=interface, prn=handler, timeout=timeout)
    except PermissionError:
        print("[!] Permission denied. Run with sudo.")
        return None
    return list(networks.values())


def display(networks):
    print("\n" + "=" * 60)
    print(f"  SHARINNGANNE WiFi Scanner  —  {len(networks)} réseaux détectés")
    print("=" * 60)
    print(f"{'SSID':<28}{'CH':<5}{'SIGNAL':<10}{'ENCRYPTION':<15}")
    print("-" * 60)
    for n in networks:
        print(f"{n.get('ssid','?')[:28]:<28}{n.get('channel','?'):<5}"
              f"{n.get('signal','?'):<10}{n.get('encryption','?'):<15}")
    print()


def main():
    parser = argparse.ArgumentParser(description='SHARINNGANNE WiFi Scanner')
    parser.add_argument('--interface', '-i', default=None,
                        help='Wireless interface (Linux: wlan0, wlan0mon)')
    parser.add_argument('--scapy', action='store_true', help='Use scapy passive scan')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    print(f"[SHARINNGANNE] WiFi Scanner started at {time.strftime('%Y-%m-%d %H:%M:%S')}")

    networks = []
    if sys.platform == 'win32':
        networks = scan_windows_networks()
        if args.verbose and not networks:
            print("[i] Run as administrator for best results.")
    elif sys.platform.startswith('linux'):
        networks = scan_linux_nmcli(args.interface)
        if networks is None:
            print("[*] nmcli unavailable, falling back to iwlist...")
            networks = scan_linux_iwlist(args.interface or 'wlan0')
        if args.scapy:
            scapy_nets = scan_scapy(args.interface or 'wlan0mon')
            if scapy_nets:
                networks.extend(scapy_nets)
    else:
        print("[!] Unsupported platform.")

    if args.json:
        print(json.dumps(networks, ensure_ascii=False, indent=2))
    else:
        display(networks)


if __name__ == '__main__':
    main()
