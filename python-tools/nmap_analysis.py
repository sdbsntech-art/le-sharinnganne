#!/usr/bin/env python3
"""
SHARINNGANNE - Nmap Analysis Toolkit
=====================================
Runs advanced Nmap scans and analyzes results, including
automated service/version detection, scripted vulnerability,
and OS fingerprinting.

Usage:
    python3 nmap_analysis.py TARGET
    python3 nmap_analysis.py TARGET --scan full
    python3 nmap_analysis.py TARGET --scan vuln -o report.json
    python3 nmap_analysis.py TARGET --parse scan.xml   # Parse existing output

Scan types:
    quick  - common ports (default)
    full   - all 65535 ports
    vuln   - NSE vulnerability scripts
    os     - OS detection + version
"""

import argparse
import shutil
import subprocess
import sys


def requires(cmd):
    if shutil.which(cmd) is None:
        sys.exit(f"[!] {cmd} not found. Install Nmap: sudo apt install nmap")


def build_command(target, scan_type, extra=None):
    base = ['nmap']
    switches = {
        'quick': ['-sV', '-sC', '-T4', '-p', '22,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,8080,8443,27017'],
        'full':  ['-p-', '--min-rate', '1000', '-T4'],
        'vuln':  ['-sV', '--script', 'vuln,ssl-enum-ciphers'],
        'os':    ['-sS', '-sV', '-sC', '-O', '-A', '-T4'],
    }
    cmd = base + switches.get(scan_type, switches['quick']) + [target]
    if extra:
        cmd.extend(extra)
    return cmd


def run_scan(target, scan_type, verbose=False):
    cmd = build_command(target, scan_type)
    print("[SHARINNGANNE] Running: " + ' '.join(cmd))
    print("=" * 60)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr and verbose:
            print(result.stderr, file=sys.stderr)
        return result.stdout
    except Exception as e:
        print(f"[!] Failed to run nmap: {e}")
        return None


def analyze_output(output):
    """Extract and summarize open ports and services from nmap output."""
    print("\n" + "=" * 60)
    print("  ANALYSE DES RÉSULTATS NMAP")
    print("=" * 60)

    open_ports = []
    lines = output.splitlines() if output else []
    for i, line in enumerate(lines):
        m = line.strip().split()
        if len(m) >= 3 and m[0].isdigit() and '/' in m[0] and 'open' in m[1]:
            open_ports.append({
                'port': m[0],
                'state': m[1],
                'service': m[2],
            })

    if not open_ports:
        print("[-] Aucun port ouvert détecté.")
        risk = 'FAIBLE'
    else:
        print(f"[+] {len(open_ports)} port(s) ouvert(s):")
        for p in open_ports:
            print(f"    {p['port']:<12}{p['service']}")
        # Heuristic risk scoring based on exposed services
        dangerous = {'telnet', 'ftp', 'netbios-ssn', 'microsoft-ds',
                     'mysql', 'postgresql', 'mssql', 'rdp', 'mongod'}
        risky = [p for p in open_ports if p['service'] in dangerous]
        if risky:
            risk = 'ÉLEVÉ' if len(risky) >= 2 else 'MOYEN'
        else:
            risk = 'MOYEN' if len(open_ports) > 5 else 'FAIBLE'

    print(f"\n[!] Niveau de risque estimé : {risk}")
    print("[*] Recommandations : réduire la surface d'exposition, "
          "désactiver les services non nécessaires, utiliser un pare-feu.")
    return {'open_ports': open_ports, 'risk': risk}


def main():
    parser = argparse.ArgumentParser(description='SHARINNGANNE Nmap Analysis')
    parser.add_argument('target', nargs='?', help='Target host/IP/range')
    parser.add_argument('--scan', default='quick',
                        choices=['quick', 'full', 'vuln', 'os'])
    parser.add_argument('--extra', default=None, help='Extra nmap args (quoted)')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--parse', help='Parse an existing nmap output file')
    args = parser.parse_args()

    if args.parse:
        with open(args.parse, 'r', encoding='utf-8', errors='ignore') as f:
            analyze_output(f.read())
        return

    if not args.target:
        parser.error('target required')

    extra = args.extra.split() if args.extra else None
    output = run_scan(args.target, args.scan, args.verbose)
    if output:
        analyze_output(output)


if __name__ == '__main__':
    main()
