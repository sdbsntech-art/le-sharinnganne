#!/usr/bin/env python3
"""
SHARINNGANNE - Localisation OSINT (éthique / sources publiques)
================================================================
Analyse un numéro de téléphone, une adresse IP ou un email pour
en extraire les informations disponibles publiquement (et légalement).

ATTENTION : cet outil NE donne PAS la localisation physique d'une
personne. Il exploite uniquement des sources ouvertes (indicatif,
opérateur, format E.164, reverse DNS, MX). La localisation réelle
d'un individu relève des opérateurs et de la justice.

Usage:
    python3 locate_person.py +221770000000        # Numéro de téléphone
    python3 locate_person.py 197.155.10.5         # Adresse IP
    python3 locate_person.py nom@domaine.com      # Email
    python3 locate_person.py --json +221770000000 # Sortie JSON
"""

import argparse
import json
import re
import socket
import sys

try:
    import requests  # noqa: F401  (utilisé pour appels OSINT optionnels)
except ImportError:
    requests = None


# ══════════════════════════════════════════
# BASE DE DONNÉES PAYS / INDICATIFS (publique)
# ══════════════════════════════════════════
COUNTRY_DATA = {
    '+221': ('Sénégal', 'SN', '221', 'Orange-Sonatel / Free'),
    '+33':  ('France', 'FR', '33', 'Orange / SFR / Bouygues / Free'),
    '+225': ("Côte d'Ivoire", 'CI', '225', 'Orange / MTN'),
    '+224': ('Guinée', 'GN', '224', 'Orange / MTN'),
    '+223': ('Mali', 'ML', '223', 'Orange / Telecel'),
    '+226': ('Burkina Faso', 'BF', '226', 'Orange / Telecel'),
    '+232': ('Sierra Leone', 'SL', '232', 'Orange / Africell'),
    '+229': ('Bénin', 'BJ', '229', 'MTN / Moov'),
    '+228': ('Togo', 'TG', '228', 'Togocel / Moov'),
    '+234': ('Nigéria', 'NG', '234', 'MTN / Airtel / Globacom'),
    '+212': ('Maroc', 'MA', '212', 'Maroc Telecom / Orange / inwi'),
    '+216': ('Tunisie', 'TN', '216', 'Ooredoo / Orange'),
    '+213': ('Algérie', 'DZ', '213', 'Djezzy / Ooredoo / Mobilis'),
    '+1':   ('États-Unis/Canada', 'US', '1', 'AT&T / Verizon / T-Mobile'),
    '+44':  ('Royaume-Uni', 'GB', '44', 'EE / O2 / Vodafone / Three'),
    '+49':  ('Allemagne', 'DE', '49', 'Telekom / Vodafone / O2'),
    '+86':  ('Chine', 'CN', '86', 'China Mobile / Unicom'),
    '+91':  ('Inde', 'IN', '91', 'Jio / Airtel / Vi'),
    '+20':  ('Égypte', 'EG', '20', 'Vodafone / Orange / Etisalat'),
    '+27':  ('Afrique du Sud', 'ZA', '27', 'Vodacom / MTN'),
    '+32':  ('Belgique', 'BE', '32', 'Proximus / Orange / Telenet'),
    '+41':  ('Suisse', 'CH', '41', 'Swisscom / Salt / Sunrise'),
    '+39':  ('Italie', 'IT', '39', 'TIM / Vodafone / WindTre'),
}


def identify_number(raw):
    """Retourne (pays, iso, indicatif, opérateur) à partir d'un numéro."""
    digits = re.sub(r'[^0-9+]', '', raw)
    if not digits.startswith('+'):
        digits = '+' + digits
    # Trier par indicatif le plus long pour éviter les faux positifs (+1 vs +1xx)
    for cc in sorted(COUNTRY_DATA, key=len, reverse=True):
        if digits.startswith(cc) and len(digits) > len(cc):
            country, iso, call, op = COUNTRY_DATA[cc]
            return country, iso, call, op
    return 'Inconnu', '??', '?', 'Inconnu'


def analyze_phone(raw):
    country, iso, call, op = identify_number(raw)
    print(f"\n[SHARINNGANNE] Analyse numéro : {raw}")
    print("=" * 55)
    print(f"  Pays (indicatif appelant) : {country}")
    print(f"  Indicatif pays             : +{call}")
    print(f"  Opérateur vraisemblable    : {op}")
    print(f"  Format E.164               : {raw}")
    print("\n  [i] La localisation précise (adresse) n'est pas possible")
    print("      sans données de l'opérateur ou décision de justice.")
    return {'type': 'phone', 'value': raw, 'country': country, 'iso': iso,
            'calling_code': call, 'carrier': op}


def analyze_ip(raw):
    parts = raw.split('.')
    first = int(parts[0]) if parts[0].isdigit() else 0
    print(f"\n[SHARINNGANNE] Analyse IP : {raw}")
    print("=" * 55)

    if first in (10, 172, 192, 100, 169):
        region = 'Réseau privé / local (non routable publiquement)'
    elif 197 <= first <= 196 or first == 41:
        region = 'Afrique / région Ouest (indicatif réseau)'
    elif first in (51, 52):
        region = 'Europe (cloud Azure)'
    elif first in (104, 172, 103, 162):
        region = 'CDN Cloudflare (lieu variable)'
    elif first == 8:
        region = 'États-Unis (Google DNS)'
    else:
        region = f'Non déterminé (classe {first})'
    print(f"  Réseau probable : {parts[0]}.{parts[1]}.x.x")
    print(f"  Localisation     : {region}")
    try:
        host = socket.gethostbyaddr(raw)[0]
        print(f"  Reverse DNS (PTR): {host}")
    except socket.herror:
        print("  Reverse DNS (PTR): aucun enregistrement")
    print("\n  [i] La géolocalisation IP est approximative et contournable")
    print("      par VPN/proxy. Elle n'identifie pas une personne.")
    return {'type': 'ip', 'value': raw, 'region': region, 'network': f'{parts[0]}.{parts[1]}.x.x'}


def analyze_email(raw):
    domain = raw.split('@')[1] if '@' in raw else raw
    print(f"\n[SHARINNGANNE] Analyse email : {raw}")
    print("=" * 55)
    print(f"  Domaine : {domain}")
    try:
        answers = socket.getaddrinfo(domain, 25)
        print(f"  Serveur de messagerie (MX) résolu : oui ({answers[0][4][0]})")
    except socket.gaierror:
        print("  Serveur de messagerie (MX) résolu : non / restreint")
    print("\n  [i] Un email ne permet pas de localiser physiquement un individu.")
    return {'type': 'email', 'value': raw, 'domain': domain}


def main():
    parser = argparse.ArgumentParser(description='SHARINNGANNE Localisation OSINT')
    parser.add_argument('query', help='Numéro (ex: +22177...), IP ou email')
    parser.add_argument('--json', action='store_true', help='Sortie JSON')
    args = parser.parse_args()
    q = args.query.strip()

    if '@' in q:
        data = analyze_email(q)
    elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', q):
        data = analyze_ip(q)
    else:
        data = analyze_phone(q)

    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
