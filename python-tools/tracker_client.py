#!/usr/bin/env python3
"""
SHARINNGANNE - IP Tracker Client (lien à partager)
===================================================
Génère un lien tracker unique via le backend, puis affiche
les IP/positions recueillies quand les personnes cliquent.

Usage:
    python3 tracker_client.py create "Mon lien" --api https://monsite.com --token JWT
    python3 tracker_client.py results TRK-XXXXXX --api https://monsite.com --token JWT

Remarque : le lien /l/CODE est créé et servi par le backend Node.js.
Ce script ne fait qu'appeler l'API de création/consultation.
"""

import argparse
import json
import sys

try:
    import requests
except ImportError:
    requests = None


def call(endpoint, method='GET', token=None, body=None):
    if requests is None:
        sys.exit("[!] requests non installé : pip install requests")
    url = endpoint
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    r = requests.request(method, url, headers=headers, json=body, timeout=15)
    try:
        data = r.json()
    except Exception:
        data = {'raw': r.text}
    if r.status_code >= 400:
        print("[!] Erreur API:", r.status_code, data)
        sys.exit(1)
    return data


def do_create(api, token, label):
    data = call(api.rstrip('/') + '/api/tools/tracker/create', 'POST', token,
                {'label': label})
    print("\n[SHARINNGANNE] Lien tracker créé !")
    print("=" * 55)
    print(f"  Code      : {data['code']}")
    print(f"  Lien à partager :")
    print(f"    {data['link']}")
    print(f"  Résultats :")
    print(f"    {data['results_link']}")
    print("\n  Partagez le lien. Quand la personne clique,")
    print("  son IP et sa position seront recueillies.")
    return data


def do_results(api, token, code):
    data = call(api.rstrip('/') + f'/api/tools/tracker/{code}/results', 'GET', token)
    print(f"\n[SHARINNGANNE] Résultats du tracker {code}")
    print("=" * 55)
    print(f"  Visites captées : {data['total']}")
    hits = data.get('hits') or []
    if not hits:
        print("  Aucune visite pour le moment. Partagez le lien et attendez.")
        return
    for h in hits:
        lat = h.get('lat')
        lon = h.get('lon')
        print(f"  - IP : {h.get('ip','?')} | {h.get('city','')}, "
              f"{h.get('country','')} | position: "
              f"{f'{lat},{lon}' if lat and lon else 'N/A'} | "
              f"{h.get('isp','')} | {h.get('captured_at','')}")


def main():
    parser = argparse.ArgumentParser(description='SHARINNGANNE IP Tracker Client')
    sub = parser.add_subparsers(dest='cmd', required=True)

    c_create = sub.add_parser('create', help='Créer un lien tracker')
    c_create.add_argument('label', nargs='?', default='Tracker')
    c_create.add_argument('--api', required=True, help='URL du backend')
    c_create.add_argument('--token', required=True, help='Token JWT')

    c_res = sub.add_parser('results', help='Consulter les résultats')
    c_res.add_argument('code')
    c_res.add_argument('--api', required=True)
    c_res.add_argument('--token', required=True)

    args = parser.parse_args()
    if args.cmd == 'create':
        do_create(args.api, args.token, args.label)
    elif args.cmd == 'results':
        do_results(args.api, args.token, args.code)


if __name__ == '__main__':
    main()
