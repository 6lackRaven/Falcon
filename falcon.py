#!/usr/bin/env python3
"""
Falcon V3
Self-contained OSINT toolkit 
Includes: WHOIS, DNS, IP (geo+port scan), Phone (phonenumbers + folium),
Username enumeration, Subdomain brute force (small list)

Usage:
  python falcon -d example.com -i 8.8.8.8 -u someuser -p +237600000000

Dependencies:
  pip install requests python-whois dnspython phonenumbers folium pycountry

Author: Raven Obsidian
Version: 3.0
"""

import argparse
import json
import socket
import concurrent.futures
import whois
import dns.resolver
import requests
import re
import hashlib
from datetime import datetime
from pathlib import Path

# phone libs
import phonenumbers
from phonenumbers import geocoder, carrier
import pycountry
import folium

# -----------------------------
# Configuration / Helpers
# -----------------------------
REPORTS_DIR = Path('reports')
REPORTS_DIR.mkdir(exist_ok=True)
COMMON_SUBDOMAINS = ['www', 'mail', 'ftp', 'webmail', 'admin', 'blog', 'dev', 'api', 'staging']
USERNAME_HOSTS = {
    'github': 'https://github.com/{}',
    'twitter': 'https://twitter.com/{}',
    'instagram': 'https://instagram.com/{}',
    'reddit': 'https://reddit.com/user/{}',
    'tiktok': 'https://tiktok.com/@{}',
    'youtube': 'https://youtube.com/@{}',
    'steam': 'https://steamcommunity.com/id/{}',
    'gitlab': 'https://gitlab.com/{}'
}

# small country centroid table (extend as needed)
_COUNTRY_CENTROIDS = {
    'US': (39.8283, -98.5795),
    'GB': (55.3781, -3.4360),
    'FR': (46.2276, 2.2137),
    'DE': (51.1657, 10.4515),
    'NG': (9.0820, 8.6753),
    'CM': (7.3697, 12.3547),
    'CN': (35.8617, 104.1954),
    'IN': (20.5937, 78.9629),
    'BR': (-14.2350, -51.9253),
    'ZA': (-30.5595, 22.9375),
    'JP': (36.2048, 138.2529),
    'CA': (56.1304, -106.3468),
    'AU': (-25.2744, 133.7751)
}

# -----------------------------
# WHOIS Module
# -----------------------------
def whois_lookup(domain):
    out = {'domain': domain, 'whois': {}, 'error': None}
    try:
        w = whois.whois(domain)
        out['whois'] = {
            'registrar': getattr(w, 'registrar', None),
            'creation_date': str(getattr(w, 'creation_date', None)),
            'expiration_date': str(getattr(w, 'expiration_date', None)),
            'name_servers': getattr(w, 'name_servers', None),
            'emails': getattr(w, 'emails', None)
        }
    except Exception as e:
        out['error'] = str(e)
    return out

# -----------------------------
# DNS Module
# -----------------------------
def dns_lookup(domain):
    out = {'domain': domain, 'records': {}, 'error': None}
    types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    resolver = dns.resolver.Resolver()
    for t in types:
        try:
            answers = resolver.resolve(domain, t, lifetime=5)
            out['records'][t] = [str(a.to_text()) for a in answers]
        except Exception:
            out['records'][t] = []
    return out

# -----------------------------
# IP Module (geo + port scan)
# -----------------------------
def ip_geo_lookup(ip):
    out = {'ip': ip, 'geo': {}, 'source': None}
    try:
        r = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        if r.status_code == 200:
            jd = r.json()
            out['geo'] = {
                'ip': jd.get('ip'),
                'city': jd.get('city'),
                'region': jd.get('region'),
                'country': jd.get('country'),
                'loc': jd.get('loc'),
                'org': jd.get('org')
            }
            out['source'] = 'ipinfo.io'
    except Exception:
        out['source'] = 'local_fallback'
    return out

def port_scan(ip, ports=None, max_workers=50, timeout=1):
    if ports is None:
        ports = [21,22,23,25,53,80,110,143,443,465,587,993,995,3306,3389]
    open_ports = []

    def scan(p):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            res = sock.connect_ex((ip, p))
            sock.close()
            return p if res == 0 else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(scan, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                open_ports.append(r)
    return open_ports

def ip_tools(ip):
    out = {'ip': ip}
    try:
        out['geo'] = ip_geo_lookup(ip)['geo']
    except Exception:
        out['geo'] = {}
    out['open_ports'] = port_scan(ip)
    # Save simple report
    fname = REPORTS_DIR / f'ip_report_{ip.replace(":","_")}.json'
    fname.write_text(json.dumps(out, indent=2))
    print(f"[+] IP report saved: {fname}")
    print(json.dumps(out, indent=2))
    return out

# -----------------------------
# Phone Module
# -----------------------------
def get_country_centroid(alpha2):
    return _COUNTRY_CENTROIDS.get(alpha2.upper()) if alpha2 else None

def phone_scan(phone, save_map=True):
    out = {'input': phone, 'valid': False, 'e164': None, 'country': None,
           'country_code': None, 'region': None, 'carrier': None, 'map': None, 'notes': []}
    try:
        parsed = phonenumbers.parse(phone, None)
    except Exception as e:
        out['notes'].append(f'parse_error:{e}')
        print(json.dumps(out, indent=2))
        return out

    out['valid'] = phonenumbers.is_valid_number(parsed)
    out['e164'] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    cc = phonenumbers.region_code_for_number(parsed)
    out['country'] = cc
    out['country_code'] = parsed.country_code
    try:
        out['region'] = geocoder.description_for_number(parsed, 'en')
    except Exception:
        out['region'] = None
    try:
        out['carrier'] = carrier.name_for_number(parsed, 'en')
    except Exception:
        out['carrier'] = None

    centroid = get_country_centroid(cc)
    if save_map and centroid:
        lat, lon = centroid
        m = folium.Map(location=[lat, lon], zoom_start=5)
        popup = f"{out['e164']}<br>Country: {cc}<br>Region: {out.get('region')}<br>Carrier: {out.get('carrier')}"
        folium.Marker([lat, lon], popup=popup).add_to(m)
        map_name = f"phone_map_{cc}_{re.sub(r'\\D','',out['e164'])}.html"
        path = REPORTS_DIR / map_name
        m.save(str(path))
        out['map'] = str(path)

    fname = REPORTS_DIR / f'phone_report_{re.sub(r"\\D","",(out.get("e164") or phone))}.json'
    fname.write_text(json.dumps(out, indent=2))
    print(f"[+] Phone report saved: {fname}")
    print(json.dumps(out, indent=2))
    return out

# -----------------------------
# Username enumeration
# -----------------------------
def username_enum(username, timeout=6):
    results = {}
    headers = {'User-Agent': 'FalconV3/2.0'}
    for k, url in USERNAME_HOSTS.items():
        try:
            r = requests.get(url.format(username), headers=headers, timeout=timeout, allow_redirects=False)
            if r.status_code == 200:
                results[k] = {'status': 'found', 'url': url.format(username)}
            elif r.status_code in (301,302) and 'Location' in r.headers:
                results[k] = {'status': 'redirect', 'location': r.headers.get('Location')}
            else:
                results[k] = {'status': 'not_found', 'code': r.status_code}
        except Exception as e:
            results[k] = {'status': 'error', 'error': str(e)}
    fname = REPORTS_DIR / f'user_enum_{username}.json'
    fname.write_text(json.dumps({'username': username, 'results': results}, indent=2))
    print(f"[+] Username enumeration saved: {fname}")
    print(json.dumps({'username': username, 'results': results}, indent=2))
    return results

# -----------------------------
# Subdomain brute force (simple)
# -----------------------------
def subdomain_bruteforce(domain, wordlist=None, timeout=3):
    found = []
    headers = {'User-Agent': 'FalconV3/2.0'}
    if wordlist is None:
        to_check = COMMON_SUBDOMAINS
    else:
        to_check = wordlist

    def probe(sub):
        host = f"{sub}.{domain}"
        try:
            r = requests.get(f'https://{host}', headers=headers, timeout=timeout, allow_redirects=False)
            return host if r.status_code < 400 else None
        except Exception:
            try:
                r = requests.get(f'http://{host}', headers=headers, timeout=timeout, allow_redirects=False)
                return host if r.status_code < 400 else None
            except Exception:
                return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(probe, s) for s in to_check]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                found.append(r)

    fname = REPORTS_DIR / f'subdomains_{domain}.json'
    fname.write_text(json.dumps({'domain': domain, 'subdomains': found}, indent=2))
    print(f"[+] Subdomain bruteforce saved: {fname}")
    print(json.dumps({'subdomains': found}, indent=2))
    return found

# -----------------------------
# Reporting helper
# -----------------------------
def save_report(data, name_prefix='report'):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = REPORTS_DIR / f"{name_prefix}_{ts}.json"
    fname.write_text(json.dumps(data, indent=2))
    return str(fname)

# -----------------------------
# CLI / Main
# -----------------------------
def parse_args():
    p = argparse.ArgumentParser(description='Falcon V3')
    p.add_argument('-d', '--domain', help='Domain to analyze')
    p.add_argument('-i', '--ip', help='IP address to analyze')
    p.add_argument('-u', '--username', help='Username to enumerate')
    p.add_argument('-p', '--phone', help='Phone number to analyze (E.164 suggested)')
    p.add_argument('--subdomains', action='store_true', help='Run subdomain brute force for domain')
    return p.parse_args()

def main():
    args = parse_args()
    if not any([args.domain, args.ip, args.username, args.phone]):
        print('Nothing to do. Use -h for help.')
        return

    if args.domain:
        print('\n=== WHOIS Lookup ===')
        w = whois_lookup(args.domain)
        print(json.dumps(w, indent=2))
        print('\n=== DNS Lookup ===')
        d = dns_lookup(args.domain)
        print(json.dumps(d, indent=2))
        if args.subdomains:
            print('\n=== Subdomain Bruteforce ===')
            subdomain_bruteforce(args.domain)

    if args.ip:
        print('\n=== IP Analysis ===')
        ip_tools(args.ip)

    if args.username:
        print('\n=== Username Enumeration ===')
        username_enum(args.username)

    if args.phone:
        print('\n=== Phone Analysis ===')
        phone_scan(args.phone)

    print('\n[!] Done. Reports saved in ./reports')

if __name__ == '__main__':
    main()
