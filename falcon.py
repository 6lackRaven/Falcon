#!/usr/bin/env python3
# falcon.py

import argparse
import json
import re
import time
import requests
import ipaddress
import dns.resolver
import whois
import socket
from datetime import datetime
import hashlib

# ==============================
# CONFIGURATION
# ==============================
__author__ = "6lackRaven"
__version__ = "1.0"
__github__ = "https://github.com/6lackRaven"
__readonly__ = True  # File integrity protection

# ==============================
# FALCON BANNER
# ==============================
def print_banner():
    print(f"""
\033[1;33m
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  🦅
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  \033[1;36mFalcon OSINT v{__version__}\033[1;33m
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  \033[1;35mDeveloped by {__author__}\033[1;33m
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  \033[1;34m{__github__}\033[1;33m
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀  \033[1;32mSwooping through digital landscapes\033[1;33m
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀  \033[1;31mKeen-eyed intelligence gathering\033[1;33m
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠛⠛⠛⠛⠛⠛⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\033[0m
\033[1;31m
╔════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ ███████ ██╗  ██╗███████╗    ██████╗  █████╗ ██╗      ██████╗  ██████╗ ███╗   ██╗███████╗██████╗   ║
║ ██╔════╝╚██╗██╔╝██╔════╝    ██╔══██╗██╔══██╗██║     ██╔═══██╗██╔════╝ ████╗  ██║██╔════╝██╔══██╗  ║
║ █████╗   ╚███╔╝ █████╗      ██████╔╝███████║██║     ██║   ██║██║  ███╗██╔██╗ ██║█████╗  ██████╔╝  ║
║ ██╔══╝   ██╔██╗ ██╔══╝      ██╔══██╗██╔══██║██║     ██║   ██║██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗  ║
║ ███████╗██╔╝ ██╗███████╗    ██║  ██║██║  ██║███████╗╚██████╔╝╚██████╔╝██║ ╚████║███████╗██║  ██║  ║
║ ╚══════╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝  ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════╝
\033[0m
\033[1;33m
[!] ETHICAL USAGE ONLY: This tool is for authorized security research and penetration testing.
[!] NEVER target systems without explicit written permission.
[!] RESPECT all applicable laws and privacy regulations.
[!] Developers assume NO liability for misuse.
\033[0m
""")

# ==============================
# ENHANCED FUNCTIONALITY
# ==============================
def social_media_deep_search(username):
    """Enhanced social media analysis with platform-specific metadata"""
    services = {
        "github": f"https://github.com/{username}",
        "twitter": f"https://twitter.com/{username}",
        "instagram": f"https://instagram.com/{username}",
        "reddit": f"https://reddit.com/user/{username}",
        "youtube": f"https://youtube.com/@{username}",
        "tiktok": f"https://tiktok.com/@{username}",
        "twitch": f"https://twitch.tv/{username}",
        "pinterest": f"https://pinterest.com/{username}",
        "steam": f"https://steamcommunity.com/id/{username}",
        "vk": f"https://vk.com/{username}",
        "gitlab": f"https://gitlab.com/{username}",
        "medium": f"https://medium.com/@{username}",
        "keybase": f"https://keybase.io/{username}",
        "hackerone": f"https://hackerone.com/{username}",
        "bugcrowd": f"https://bugcrowd.com/{username}"
    }
    
    results = {}
    for platform, url in services.items():
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                results[platform] = {"url": url, "status": "found"}
            elif response.status_code in [301, 302]:
                results[platform] = {"url": url, "status": "redirect", "location": response.headers.get('Location')}
            else:
                results[platform] = {"url": url, "status": "not_found"}
            time.sleep(1)
        except Exception as e:
            results[platform] = {"url": url, "status": "error", "message": str(e)}
    
    # Profile content analysis
    try:
        gh_response = requests.get(f"https://api.github.com/users/{username}")
        if gh_response.status_code == 200:
            gh_data = gh_response.json()
            results['github']['meta'] = {
                'name': gh_data.get('name'),
                'bio': gh_data.get('bio'),
                'repos': gh_data.get('public_repos'),
                'created_at': gh_data.get('created_at')
            }
    except:
        pass
    
    # Twitter metadata
    try:
        tw_response = requests.get(f"https://cdn.syndication.twimg.com/widgets/followbutton/info.json?screen_names={username}")
        if tw_response.status_code == 200:
            tw_data = tw_response.json()
            if tw_data:
                results['twitter']['meta'] = {
                    'name': tw_data[0].get('name'),
                    'followers': tw_data[0].get('followers_count'),
                    'verified': tw_data[0].get('verified')
                }
    except:
        pass
    
    return results

def dark_web_monitor(email):
    """Check dark web exposure using breach databases"""
    results = {'breaches': [], 'exposed_data': []}
    
    try:
        # Check Have I Been Pwned
        headers = {"hibp-api-key": "YOUR_HIBP_API_KEY"} 
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers, timeout=10
        )
        if response.status_code == 200:
            results['breaches'] = [{"name": b["Name"], "date": b["BreachDate"]} for b in response.json()]
    except:
        pass
    
    return results

def email_scan(email):
    """Comprehensive email analysis"""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"error": "Invalid email format"}
    
    if any(entity in email for entity in ['.gov', '.mil', '.police']):
        return {"error": "Restricted entity prohibited"}
    
    results = {
        "email": email,
        "breaches": [],
        "gravatar": {},
        "domain_info": {},
        "disposable": False
    }
    
    # Check disposable email
    disposable_domains = ["tempmail", "10minutemail", "guerrillamail", "mailinator"]
    domain = email.split('@')[-1]
    if any(d in domain for d in disposable_domains):
        results["disposable"] = True
    
    # Get domain info
    results["domain_info"] = domain_scan(domain)
    
    # Check breaches
    results.update(dark_web_monitor(email))
    
    # Gravatar profile
    gravatar_hash = hashlib.md5(email.lower().encode()).hexdigest()
    results["gravatar"] = {
        "profile": f"https://gravatar.com/{gravatar_hash}",
        "image": f"https://gravatar.com/avatar/{gravatar_hash}"
    }
    
    return results

def phone_scan(phone):
    """Phone number intelligence"""
    phone = re.sub(r'\D', '', phone)
    
    if len(phone) < 7:
        return {"error": "Invalid phone number"}
    
    if any(entity in phone for entity in ['1555', '1666', '1777']):
        return {"error": "Military/government numbers prohibited"}
    
    results = {}
    
    # Use abstractapi.com
    try:
        response = requests.get(
            f"https://phonevalidation.abstractapi.com/v1/?api_key=YOUR_ABSTRACT_API_KEY&phone={phone}",
            timeout=10
        )
        data = response.json()
        
        if data.get("valid"):
            results = {
                "number": data.get("format", {}).get("international"),
                "location": data.get("location"),
                "carrier": data.get("carrier"),
                "country": data.get("country", {}).get("name"),
                "prefix": data.get("country", {}).get("prefix")
            }
    except:
        pass
    
    return results

def domain_scan(domain):
    """Comprehensive domain analysis"""
    if any(entity in domain for entity in ['.gov', '.mil', '.police']):
        return {"error": "Restricted entity prohibited"}
    
    results = {
        "domain": domain,
        "dns": {},
        "whois": {},
        "subdomains": [],
        "security": {}
    }
    
    # DNS Records
    try:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                results["dns"][rtype] = [str(r) for r in answers]
            except:
                pass
    except:
        pass
    
    # WHOIS Lookup
    try:
        w = whois.whois(domain)
        results["whois"] = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails
        }
    except:
        pass
    
    # Subdomain discovery
    try:
        common_subdomains = ['www', 'mail', 'ftp', 'webmail', 'admin', 'blog', 'dev']
        for sub in common_subdomains:
            try:
                socket.gethostbyname(f"{sub}.{domain}")
                results["subdomains"].append(f"{sub}.{domain}")
            except:
                pass
    except:
        pass
    
    # Security headers
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        security_headers = [
            'Strict-Transport-Security', 
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection'
        ]
        results["security"]["headers"] = {
            h: response.headers.get(h, "MISSING") for h in security_headers
        }
    except:
        pass
    
    return results

def ip_scan(ip):
    """IP address intelligence"""
    if ipaddress.ip_address(ip).is_private:
        return {"error": "Private IP addresses are blocked"}
    
    if any(entity in ip for entity in ['.gov', '.mil']):
        return {"error": "Restricted entity prohibited"}
    
    results = {
        "ip": ip,
        "geo": {},
        "ports": [],
        "shodan": {}
    }
    
    # GeoIP information
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        geo_data = response.json()
        results["geo"] = {
            "country": geo_data.get("country_name"),
            "region": geo_data.get("region"),
            "city": geo_data.get("city"),
            "isp": geo_data.get("org"),
            "asn": geo_data.get("asn")
        }
    except:
        pass
    
    # Common port scan
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                results["ports"].append(port)
        except:
            pass
    
    # Shodan data
    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key=YOUR_SHODAN_API_KEY",
            timeout=10
        )
        shodan_data = response.json()
        results["shodan"] = {
            "ports": shodan_data.get("ports", []),
            "services": [f"{item['port']}/{item['transport']} ({item.get('product','')})" 
                         for item in shodan_data.get('data', [])]
        }
    except:
        pass
    
    return results

def vulnerability_scan(domain):
    """Scan for common web vulnerabilities"""
    results = {'vulnerabilities': []}
    
    # Check for common misconfigurations
    try:
        # Check for exposed .git repository
        response = requests.get(f"https://{domain}/.git/HEAD", timeout=5)
        if response.status_code == 200 and "ref:" in response.text:
            results['vulnerabilities'].append({
                'type': 'EXPOSED_SOURCE_CODE',
                'severity': 'CRITICAL',
                'description': 'Git repository exposed publicly'
            })
    except:
        pass
    
    # Check for S3 bucket misconfigurations
    try:
        response = requests.get(f"http://{domain}.s3.amazonaws.com", timeout=5)
        if response.status_code == 200:
            results['vulnerabilities'].append({
                'type': 'MISCONFIGURED_S3_BUCKET',
                'severity': 'HIGH',
                'description': 'S3 bucket exists and may be misconfigured'
            })
    except:
        pass
    
    return results

def generate_report(data, format='html'):
    """Generate professional OSINT report"""
    if format == 'html':
        # Create HTML report template
        report = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Falcon OSINT Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #0f0f23; color: #ffffff; }}
                .header {{ text-align: center; padding: 20px; background: #1a1a2e; }}
                .results {{ padding: 20px; }}
                .section {{ margin-bottom: 30px; background: #16213e; padding: 15px; border-radius: 5px; }}
                h1 {{ color: #4ecca3; }}
                h2 {{ color: #4ecca3; border-bottom: 1px solid #4ecca3; padding-bottom: 5px; }}
                .vulnerability {{ color: #ff5555; font-weight: bold; }}
                .falcon-logo {{ text-align: center; font-size: 48px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <div class="falcon-logo">🦅</div>
                <h1>Falcon OSINT Report</h1>
                <h3>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</h3>
            </div>
            <div class="results">
                <pre>{json.dumps(data, indent=2)}</pre>
            </div>
            <div class="footer">
                <p>Generated by Falcon v{__version__} | github.com/6lackRaven</p>
            </div>
        </body>
        </html>
        """
        return report
    else:
        return json.dumps(data, indent=2)

# ==============================
# MAIN FUNCTION
# ==============================
def main():
    parser = argparse.ArgumentParser(
        description="Falcon - Advanced Digital Reconnaissance Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-u', '--username', help="Deep social media search")
    parser.add_argument('-e', '--email', help="Email analysis with dark web monitoring")
    parser.add_argument('-p', '--phone', help="Phone number intelligence")
    parser.add_argument('-d', '--domain', help="Domain reconnaissance")
    parser.add_argument('-i', '--ip', help="IP address investigation")
    parser.add_argument('-vuln', '--vulnerability', metavar='DOMAIN', help="Scan for web vulnerabilities")
    parser.add_argument('-r', '--report', choices=['html', 'json'], help="Generate professional report")
    
    args = parser.parse_args()
    
    print_banner()
    
    # Execute requested operation
    if args.username:
        result = {"username": args.username, "results": social_media_deep_search(args.username)}
    elif args.email:
        result = email_scan(args.email)
    elif args.phone:
        result = {"phone": args.phone, "info": phone_scan(args.phone)}
    elif args.domain:
        result = {"domain": args.domain, "info": domain_scan(args.domain)}
        # Add vulnerability scan if requested
        if args.vulnerability:
            result['vulnerabilities'] = vulnerability_scan(args.domain)
    elif args.ip:
        result = {"ip": args.ip, "info": ip_scan(args.ip)}
    else:
        parser.print_help()
        return
    
    # Generate report if requested
    if args.report:
        report = generate_report(result, format=args.report)
        filename = f"falcon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{'html' if args.report == 'html' else 'json'}"
        with open(filename, 'w') as f:
            f.write(report)
        print(f"\n\033[1;32m[+] Report generated: {filename}\033[0m")
    else:
        # Display results in terminal
        print(json.dumps(result, indent=2))
    
    # Show ethical reminder
    print("\n\033[1;33m[!] Remember: With great power comes great responsibility. Use ethically!\033[0m")

if __name__ == "__main__":
    # File protection mechanism
    if __readonly__:
        try:
            # Attempt to modify file (should fail in production)
            with open(__file__, 'a') as f:
                f.write("\n# Attempted modification")
            print("\033[1;31m[!] Security alert: File modification detected!\033[0m")
        except:
            pass
    main()

# Attempted modification