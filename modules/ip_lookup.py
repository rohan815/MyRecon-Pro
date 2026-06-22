"""
MyRecon Pro - IP Lookup Module
Resolves domain to IP, then gathers IP geolocation and hosting info.
"""

import socket
import requests
from core.utils import print_info, print_success, print_error, print_banner, make_request, save_json, rate_limiter
from core.config import Config

def get_ip_addresses(domain):
    """Resolve domain to IPv4 addresses."""
    ips = []
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        ips = ip_list
        print_success(f"Resolved IPs: {', '.join(ips)}")
    except socket.gaierror:
        print_error(f"Could not resolve {domain}")
    except Exception as e:
        print_error(f"DNS resolution error: {e}")
    return ips

def ip_geolocation(ip):
    """Get geolocation data for an IP address."""
    rate_limiter.wait()
    
    # Using ip-api.com (free, no API key needed)
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,reverse,query"
    
    try:
        resp = make_request(url)
        if resp:
            data = resp.json()
            if data.get("status") == "success":
                print_success(f"[{ip}] {data.get('city')}, {data.get('regionName')}, {data.get('country')}")
                print_info(f"  ISP: {data.get('isp')}")
                print_info(f"  Organization: {data.get('org')}")
                print_info(f"  ASN: {data.get('as')}")
                return data
            else:
                print_error(f"[{ip}] Geolocation failed: {data.get('message', 'unknown')}")
        return None
    except Exception as e:
        print_error(f"[{ip}] Geolocation error: {e}")
        return None

def ip_lookup(domain):
    """
    Full IP intelligence: resolution + geolocation.
    """
    print_banner("IP LOOKUP")
    
    results = {"domain": domain, "ip_addresses": []}
    
    ips = get_ip_addresses(domain)
    
    for ip in ips:
        geo = ip_geolocation(ip)
        results["ip_addresses"].append({
            "ip": ip,
            "geolocation": geo
        })
    
    save_json(results, f"{domain}_ip.json")
    
    return results