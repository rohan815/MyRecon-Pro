"""
MyRecon Pro - SSL/TLS Certificate Module
Fetches and parses SSL certificate details, checks expiry, issuer, SANs.
"""

import ssl
import socket
import datetime
import json
from core.utils import print_info, print_success, print_error, print_warning, print_banner, save_json

def get_certificate(hostname, port=443):
    """Retrieve SSL certificate from a server."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except socket.timeout:
        print_error(f"  Connection timeout to {hostname}:{port}")
    except ConnectionRefusedError:
        print_error(f"  Connection refused to {hostname}:{port}")
    except ssl.SSLError as e:
        print_error(f"  SSL error: {e}")
    except Exception as e:
        print_error(f"  Error: {e}")
    return None

def parse_certificate(cert, hostname):
    """Parse certificate fields into a structured dict."""
    if not cert:
        return {}
    
    # Parse validity dates
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    
    # Convert to datetime
    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        valid_from = datetime.datetime.strptime(not_before, fmt) if not_before else None
        valid_to = datetime.datetime.strptime(not_after, fmt) if not_after else None
    except ValueError:
        valid_from = str(not_before)
        valid_to = str(not_after)
    
    # Check expiry
    days_remaining = None
    if isinstance(valid_to, datetime.datetime):
        now = datetime.datetime.now()
        days_remaining = (valid_to - now).days
    
    # Extract SANs
    san_list = []
    for subj_alt in cert.get("subjectAltName", []):
        if subj_alt[0] == "DNS":
            san_list.append(subj_alt[1])
    
    result = {
        "hostname": hostname,
        "subject": dict(cert.get("subject", [[["", ""]]])[0]),
        "issuer": dict(cert.get("issuer", [[["", ""]]])[0]),
        "version": cert.get("version"),
        "serial_number": cert.get("serialNumber"),
        "valid_from": str(valid_from) if valid_from else "Unknown",
        "valid_to": str(valid_to) if valid_to else "Unknown",
        "days_remaining": days_remaining,
        "subject_alt_names": san_list,
        "fingerprint_sha256": cert.get("fingerprint", {}).get("SHA256", "N/A")
    }
    
    return result

def ssl_info(domain):
    """
    Retrieve and analyze SSL/TLS certificate for the domain.
    """
    print_banner("SSL/TLS CERTIFICATE")
    
    results = {"domain": domain, "certificates": []}
    
    # Check standard HTTPS (port 443)
    print_info(f"Fetching certificate for {domain}:443...")
    cert = get_certificate(domain, 443)
    cert_data = parse_certificate(cert, domain)
    
    if cert_data:
        results["certificates"].append(cert_data)
        
        # Display info
        issuer = cert_data.get("issuer", {}).get("organizationName", "Unknown")
        subject = cert_data.get("subject", {}).get("commonName", "Unknown")
        print_success(f"Subject CN: {subject}")
        print_success(f"Issuer: {issuer}")
        print_success(f"Valid From: {cert_data['valid_from']}")
        print_success(f"Valid To: {cert_data['valid_to']}")
        
        days = cert_data.get("days_remaining")
        if days is not None:
            if days < 0:
                print_error(f"  *** Certificate EXPIRED {abs(days)} days ago! ***")
            elif days < 30:
                print_warning(f"  Expiring in {days} days!")
            else:
                print_info(f"  Days remaining: {days}")
        
        sans = cert_data.get("subject_alt_names", [])
        print_info(f"Subject Alternative Names ({len(sans)}): {', '.join(sans[:8])}")
        if len(sans) > 8:
            print_info(f"  ... and {len(sans) - 8} more")
    
    # Also check port 8443 if common
    print_info(f"Checking {domain}:8443...")
    cert8443 = get_certificate(domain, 8443)
    if cert8443:
        cert8443_data = parse_certificate(cert8443, domain)
        results["certificates"].append(cert8443_data)
        print_success(f"  Certificate found on 8443: {cert8443_data.get('subject', {}).get('commonName', 'N/A')}")
    
    save_json(results, f"{domain}_ssl.json")
    
    return results 