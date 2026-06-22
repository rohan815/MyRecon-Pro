#!/usr/bin/env python3
"""
MyRecon Pro - WHOIS Lookup Module 
Stable version with DNS precheck, timeout handling, and safer parsing.
"""

import socket
import whois
from core.utils import (
    print_info,
    print_success,
    print_error,
    print_warning,
    print_banner,
    save_json
)


def safe_list(value):
    """Convert WHOIS fields into safe lists"""
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def whois_lookup(domain):
    print_banner("WHOIS LOOKUP")

    results = {
        "domain": domain,
        "status": "failed"
    }

    # -----------------------------
    # 1. DNS PRE-CHECK (IMPORTANT)
    # -----------------------------
    try:
        socket.setdefaulttimeout(10)
        socket.gethostbyname(domain)
    except Exception as e:
        print_error(f"DNS resolution failed: {e}")
        results["error"] = "DNS resolution failed"
        save_json(results, f"{domain}_whois.json")
        return results

    print_info(f"Querying WHOIS for {domain}...")

    # -----------------------------
    # 2. WHOIS QUERY (SAFE)
    # -----------------------------
    try:
        socket.setdefaulttimeout(15)
        w = whois.whois(domain)

        results["registrar"] = getattr(w, "registrar", None)

        results["creation_date"] = str(getattr(w, "creation_date", None))
        results["expiration_date"] = str(getattr(w, "expiration_date", None))
        results["updated_date"] = str(getattr(w, "updated_date", None))

        results["name_servers"] = safe_list(getattr(w, "name_servers", None))
        results["status"] = safe_list(getattr(w, "status", None))
        results["emails"] = safe_list(getattr(w, "emails", None))

        results["org"] = getattr(w, "org", None)
        results["country"] = getattr(w, "country", None)
        results["state"] = getattr(w, "state", None)
        results["city"] = getattr(w, "city", None)
        results["address"] = getattr(w, "address", None)

        results["status"] = "success"

        # -----------------------------
        # 3. OUTPUT SUMMARY
        # -----------------------------
        print_success(f"Registrar: {results['registrar'] or 'Unknown'}")
        print_success(f"Creation: {results['creation_date'] or 'Unknown'}")
        print_success(f"Expiration: {results['expiration_date'] or 'Unknown'}")

        if results["name_servers"]:
            print_info(f"Name Servers: {', '.join(results['name_servers'][:5])}")
        else:
            print_warning("No name servers found")

        if results["emails"]:
            print_info(f"Emails: {', '.join(results['emails'][:3])}")
        else:
            print_warning("No emails found")

        # -----------------------------
        # 4. PRIVACY DETECTION
        # -----------------------------
        combined = str(results).lower()

        privacy_keywords = [
            "redacted",
            "whoisguard",
            "privacy",
            "contact privacy",
            "domains by proxy"
        ]

        if any(k in combined for k in privacy_keywords):
            print_warning(
                "WHOIS privacy detected (registrant details hidden)"
            )

    # -----------------------------
    # 5. ERROR HANDLING (STRONG)
    # -----------------------------
    except whois.parser.PywhoisError as e:
        print_error(f"WHOIS parser error: {e}")
        results["error"] = str(e)

    except Exception as e:
        print_error(f"Unexpected WHOIS error: {e}")
        results["error"] = str(e)

    # -----------------------------
    # 6. SAVE RESULTS SAFELY
    # -----------------------------
    save_json(results, f"{domain}_whois.json")

    return results