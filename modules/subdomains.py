"""
MyRecon Pro - Subdomain Enumeration Module
Discovers subdomains via DNS brute-force and certificate transparency logs.
"""

import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils import (
    print_info, print_success, print_error,
    print_warning, print_banner, save_json, rate_limiter
)

from core.config import Config


def check_subdomain(domain, prefix):
    sub = f"{prefix}.{domain}"
    rate_limiter.wait()

    try:
        answers = dns.resolver.resolve(sub, "A")
        ips = [str(r) for r in answers]

        if ips:
            return sub, ips

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception:
        pass

    return None


def brute_force_subdomains(domain, wordlist=None):
    prefixes = wordlist or Config.COMMON_SUBDOMAIN_PREFIXES

    print_info(f"Brute-forcing {len(prefixes)} subdomains...")

    found = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        fut_to_prefix = {executor.submit(check_subdomain, domain, p): p for p in prefixes}

        for future in as_completed(fut_to_prefix):
            try:
                result = future.result()
            except Exception:
                continue

            if result:
                sub, ips = result
                print_success(f"  {sub} -> {', '.join(ips)}")
                found.append({"subdomain": sub, "ip_addresses": ips})

    return found


def crtsh_lookup(domain):
    print_info("Querying crt.sh certificate transparency logs...")

    found = []

    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        resp = requests.get(
            url,
            headers={"User-Agent": Config.USER_AGENT},
            timeout=30
        )

        if resp.status_code != 200:
            print_warning(f"  crt.sh returned HTTP {resp.status_code}")
            return found

        try:
            data = resp.json()
        except Exception:
            print_warning("  crt.sh returned invalid JSON (likely timeout/HTML response)")
            return found

        seen = set()

        for entry in data:
            name = entry.get("name_value", "")

            for sub in name.split("\n"):
                sub = sub.strip().lower()

                if sub.endswith(f".{domain}") and sub not in seen:
                    seen.add(sub)
                    found.append({
                        "subdomain": sub,
                        "source": "crt.sh",
                        "id": entry.get("id")
                    })
                    print_success(f"  {sub}")

        if not found:
            print_info("  No subdomains found via crt.sh")

    except requests.exceptions.Timeout:
        print_error("  crt.sh timeout (try again later)")
    except requests.exceptions.RequestException as e:
        print_error(f"  crt.sh request error: {e}")
    except Exception as e:
        print_error(f"  crt.sh error: {e}")

    return found


def subdomain_enum(domain, wordlist=None):
    print_banner("SUBDOMAIN ENUMERATION")

    results = {"domain": domain, "subdomains": []}

    # Phase 1: crt.sh
    crtsh_results = crtsh_lookup(domain)
    results["subdomains"].extend(crtsh_results)

    # Phase 2: DNS brute-force
    brute_results = brute_force_subdomains(domain, wordlist)
    results["subdomains"].extend(brute_results)

    # Deduplicate
    seen = set()
    unique = []

    for s in results["subdomains"]:
        key = s["subdomain"].lower()

        if key not in seen:
            seen.add(key)
            unique.append(s)

    results["subdomains"] = unique

    print_success(f"\nTotal unique subdomains found: {len(unique)}")

    save_json(results, f"{domain}_subdomains.json")

    return results