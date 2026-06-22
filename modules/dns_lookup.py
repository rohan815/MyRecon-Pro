"""
MyRecon Pro - DNS Lookup Module 
Improved resolver with public DNS + retry support.
"""

import dns.resolver
from core.utils import print_info, print_success, print_error, print_banner, save_json


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def create_resolver():
    """Use fast public DNS servers"""
    resolver = dns.resolver.Resolver()

    # Cloudflare + Google DNS (faster + more stable)
    resolver.nameservers = [
        "1.1.1.1",
        "8.8.8.8",
        "8.8.4.4"
    ]

    resolver.timeout = 3
    resolver.lifetime = 5

    return resolver


def safe_resolve(resolver, domain, rtype):
    """Resolve with retry"""
    for _ in range(2):  # retry twice
        try:
            return resolver.resolve(domain, rtype)
        except Exception:
            continue
    return None


def dns_lookup(domain):

    print_banner("DNS ENUMERATION")

    results = {
        "domain": domain,
        "records": {}
    }

    resolver = create_resolver()

    for rtype in RECORD_TYPES:
        print_info(f"Querying {rtype} records...")

        try:
            answers = safe_resolve(resolver, domain, rtype)

            if not answers:
                print_error(f"  Timeout / no response for {rtype}")
                continue

            records = []

            for rdata in answers:
                if rtype == "MX":
                    records.append({
                        "priority": rdata.preference,
                        "exchange": str(rdata.exchange)
                    })

                elif rtype == "SOA":
                    records.append({
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial
                    })

                else:
                    records.append(str(rdata))

            results["records"][rtype] = records

            for rec in records[:5]:
                print_success(f"  {rtype}: {rec}")

        except dns.resolver.NXDOMAIN:
            print_error("Domain does not exist")
            break

        except Exception as e:
            print_error(f"Error querying {rtype}: {e}")

    save_json(results, f"{domain}_dns.json")

    return results