
"""
MyRecon Pro - Shodan Lookup Module 
Queries Shodan for open ports, services, and banners on target IPs.
"""

from core.utils import (
    print_info,
    print_success,
    print_error,
    print_warning,
    print_banner,
    save_json
)

from core.config import Config


def safe_list(value):
    """Convert Shodan fields safely to list"""
    if not value:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.keys())
    return [value]


def shodan_lookup(ip_addresses):

    print_banner("SHODAN LOOKUP")

    if not Config.SHODAN_API_KEY:
        print_warning("No Shodan API key configured — skipping Shodan lookup")
        print_info("Set SHODAN_API_KEY in .env or environment variables")
        return {"error": "No API key configured"}

    try:
        import shodan
        api = shodan.Shodan(Config.SHODAN_API_KEY)
    except ImportError:
        print_error("Shodan library not installed. Run: pip install shodan")
        return {"error": "Shodan library missing"}

    results = {"hosts": []}

    for ip in ip_addresses:
        print_info(f"Querying Shodan for {ip}...")

        try:
            host = api.host(ip)

            vulns = safe_list(host.get("vulns"))

            host_data = {
                "ip": ip,
                "org": host.get("org", ""),
                "isp": host.get("isp", ""),
                "country": host.get("country_name", ""),
                "city": host.get("city", ""),
                "os": host.get("os", ""),
                "hostnames": safe_list(host.get("hostnames")),
                "ports": safe_list(host.get("ports")),
                "vulns": vulns,
                "data": []
            }

            for item in host.get("data", []):
                service = {
                    "port": item.get("port"),
                    "transport": item.get("transport", ""),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner": str(item.get("data", ""))[:200]
                }
                host_data["data"].append(service)

            results["hosts"].append(host_data)

            print_success(f"[{ip}] Open ports: {host_data['ports']}")
            print_info(f"  OS: {host_data['os'] or 'Unknown'}")
            print_info(f"  Organization: {host_data['org'] or 'Unknown'}")

            if vulns:
                print_warning(f"  CVEs: {', '.join(vulns[:5])}")

        except shodan.APIError as e:
            print_error(f"Shodan API error for {ip}: {e}")

        except Exception as e:
            print_error(f"Unexpected Shodan error for {ip}: {e}")

    if results["hosts"]:
        save_json(results, "shodan_results.json")
        print_success("Results saved to shodan_results.json")

    return results



if __name__ == "__main__":

    print_banner("SHODAN MODULE TEST RUN")

    raw_input = input("Enter IP(s) separated by comma: ")

    ip_list = [ip.strip() for ip in raw_input.split(",") if ip.strip()]

    if not ip_list:
        print_error("No IPs provided!")
        exit()

    result = shodan_lookup(ip_list)

    print_success("\nScan Completed")