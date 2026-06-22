"""
MyRecon Pro - Netcraft Lookup Module (Improved)
"""

import re
import requests
from bs4 import BeautifulSoup

from core.utils import (
    print_info, print_success, print_error,
    print_warning, print_banner, save_json,
    rate_limiter
)

NETCRAFT_URL = "https://sitereport.netcraft.com/?url={}"


def extract_value(text, pattern):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"


def netcraft_lookup(domain):
    print_banner("NETCRAFT SITE REPORT")
    print_info(f"Fetching Netcraft report for {domain}...")

    rate_limiter.wait()

    url = NETCRAFT_URL.format(domain)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.google.com/"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=20)

        if resp.status_code != 200:
            print_warning(f"HTTP Error: {resp.status_code}")
            return {"domain": domain, "error": f"HTTP {resp.status_code}"}

        html = resp.text

        # Debug (uncomment if needed)
        # print(html[:1000])

        soup = BeautifulSoup(html, "html.parser")

        text = soup.get_text(" ", strip=True)

        results = {
            "domain": domain,
            "server_software": extract_value(text, r"Server.*?:\s*(.+?)\s"),
            "hosting_provider": extract_value(text, r"Hosting.*?:\s*(.+?)\s"),
            "ip_address": extract_value(text, r"IP Address.*?:\s*([\d\.]+)"),
            "nameservers": [],
            "technology_stack": []
        }

        # Fallback: try table parsing if regex fails
        for row in soup.find_all("tr"):
            cols = row.find_all("td")
            if len(cols) >= 2:
                key = cols[0].get_text(strip=True).lower()
                val = cols[1].get_text(strip=True)

                if "server" in key and results["server_software"] == "N/A":
                    results["server_software"] = val

                elif "hosting" in key and results["hosting_provider"] == "N/A":
                    results["hosting_provider"] = val

                elif "ip" in key and results["ip_address"] == "N/A":
                    ip = re.findall(r"\d+\.\d+\.\d+\.\d+", val)
                    if ip:
                        results["ip_address"] = ip[0]

        # If everything still N/A → likely blocked or layout changed
        if all(v == "N/A" or v == [] for v in results.values()):
            print_warning("Netcraft returned empty/blocked response")

        print_success(f"Server: {results['server_software']}")
        print_success(f"Hosting: {results['hosting_provider']}")
        print_success(f"IP: {results['ip_address']}")

        save_json(results, f"{domain}_netcraft.json")
        print_success(f"Saved: {domain}_netcraft.json")

        return results

    except Exception as e:
        print_error(f"Netcraft error: {e}")
        return {"domain": domain, "error": str(e)}