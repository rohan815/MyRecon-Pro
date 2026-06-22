#!/usr/bin/env python3
"""
MyRecon Pro - Main Entry Point
Orchestrates all footprinting modules based on command-line arguments.
"""

import argparse
import sys
import os
from core.banner import show_banner
from core.utils import print_info, print_success, print_error, print_warning, print_banner, save_json
from modules.whois_lookup import whois_lookup
from modules.dns_lookup import dns_lookup
from modules.ip_lookup import ip_lookup
from modules.headers import headers_analysis
from modules.subdomains import subdomain_enum
from modules.emails import email_harvest
from modules.shodan_lookup import shodan_lookup
from modules.netcraft_lookup import netcraft_lookup
from modules.ssl_info import ssl_info
from modules.wayback import wayback_urls

def parse_args():
    parser = argparse.ArgumentParser(
        description="MyRecon Pro - Advanced Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com                      # Full reconnaissance
  python main.py example.com --module whois,dns   # Specific modules only
  python main.py example.com --output json        # Only JSON output
  python main.py -t targets.txt                   # Batch process targets
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target domain or URL")
    parser.add_argument("-t", "--targets", help="File containing multiple targets (one per line)")
    parser.add_argument("-m", "--modules", 
                       help="Comma-separated modules to run (default: all)\n"
                            "Available: whois,dns,ip,headers,subdomains,emails,shodan,netcraft,ssl,wayback")
    parser.add_argument("--shodan-only", action="store_true", help="Run only Shodan lookup (requires IPs)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    parser.add_argument("--subdomain-list", help="Custom subdomain wordlist file")
    parser.add_argument("--no-banner", action="store_true", help="Skip ASCII banner")
    
    return parser.parse_args()

def get_modules_to_run(module_arg):
    """Parse module selection argument."""
    all_modules = {
        "whois": whois_lookup,
        "dns": dns_lookup,
        "ip": ip_lookup,
        "headers": headers_analysis,
        "subdomains": subdomain_enum,
        "emails": email_harvest,
        "shodan": shodan_lookup,
        "netcraft": netcraft_lookup,
        "ssl": ssl_info,
        "wayback": wayback_urls
    }
    
    if not module_arg:
        return all_modules  # Run all
    
    selected = {}
    for name in module_arg.lower().split(","):
        name = name.strip()
        if name in all_modules:
            selected[name] = all_modules[name]
        else:
            print_warning(f"Unknown module: '{name}'. Available: {', '.join(all_modules.keys())}")
    
    if not selected:
        print_error("No valid modules selected. Running all modules.")
        return all_modules
    
    return selected

def run_footprinting(domain, modules_to_run, subdomain_wordlist=None):
    """
    Execute the footprinting workflow.
    Modules run in dependency order.
    """
    full_results = {"target": domain, "modules": {}}
    
    # Phase 1: WHOIS (independent)
    if "whois" in modules_to_run:
        whois_data = whois_lookup(domain)
        full_results["modules"]["whois"] = whois_data
    
    # Phase 2: DNS (independent)
    if "dns" in modules_to_run:
        dns_data = dns_lookup(domain)
        full_results["modules"]["dns"] = dns_data
    
    # Phase 3: IP resolution (may depend on DNS)
    if "ip" in modules_to_run:
        ip_data = ip_lookup(domain)
        full_results["modules"]["ip"] = ip_data
    
    # Phase 4: Subdomains (independent of most)
    if "subdomains" in modules_to_run:
        sub_data = subdomain_enum(domain, subdomain_wordlist)
        full_results["modules"]["subdomains"] = sub_data
    
    # Phase 5: Emails (uses WHOIS data if available)
    if "emails" in modules_to_run:
        whois_data = full_results["modules"].get("whois", {})
        email_data = email_harvest(domain, whois_data)
        full_results["modules"]["emails"] = email_data
    
    # Phase 6: HTTP Headers
    if "headers" in modules_to_run:
        headers_data = headers_analysis(domain)
        full_results["modules"]["headers"] = headers_data
    
    # Phase 7: SSL/TLS
    if "ssl" in modules_to_run:
        ssl_data = ssl_info(domain)
        full_results["modules"]["ssl"] = ssl_data
    
   
    
    # Phase 9: Netcraft
    if "netcraft" in modules_to_run:
        netcraft_data = netcraft_lookup(domain)
        full_results["modules"]["netcraft"] = netcraft_data
    
    # Phase 10: Shodan (requires IPs — get from IP module or resolve in-line)
    if "shodan" in modules_to_run:
        # Try to get IPs from already-run IP module
        ip_list = []
        if "ip" in full_results["modules"]:
            ip_data = full_results["modules"]["ip"]
            for entry in ip_data.get("ip_addresses", []):
                ip_list.append(entry.get("ip"))
        if not ip_list:
            # Fallback: resolve now
            import socket
            try:
                _, _, ip_list = socket.gethostbyname_ex(domain)
            except:
                pass
        
        if ip_list:
            shodan_data = shodan_lookup(ip_list)
            full_results["modules"]["shodan"] = shodan_data
        else:
            print_warning("No IP addresses available for Shodan lookup")
    
    # Save consolidated results
    save_json(full_results, f"{domain}_full_recon.json")
     # Phase 8: Wayback Machine
    if "wayback" in modules_to_run:
        wayback_data = wayback_urls(domain)
        full_results["modules"]["wayback"] = wayback_data
    
    return full_results

def main():
    args = parse_args()
    
    if not args.no_banner:
        show_banner()
    
    # Collect targets
    targets = []
    if args.targets:
        with open(args.targets, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        print_info(f"Loaded {len(targets)} targets from {args.targets}")
    elif args.target:
        targets = [args.target]
    else:
        print_error("No target specified. Use 'python main.py example.com' or '-t targets.txt'")
        sys.exit(1)
    
    # Parse module selection
    modules_to_run = get_modules_to_run(args.modules)
    
    # Load custom subdomain list if provided
    subdomain_list = None
    if args.subdomain_list:
        from core.utils import read_file_lines
        subdomain_list = read_file_lines(args.subdomain_list)
        if subdomain_list:
            print_info(f"Loaded {len(subdomain_list)} custom subdomain prefixes")
    
    # Run recon on each target
    for idx, target in enumerate(targets, 1):
        print_banner(f"TARGET {idx}/{len(targets)}: {target}")
        
        # Clean up target
        domain = target.strip()
        # Remove protocol prefix if present
        if domain.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc or urlparse(domain).path
        
        if args.shodan_only:
            # Resolve IP and run Shodan only
            import socket
            try:
                _, _, ips = socket.gethostbyname_ex(domain)
                shodan_lookup(ips)
            except Exception as e:
                print_error(f"Failed to resolve {domain}: {e}")
        else:
            run_footprinting(domain, modules_to_run, subdomain_list)
    
    print_success("\nAll recon completed. Check 'output/' and 'reports/' directories.")
    
    if not args.quiet:
        print_info("\nTip: Run with '--module whois,dns,ssl' to run specific modules.")
        print_info("     Use '-t targets.txt' for batch processing.")

if __name__ == "__main__":
    main()