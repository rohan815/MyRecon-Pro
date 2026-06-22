"""
MyRecon Pro - Email Harvesting Module
Extracts emails from web pages, WHOIS, and TXT records.
"""

import re
from core.utils import print_info, print_success, print_error, print_banner, make_request, save_json

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

def extract_emails_from_text(text):
    """Extract email addresses from raw text using regex."""
    return list(set(re.findall(EMAIL_REGEX, text)))

def scrape_webpage_emails(domain):
    """Fetch the domain homepage and extract emails."""
    print_info("Scraping homepage for email addresses...")
    emails = []
    for protocol in ["https://", "http://"]:
        url = f"{protocol}{domain}"
        resp = make_request(url)
        if resp:
            found = extract_emails_from_text(resp.text)
            # Filter out generic/noreply addresses
            filtered = [e for e in found if not e.startswith(("noreply", "no-reply", "donotreply"))]
            emails.extend(filtered)
            print_success(f"  Found {len(filtered)} emails from {url}")
            break  # Only need one successful fetch
    return emails

def extract_txt_record_emails(domain):
    """Extract emails from DNS TXT records (e.g. SPF, DMARC)."""
    import dns.resolver
    emails = []
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata)
            found = extract_emails_from_text(txt)
            emails.extend(found)
    except Exception:
        pass
    return emails

def email_harvest(domain, whois_data=None):
    """
    Harvest emails from multiple sources: webpage, TXT records, WHOIS.
    """
    print_banner("EMAIL HARVESTING")
    
    results = {"domain": domain, "email_addresses": []}
    
    # Source 1: Webpage scraping
    web_emails = scrape_webpage_emails(domain)
    for e in web_emails:
        results["email_addresses"].append({"email": e, "source": "webpage"})
        print_success(f"  [web] {e}")
    
    # Source 2: TXT records
    txt_emails = extract_txt_record_emails(domain)
    for e in txt_emails:
        results["email_addresses"].append({"email": e, "source": "TXT record"})
        print_success(f"  [dns] {e}")
    
    # Source 3: WHOIS (if provided)
    if whois_data and "emails" in whois_data:
        for e in whois_data["emails"]:
            if e:
                results["email_addresses"].append({"email": e, "source": "WHOIS"})
                print_success(f"  [whois] {e}")
    
    print_success(f"\nTotal emails found: {len(results['email_addresses'])}")
    
    save_json(results, f"{domain}_emails.json")
    
    return results
