"""
MyRecon Pro - Wayback Machine Module
Pulls historical URLs and snapshots from archive.org for hidden endpoints.
"""
import json
from core.utils import print_info, print_success, print_error, print_warning, print_banner, make_request, save_json

def wayback_urls(domain):
    """
    Query Wayback Machine CDX API for historical URLs.
    """
    print_banner("WAYBACK MACHINE - HISTORICAL URLS")
    print_info(f"Fetching historical URLs for {domain} from archive.org...")
    
    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*"
        f"&output=json"
        f"&fl=timestamp,original,statuscode,length"
        f"&collapse=urlkey"
        f"&limit=5000"
    )
    
    resp = make_request(cdx_url)
    if not resp:
        return {"domain": domain, "urls": []}
    
    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        print_error("Failed to parse Wayback CDX response")
        return {"domain": domain, "urls": []}
    
    # First entry is header row
    if len(data) <= 1:
        print_info("No historical URLs found")
        return {"domain": domain, "urls": []}
    
    urls = []
    seen = set()
    
    for entry in data[1:]:  # Skip header
        if len(entry) < 4:
            continue
        
        timestamp, original_url, status_code, length = entry[0], entry[1], entry[2], entry[3]
        
        # Skip duplicate URLs
        if original_url in seen:
            continue
        seen.add(original_url)
        
        # Build Wayback snapshot URL
        snapshot_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
        
        urls.append({
            "timestamp": timestamp,
            "original_url": original_url,
            "status_code": status_code,
            "length": length,
            "snapshot_url": snapshot_url
        })
    
    print_success(f"Found {len(urls)} historical URLs")
    
    # Show interesting file types
    interesting_extensions = [".js", ".php", ".asp", ".aspx", ".jsp", 
                               ".json", ".xml", ".config", ".env", 
                               ".sql", ".bak", ".old", ".txt", ".git"]
    
    interesting_urls = [u for u in urls 
                        if any(u["original_url"].lower().endswith(ext) for ext in interesting_extensions)]
    
    print_info(f"Interesting URLs (scripts, configs, backups): {len(interesting_urls)}")
    for u in interesting_urls[:15]:
        print_success(f"  [{u['status_code']}] {u['original_url']}")
        print_info(f"         {u['snapshot_url']}")
    
    if len(interesting_urls) > 15:
        print_info(f"  ... and {len(interesting_urls) - 15} more")
    
    save_json(urls, f"{domain}_wayback.json")
    
    return {"domain": domain, "urls": urls, "total": len(urls)}