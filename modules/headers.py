"""
MyRecon Pro - HTTP Headers Module
Analyzes security headers and server info.
"""

from core.utils import print_info, print_success, print_error, print_warning, print_banner, make_request, save_json

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS - enforces HTTPS connections",
    "Content-Security-Policy": "CSP - mitigates XSS / data injection",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "X-Frame-Options": "Prevents clickjacking",
    "X-XSS-Protection": "Legacy XSS filter (modern browsers deprecate this)",
    "Referrer-Policy": "Controls referrer header when navigating",
    "Permissions-Policy": "Controls browser API access (camera, mic, etc.)",
    "Access-Control-Allow-Origin": "CORS policy",
    "Set-Cookie": "Cookie attributes (HttpOnly, Secure, SameSite)"
}

def headers_analysis(target_url):
    """
    Fetch and analyze HTTP response headers.
    target_url should be full URL (e.g. https://example.com).
    """
    print_banner("HTTP HEADERS ANALYSIS")
    print_info(f"Fetching headers from {target_url}...")
    
    # Ensure proper URL format
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"
    
    resp = make_request(target_url, allow_redirects=True)
    if not resp:
        return {}
    
    results = {
        "target": target_url,
        "final_url": str(resp.url),
        "status_code": resp.status_code,
        "server": resp.headers.get("Server", "N/A"),
        "technology": resp.headers.get("X-Powered-By", "N/A"),
        "security_headers": {},
        "missing_headers": []
    }
    
    print_success(f"Status: {resp.status_code}")
    print_info(f"Final URL: {resp.url}")
    print_info(f"Server: {results['server']}")
    if results['technology'] != "N/A":
        print_info(f"X-Powered-By: {results['technology']}")
    
    print_info("\n--- Security Headers ---")
    
    for header, description in SECURITY_HEADERS.items():
        value = resp.headers.get(header)
        if value:
            results["security_headers"][header] = value
            if "cookie" in header.lower():
                # Truncate cookies for display
                display_val = value[:60] + "..." if len(value) > 60 else value
                print_success(f"  [+] {header}: {display_val}")
            else:
                print_success(f"  [+] {header}: {value}")
        else:
            results["missing_headers"].append(header)
            print_warning(f"  [-] Missing: {header} ({description})")
    
    # Additional useful headers
    for h in ["Location", "WWW-Authenticate", "X-Redirect-By"]:
        if h in resp.headers:
            print_info(f"  [*] {h}: {resp.headers[h]}")
    
    save_json(results, f"{target_url.replace('://', '_').replace('/', '_')}_headers.json")
    
    return results