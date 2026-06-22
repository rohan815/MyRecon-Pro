"""
MyRecon Pro - Configuration Module
Stores API keys, default settings, and constants.
"""

import os
from dotenv import load_dotenv

load_dotenv("api.env") 

class Config:
    # API Keys (loaded securely from environment)
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "api.env")

    # HTTP Settings
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    TIMEOUT = 30  # Request timeout in seconds

    # Output Settings
    OUTPUT_DIR = "output"
    REPORT_DIR = "reports"

    # Rate Limiting (requests per second)
    RATE_LIMIT = 2

    # Common subdomains for recon
    COMMON_SUBDOMAIN_PREFIXES = [
        "www", "mail", "ftp", "admin", "blog", "dev", "api",
        "staging", "vpn", "webmail", "portal", "cpanel", "whm",
        "support", "docs", "status", "shop", "cdn", "static",
        "app", "test", "beta", "demo", "forum", "wiki", "news",
        "media", "img", "video", "m", "mobile", "remote", "git",
        "jenkins", "jira", "confluence", "grafana", "prometheus"
    ]

    # Common ports for IP reconnaissance
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
        5900, 6379, 8080, 8443, 9090, 27017
    ]