
"""
MyRecon Pro - Utility Functions
Shared helpers used across all modules.
"""

import json
import csv
import os
import time
import colorama
import requests
from colorama import Fore, Style
from urllib3.exceptions import InsecureRequestWarning
from core.config import Config

# Initialize colorama
colorama.init(autoreset=True)

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------- HTTP Helpers ----------

session = requests.Session()
session.headers.update({"User-Agent": Config.USER_AGENT})
session.verify = False
session.timeout = Config.TIMEOUT

def make_request(url, method="GET", **kwargs):
    """Thread-safe HTTP request wrapper with error handling."""
    try:
        resp = session.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp
    except requests.exceptions.Timeout:
        print_error(f"Timeout: {url}")
    except requests.exceptions.ConnectionError:
        print_error(f"Connection failed: {url}")
    except requests.exceptions.HTTPError as e:
        print_error(f"HTTP {e.response.status_code}: {url}")
    except Exception as e:
        print_error(f"Request error: {e}")
    return None

# ---------- Colored Output ----------

def print_info(msg):
    print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")

def print_success(msg):
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

def print_warning(msg):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def print_error(msg):
    print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")

def print_banner(text):
    """Print a section header."""
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

# ---------- File I/O ----------

def save_json(data, filename, subdir="output"):
    """Save data as JSON in the specified subdirectory."""
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print_success(f"Saved JSON: {path}")
    return path

def save_csv(rows, fieldnames, filename, subdir="output"):
    """Save data as CSV."""
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, filename)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print_success(f"Saved CSV: {path}")
    return path

def read_file_lines(path):
    """Read lines from a file, stripping whitespace and ignoring blanks."""
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print_error(f"File not found: {path}")
        return []

# ---------- Rate Limiting ----------

class RateLimiter:
    """Simple token-bucket rate limiter."""
    def __init__(self, rate=Config.RATE_LIMIT):
        self.rate = rate
        self.last_call = 0.0

    def wait(self):
        elapsed = time.time() - self.last_call
        sleep_time = (1.0 / self.rate) - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)
        self.last_call = time.time()

rate_limiter = RateLimiter()