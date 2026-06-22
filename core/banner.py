"""
MyRecon Pro - Banner Module
ASCII art and version info displayed at startup.
"""

import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
███╗   ███╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
████╗ ████║╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██╔████╔██║ ╚████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║╚██╔╝██║  ╚██╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║ ╚═╝ ██║   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝     ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Fore.GREEN}                     MyRecon Pro v1.0
{Fore.YELLOW}            Advanced Reconnaissance Framework
{Fore.CYAN}           Authorized Penetration Testing Tool
{Style.RESET_ALL}
"""

SHORT_BANNER = f"{Fore.MAGENTA}MyRecon Pro v1.0{Style.RESET_ALL}"

def show_banner():
    """Print the full banner."""
    print(BANNER)

def show_version():
    """Print version info."""
    print(SHORT_BANNER)