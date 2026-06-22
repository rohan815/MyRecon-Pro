Samajh gaya 👍 tumhe **single clean professional README file** chahiye jisko seedha copy-paste kar sako (no confusion, no duplicates).

Yeh lo — improved + polished version 👇

---

```md
# 🔎 MyRecon-Pro

MyRecon-Pro is a professional Python-based OSINT (Open Source Intelligence) reconnaissance tool designed for gathering and analyzing information about domains, IP addresses, and network infrastructure. It helps security researchers and ethical hackers automate intelligence collection in one place.

---

## ⚡ Overview

MyRecon-Pro provides automated reconnaissance capabilities to extract valuable information such as WHOIS data, DNS records, IP details, subdomains, SSL certificates, email addresses, and archived website data.

This tool is built for **educational and ethical cybersecurity research purposes only**.

---

## 🚀 Features

- WHOIS Lookup
- DNS Records Extraction
- IP Address Information
- HTTP Header Analysis
- Subdomain Enumeration
- Email Discovery
- Shodan Integration (API-based)
- Netcraft Lookup
- SSL Certificate Details
- Wayback Machine Historical Data

---

## 🧱 Project Structure

```

MyRecon-Pro/
│
├── main.py
│
├── core/
│ ├── banner.py
│ ├── config.py
│ └── utils.py
│
├── modules/
│ ├── whois_lookup.py
│ ├── dns_lookup.py
│ ├── ip_lookup.py
│ ├── headers.py
│ ├── subdomains.py
│ ├── emails.py
│ ├── shodan_lookup.py
│ ├── netcraft_lookup.py
│ ├── ssl_info.py
│ └── wayback.py
│
├── reports/
├── output/
├── requirements.txt
└── README.md

````

---

## ⚙️ Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/rohan815/MyRecon-Pro.git
cd MyRecon-Pro
pip install -r requirements.txt
````

---

## ▶️ Usage

Run the tool:

```bash
python main.py
```

Enter target domain or IP when prompted:

```bash
Enter target: example.com
```

---

## 📊 Output

The tool generates structured intelligence reports including:

* WHOIS details
* DNS records
* IP geolocation information
* Subdomain results
* SSL certificate data
* Archived URLs from Wayback Machine

Results are saved in the `output/` or `reports/` folder.

---

## 📦 Requirements

* Python 3.x
* requests
* python-whois
* dnspython
* shodan (optional)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ⚠️ Disclaimer

This tool is created strictly for **educational purposes and legal security research**.

Any misuse of this tool against systems without permission is strictly prohibited. The developer is not responsible for any illegal activity performed using this tool.

---

## 👨‍💻 Author

GitHub: [https://github.com/rohan815](https://github.com/rohan815)

---

## ⭐ Support

If you like this project, don’t forget to give it a ⭐ on GitHub.


