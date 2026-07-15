# 🔍 Nexreaper OSINT Tool

**Advanced Web Intelligence & Security Scanner**  
*30+ Features – Real Vulnerability Testing – Endpoint Discovery – Full Data Extraction*

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D16.x-brightgreen)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

---

## 🚀 Overview

Nexreaper OSINT is a powerful Node.js command-line tool designed for comprehensive web reconnaissance, vulnerability scanning, and data extraction. It combines **30+ modules** ranging from basic WHOIS lookups to advanced endpoint discovery and complete data harvesting. Whether you're a penetration tester, security researcher, or OSINT enthusiast, this toolkit provides a unified interface for probing web targets.

> **⚠️ Disclaimer:** This tool is intended for **authorized security testing and educational purposes only**. Unauthorised use against third-party systems is illegal. The author assumes no responsibility for misuse.

---

## ✨ Features

| # | Module | Description |
|---|--------|-------------|
| 1 | Basic Reconnaissance | Fetch HTTP headers, status, and page title. |
| 2 | WHOIS Lookup | Domain registration details (registrar, emails, dates). |
| 3 | Geo-IP Lookup | IP geolocation (country, city, ISP) via ip-api.com. |
| 4 | Banner Grabbing | Retrieve server banners and HTTP headers. |
| 5 | DNS Lookup | A, MX, NS, TXT, CNAME, SOA records. |
| 6 | Subnet Calculator | CIDR to network/broadcast/host range. |
| 7 | Port Scanner | Scan common ports (SSH, HTTP, MySQL, etc.). |
| 8 | Subdomain Finder | Brute‑force common subdomains using DNS. |
| 9 | Reverse IP & CMS Detection | Find domains on same IP & detect CMS (WordPress, Joomla, etc.). |
| 10 | SQLi Scanner | Real payloads (boolean, union, time‑based) with error detection. |
| 11 | XSS Scanner | Injects script, img, svg, etc., and checks reflection. |
| 12 | WordPress Scan | User enumeration, XML‑RPC, debug mode, wp‑config exposure. |
| 13 | Directory Brute Force | Common admin/backup/uploads paths. |
| 14 | MX Lookup | Mail exchange records. |
| 15 | SSL Analysis | Certificate details and expiry. |
| 16 | Security Headers | Check for missing security headers (HSTS, CSP, etc.). |
| 17 | WAF Detection | Identify Cloudflare, Sucuri, ModSecurity, etc., with live payload tests. |
| 18 | Cloudflare Analysis | Detect Cloudflare and cache status. |
| 19 | Bot Protection Check | Test responses with different user agents. |
| 20 | Technology Detection | Server, CMS, JS frameworks, analytics. |
| 21 | Rate Limit Test | Send rapid requests to detect throttling. |
| 22 | CAPTCHA Detection | Identify reCAPTCHA, hCaptcha, Turnstile. |
| 23 | **Full Scan** | Run all modules sequentially. |
| 24 | WAF Fingerprinting | Detailed WAF strength and blocking behaviour. |
| 25 | Email Discovery | Harvest emails from HTML, WHOIS, and common patterns. |
| 26 | Email Tracing | OSINT research links (HaveIBeenPwned, LinkedIn, etc.). |
| 27 | Wayback Machine Extractor | Fetch archived URLs from archive.org. |
| 28 | CMS Vulnerability Checker | Sub‑scanner for WordPress/Shopify (plugin brute‑force, user enum). |
| 29 | **Endpoint Discovery** | Crawl pages, JavaScript files, and robots.txt to reveal hidden API endpoints and parameters. |
| 30 | **Complete Data Extraction** | Aggressively extract emails, phone numbers, social media, secrets, comments, forms, meta tags – everything! |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/nexreaper-osint.git
cd nexreaper-osint

# Install dependencies (automatically handled on first run)
npm install
```

---

## 🖥️ Usage

```bash
node webosint.js
```

On first launch, the tool will **automatically install** any missing dependencies (`axios`, `chalk`, `whois-json`, `ipaddr.js`). Then you'll see the interactive menu:

```
[1]  🎯 Basic Reconnaissance
[2]  📝 WHOIS Lookup
...
[30] 📊 COMPLETE DATA EXTRACTION
[0]  ❌ Exit
```

Choose a number and follow the prompts (target URL/IP, etc.). Results are displayed in real-time and saved as JSON/text reports.

---

## ⚙️ Dependencies

- [Node.js](https://nodejs.org/) >= 16.x
- `axios` – HTTP client
- `chalk` – terminal styling
- `whois-json` – WHOIS queries
- `ipaddr.js` – IP/CIDR utilities

All are installed automatically if missing.

---

## 📝 Example Output

After running **Complete Data Extraction (30)** against a target:

```
📊 COMPLETE DATA EXTRACTION REPORT
════════════════════════════════════════════════════════════
📈 EXTRACTION STATISTICS:
  ┌─────────────────────────────────────────┐
  │ Emails Found:          12              │
  │ Phone Numbers:         3               │
  │ Social Media:          5               │
  │ Technologies:          4               │
  │ Forms Found:           2               │
  │ HTML Comments:         18              │
  │ Potential Secrets:     1               │
  │ URLs Extracted:        87              │
  │ API Endpoints:         6               │
  └─────────────────────────────────────────┘

📧 EMAIL ADDRESSES FOUND (12):
  → admin@example.com
  → contact@example.com
  ...
🔐 POTENTIAL SECRETS/KEYS FOUND!
  ⚠ [Google API Key] AIzaSy...
```

---

## 🛡️ Disclaimer

This tool is provided **for educational and defensive security research only**. The user assumes full responsibility for compliance with all applicable laws. The developer(s) are not liable for any misuse or damage caused by this software.

---

## 🤝 Contributing

Pull requests are welcome! Please open an issue first to discuss any major changes.

---

## 📄 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## 👑 Author

**Ahmad Bilal Qureshi** – *Creator of Nexreaper*  
- TikTok: [@nexreaper_69](https://tiktok.com/@nexreaper_69)  
- Instagram: [@dex7er_0](https://instagram.com/dex7er_0)

---

> *“Mene – Nexreaper delivers.”*
