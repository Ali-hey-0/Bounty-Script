# Ultimate Enterprise Recon Tool 🔍

A powerful, enterprise-grade reconnaissance tool designed for bug bounty hunters and security professionals. This tool combines multiple recon techniques with advanced features like multi-threading, notifications, and automated reporting.

## 🌟 Features

- 🚀 **Multi-threaded & Optimized** - Configurable threading for maximum performance
- 📱 **Instant Notifications** - Slack and Discord integration for real-time updates
- 📊 **EPSS Scoring** - Automated CVE risk assessment using EPSS API
- 🔄 **CI/CD Integration** - Seamless integration with CI/CD pipelines
- 📈 **Resource Monitoring** - Automatic performance optimization
- 🔒 **Data Security** - Sensitive data encryption support
- 🧩 **Modular Design** - Easy to extend and customize
- 🔄 **Auto-Update** - Keeps all dependencies up to date

## 📋 Prerequisites

The following tools are required and will be automatically installed if missing:

- amass
- subfinder
- httpx
- nuclei
- gau
- ffuf
- dalfox
- naabu
- katana
- gowitness
- rush
- jq
- md-to-pdf
- curl

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/Ali-hey-0/Bounty-Script.git
cd Bounty-Script
```

2. Make the script executable:
```bash
chmod +x recon.sh
```

3. The script will automatically install any missing dependencies when run.

## ⚙️ Configuration

Configure the script by setting the following environment variables or editing the script directly:

```bash
# Core Settings
THREADS=500                    # Number of concurrent threads
RESOLVERS="8.8.8.8,1.1.1.1"   # DNS resolvers
WORDLIST_DIR="/opt/wordlists"  # Custom wordlists location

# Notification Settings
SLACK_WEBHOOK="your-webhook-url"
DISCORD_WEBHOOK="your-webhook-url"

# Security Settings
ENCRYPT_DUMPS=true
ENCRYPT_KEY="your-encryption-key"
BLIND_XSS="https://your.interact.sh"

# CI/CD Settings
CI_MODE="false"               # Enable/disable CI mode
```

## 🚀 Usage

Basic usage:
```bash
./recon.sh domain1.com domain2.com
```

The script will create a time-stamped output directory containing:
- 📁 `subdomains/` - Discovered subdomains
- 📁 `urls/` - Discovered URLs and endpoints
- 📁 `vulns/` - Identified vulnerabilities
- 📁 `logs/` - Execution logs
- 📁 `screenshots/` - Web page screenshots
- 📄 `report.pdf` - Comprehensive PDF report

## 📊 Output Structure

```
recon-YYYYMMDD-HHMMSS/
├── subdomains/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   └── passive.txt
├── urls/
│   ├── live_hosts.txt
│   ├── historical.txt
│   └── js_endpoints.txt
├── vulns/
│   ├── nuclei_results.txt
│   ├── xss_results.txt
│   └── high_risk_cves.txt
├── screenshots/
├── logs/
└── report.pdf
```

## 🔄 Workflow Phases

1. **Subdomain Enumeration**
   - Passive and active subdomain discovery
   - Multiple tools for comprehensive coverage

2. **URL Discovery**
   - Live host detection
   - Historical endpoint discovery
   - JavaScript endpoint analysis

3. **Vulnerability Scanning**
   - Automated vulnerability detection
   - XSS hunting
   - CVE checking

4. **Exploit Validation**
   - Automated exploit verification
   - Screenshot capture
   - Risk assessment

5. **Reporting**
   - HTML and PDF report generation
   - EPSS score integration
   - Notification delivery

## 🔒 Security Features

- Encrypted storage of sensitive data
- Secure handling of credentials
- Resource usage monitoring
- Configurable rate limiting

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for improvements.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before performing reconnaissance activities.

## 👤 Author

- Original Author: Ali
- Enhanced by AI

## 📞 Support

For support, please open an issue in the GitHub repository or contact the maintainers.
