#!/bin/bash
# ------------------------------------------
# Ultimate Enterprise Recon Tool (Enhanced)
# Author: Ali (Enhanced by AI)
# Features:
# - Multi-threaded & optimized
# - Slack/Discord notifications
# - EPSS scoring for CVEs
# - CI/CD integration
# - Resource monitoring
# - Sensitive data encryption
# - Modular design
# - Auto-update tools
# - Expanded toolset for broader coverage
# ------------------------------------------

# Configuration
THREADS=500                                    # Adjust based on hardware
RESOLVERS="8.8.8.8,1.1.1.1,9.9.9.9"           # Trusted DNS resolvers
WORDLIST_DIR="/opt/wordlists"                  # Custom wordlists location
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M%S)"      # Time-stamped results
LOG_FILE="$OUTPUT_DIR/recon.log"
TARGETS=("${@}")                               # Input domains
BLIND_XSS="${BLIND_XSS:-https://your.interact.sh}"  # Blind XSS endpoint
ENCRYPT_DUMPS=true                             # Encrypt sensitive data
ENCRYPT_KEY="supersecret"                      # Encryption key
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"             # Slack webhook URL
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"         # Discord webhook URL
CI_MODE="${CI_MODE:-false}"                    # CI/CD integration
EPSS_API="https://epss.cyentia.com/epss/api/v1/epsstoday"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Required Tools
declare -A REQUIRED_TOOLS=(
    ["amass"]="latest"
    ["subfinder"]="latest"
    ["httpx"]="v1.3.7"
    ["nuclei"]="v3.1.0"
    ["gau"]="latest"
    ["ffuf"]="2.0.0"
    ["dalfox"]="latest"
    ["naabu"]="latest"
    ["katana"]="latest"
    ["gowitness"]="latest"
    ["rush"]="latest"
    ["jq"]="latest"
    ["md-to-pdf"]="latest"  # For summary conversion if needed
    ["curl"]="latest"
    # Non-Go/npm tools assumed to be installed
    ["sublist3r"]=""
    ["waybackurls"]=""
    ["nikto"]=""
    ["wkhtmltopdf"]=""
    ["parallel"]=""
)

# Notify via Slack/Discord
notify() {
    local message="$1"
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"$message\"}" "$SLACK_WEBHOOK" &>/dev/null
    fi
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        curl -X POST -H 'Content-type: application/json' --data "{\"content\":\"$message\"}" "$DISCORD_WEBHOOK" &>/dev/null
    fi
}

# Check and install missing tools
auto_update_tools() {
    for tool in "${!REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[!] Missing $tool - Please install it manually if not Go/npm-based${NC}" | tee -a "$LOG_FILE"
            if [[ "$tool" == "md-to-pdf" ]]; then
                npm install -g md-to-pdf
            elif [[ ! "$tool" =~ ^(sublist3r|waybackurls|nikto|wkhtmltopdf|parallel)$ ]]; then
                go install "github.com/projectdiscovery/${tool}/cmd/${tool}@${REQUIRED_TOOLS[$tool]}"
            fi
        fi
    done
}

# Setup
setup() {
    mkdir -p "$OUTPUT_DIR"/{subdomains,urls,vulns,logs,screenshots}
    ulimit -n 1000000  # Handle massive file descriptors
    echo "[+] Recon started at $(date)" | tee -a "$LOG_FILE"
    notify "Recon started for ${TARGETS[*]}"
}

# Domain Validation
validate_domains() {
    for domain in "${TARGETS[@]}"; do
        if ! whois "$domain" &> /dev/null; then
            echo -e "${RED}[!] Invalid Domain: $domain${NC}" | tee -a "$LOG_FILE"
            notify "Invalid Domain: $domain"
            exit 1
        fi
    done
}

# Resource Monitoring
check_resources() {
    local cpu_load=$(awk '{print $1}' /proc/loadavg)
    local max_load=$(nproc)
    
    if (( $(echo "$cpu_load > $max_load" | bc -l) )); then
        echo -e "${RED}[!] CPU overload detected! Adjusting threads${NC}" | tee -a "$LOG_FILE"
        THREADS=$((THREADS/2))
    fi
}

# Phase 1: Subdomain Enumeration
subdomain_enum() {
    echo -e "\n${GREEN}[+] Subdomain Enumeration${NC}" | tee -a "$LOG_FILE"
    subfinder -d "${TARGETS[@]}" -o "$OUTPUT_DIR/subdomains/subfinder.txt" &
    assetfinder --subs-only "${TARGETS[@]}" | tee "$OUTPUT_DIR/subdomains/assetfinder.txt" &
    amass enum -passive -d "${TARGETS[@]}" -o "$OUTPUT_DIR/subdomains/passive.txt" &
    # Add Sublist3r for broader coverage
    for domain in "${TARGETS[@]}"; do
        sublist3r -d "$domain" -o "$OUTPUT_DIR/subdomains/sublist3r_$domain.txt" &
    done
    wait
    cat "$OUTPUT_DIR/subdomains/"*.txt | sort -u > "$OUTPUT_DIR/subdomains/all.txt"
}

# Phase 2: URL Discovery
url_discovery() {
    echo -e "\n${GREEN}[+] URL Discovery${NC}" | tee -a "$LOG_FILE"
    cat "$OUTPUT_DIR/subdomains/all.txt" | httpx -silent -threads $THREADS | tee "$OUTPUT_DIR/urls/live_hosts.txt"
    cat "$OUTPUT_DIR/subdomains/all.txt" | gau | uro | tee "$OUTPUT_DIR/urls/historical.txt"
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | katana -jc -kf all -c $THREADS -o "$OUTPUT_DIR/urls/js_endpoints.txt"
    # Add waybackurls for historical URLs
    cat "$OUTPUT_DIR/subdomains/all.txt" | waybackurls | tee "$OUTPUT_DIR/urls/wayback.txt"
    # Merge all URLs
    cat "$OUTPUT_DIR/urls/"{historical,js_endpoints,wayback}.txt | sort -u > "$OUTPUT_DIR/urls/all_urls.txt"
}

# Phase 3: Vulnerability Scanning
vulnerability_scan() {
    echo -e "\n${GREEN}[+] Vulnerability Scanning${NC}" | tee -a "$LOG_FILE"
    # Use JSON output for Nuclei
    nuclei -list "$OUTPUT_DIR/urls/live_hosts.txt" -t ~/nuclei-templates/ -severity critical,high -rl $THREADS -json -o "$OUTPUT_DIR/vulns/nuclei_results.json"
    cat "$OUTPUT_DIR/urls/historical.txt" | dalfox pipe -b "$BLIND_XSS" -o "$OUTPUT_DIR/vulns/xss_results.txt"
    # Add Nikto scans on live hosts
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | parallel -j $THREADS nikto -h {} -output "$OUTPUT_DIR/vulns/nikto_{}.txt"
}

# Phase 4: Exploit Validation
validate_findings() {
    echo -e "\n${GREEN}[+] Exploit Validation${NC}" | tee -a "$LOG_FILE"
    sqlmap -m "$OUTPUT_DIR/vulns/nuclei_results.json" --batch --dump-all --threads 10
    nuclei -tags rce -json -o "$OUTPUT_DIR/vulns/rce_verified.json"
    gowitness file -f "$OUTPUT_DIR/urls/live_hosts.txt" -P "$OUTPUT_DIR/screenshots/"
}

# Phase 5: CVE-Based Scanning with EPSS
cve_scan() {
    echo -e "\n${GREEN}[+] CVE-Based Scanning${NC}" | tee -a "$LOG_FILE"
    naabu -list "$OUTPUT_DIR/urls/live_hosts.txt" -o "$OUTPUT_DIR/vulns/open_ports.txt"
    cat "$OUTPUT_DIR/vulns/open_ports.txt" | nuclei -t ~/nuclei-templates/cves/
    # Fetch EPSS scores
    curl -s "$EPSS_API" | jq '.data[] | select(.epss_score > 0.7)' > "$OUTPUT_DIR/vulns/high_risk_cves.txt"
}

# Final Report
generate_report() {
    echo -e "\n${GREEN}[+] Generating Report${NC}" | tee -a "$LOG_FILE"
    # Generate HTML report from Nuclei JSON
    cat "$OUTPUT_DIR/vulns/nuclei_results.json" | nuclei-reporter -format html -output "$OUTPUT_DIR/report.html"
    # Convert to PDF using wkhtmltopdf
    wkhtmltopdf "$OUTPUT_DIR/report.html" "$OUTPUT_DIR/report.pdf"
    # Generate summary
    echo "Recon Summary for ${TARGETS[*]}" > "$OUTPUT_DIR/summary.txt"
    echo "-----------------------------" >> "$OUTPUT_DIR/summary.txt"
    echo "Subdomains found: $(wc -l < "$OUTPUT_DIR/subdomains/all.txt")" >> "$OUTPUT_DIR/summary.txt"
    echo "Live hosts: $(wc -l < "$OUTPUT_DIR/urls/live_hosts.txt")" >> "$OUTPUT_DIR/summary.txt"
    echo "URLs discovered: $(wc -l < "$OUTPUT_DIR/urls/all_urls.txt")" >> "$OUTPUT_DIR/summary.txt"
    echo "Vulnerabilities (Nuclei):" >> "$OUTPUT_DIR/summary.txt"
    echo "  Critical: $(jq '[.[] | select(.info.severity == "critical")] | length' "$OUTPUT_DIR/vulns/nuclei_results.json")" >> "$OUTPUT_DIR/summary.txt"
    echo "  High: $(jq '[.[] | select(.info.severity == "high")] | length' "$OUTPUT_DIR/vulns/nuclei_results.json")" >> "$OUTPUT_DIR/summary.txt"
    echo "XSS findings (Dalfox): $(wc -l < "$OUTPUT_DIR/vulns/xss_results.txt")" >> "$OUTPUT_DIR/summary.txt"
    echo "Nikto scans performed on live hosts. See vulns/nikto_*.txt for details." >> "$OUTPUT_DIR/summary.txt"
    echo -e "\n${GREEN}[+] Report saved to $OUTPUT_DIR/report.pdf, Summary at $OUTPUT_DIR/summary.txt${NC}" | tee -a "$LOG_FILE"
    notify "Recon completed for ${TARGETS[*]}. Report: $OUTPUT_DIR/report.pdf, Summary: $OUTPUT_DIR/summary.txt"
}

# Cleanup
cleanup() {
    if [ "$ENCRYPT_DUMPS" = true ]; then
        echo -e "\n${GREEN}[+] Encrypting sensitive data${NC}" | tee -a "$LOG_FILE"
        gpg --batch --passphrase "$ENCRYPT_KEY" -c "$OUTPUT_DIR/vulns/"*.json
        shred -u "$OUTPUT_DIR/vulns/"*.json
    fi
}

# CI/CD Integration
ci_integration() {
    if [[ "$CI_MODE" == "true" ]]; then
        echo -e "\n${GREEN}[+] CI/CD Mode Enabled${NC}" | tee -a "$LOG_FILE"
        aws s3 cp "$OUTPUT_DIR/report.pdf" "s3://your-bucket/reports/"
        aws s3 cp "$OUTPUT_DIR/summary.txt" "s3://your-bucket/reports/"
    fi
}

# Main Execution
main() {
    auto_update_tools
    setup
    validate_domains
    subdomain_enum
    url_discovery
    vulnerability_scan
    validate_findings
    cve_scan
    generate_report
    cleanup
    ci_integration
}

# Argument Handling
if [ $# -eq 0 ]; then
    echo -e "${RED}Usage: $0 <domain1> <domain2> ...${NC}" | tee -a "$LOG_FILE"
    exit 1
fi

# Cleanup Trap
trap 'cleanup; rm -rf "$OUTPUT_DIR"' EXIT

main
