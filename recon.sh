#!/bin/bash
# ------------------------------------------
# Ultimate Enterprise Recon Tool
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
    ["md-to-pdf"]="latest"
    ["curl"]="latest"
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
            echo -e "${RED}[!] Missing $tool - Installing...${NC}" | tee -a "$LOG_FILE"
            if [[ "$tool" == "md-to-pdf" ]]; then
                npm install -g md-to-pdf
            else
                go install "github.com/projectdiscovery/${tool}/cmd/${tool}@latest"
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
    wait
    cat "$OUTPUT_DIR/subdomains/"*.txt | sort -u > "$OUTPUT_DIR/subdomains/all.txt"
}

# Phase 2: URL Discovery
url_discovery() {
    echo -e "\n${GREEN}[+] URL Discovery${NC}" | tee -a "$LOG_FILE"
    cat "$OUTPUT_DIR/subdomains/all.txt" | httpx -silent -threads $THREADS | tee "$OUTPUT_DIR/urls/live_hosts.txt"
    cat "$OUTPUT_DIR/subdomains/all.txt" | gau | uro | tee "$OUTPUT_DIR/urls/historical.txt"
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | katana -jc -kf all -c $THREADS -o "$OUTPUT_DIR/urls/js_endpoints.txt"
}

# Phase 3: Vulnerability Scanning
vulnerability_scan() {
    echo -e "\n${GREEN}[+] Vulnerability Scanning${NC}" | tee -a "$LOG_FILE"
    nuclei -list "$OUTPUT_DIR/urls/live_hosts.txt" -t ~/nuclei-templates/ -severity critical,high -rl $THREADS -o "$OUTPUT_DIR/vulns/nuclei_results.txt"
    cat "$OUTPUT_DIR/urls/historical.txt" | dalfox pipe -b "$BLIND_XSS" -o "$OUTPUT_DIR/vulns/xss_results.txt"
}

# Phase 4: Exploit Validation
validate_findings() {
    echo -e "\n${GREEN}[+] Exploit Validation${NC}" | tee -a "$LOG_FILE"
    sqlmap -m "$OUTPUT_DIR/vulns/nuclei_results.txt" --batch --dump-all --threads 10
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
    nuclei -json -o - | jq -s '.' | nuclei-reporter -format html -output "$OUTPUT_DIR/report.html"
    md-to-pdf "$OUTPUT_DIR/report.html" --output "$OUTPUT_DIR/report.pdf"
    echo -e "\n${GREEN}[+] Report saved to $OUTPUT_DIR/report.pdf${NC}" | tee -a "$LOG_FILE"
    notify "Recon completed for ${TARGETS[*]}. Report: $OUTPUT_DIR/report.pdf"
}

# Cleanup
cleanup() {
    if [ "$ENCRYPT_DUMPS" = true ]; then
        echo -e "\n${GREEN}[+] Encrypting sensitive data${NC}" | tee -a "$LOG_FILE"
        gpg --batch --passphrase "$ENCRYPT_KEY" -c "$OUTPUT_DIR/vulns/*.json"
        shred -u "$OUTPUT_DIR/vulns/*.json" 
    fi
}

# CI/CD Integration
ci_integration() {
    if [[ "$CI_MODE" == "true" ]]; then
        echo -e "\n${GREEN}[+] CI/CD Mode Enabled${NC}" | tee -a "$LOG_FILE"
        # Add CI/CD-specific logic here (e.g., upload reports to S3, trigger pipelines)
        aws s3 cp "$OUTPUT_DIR/report.pdf" "s3://your-bucket/reports/"
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
