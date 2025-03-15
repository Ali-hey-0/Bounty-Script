#!/bin/bash
# ------------------------------------------
# Ultimate Enterprise Recon Tool (Widest Scope)
# Author: Ali (Enhanced by AI)
# Features:
# - Comprehensive subdomain, URL, and vuln scanning
# - Network, cloud, and container recon
# - Threat intelligence integration
# - Multi-format reporting
# - API-driven automation
# - Widest toolset for maximum coverage
# ------------------------------------------

# Configuration
THREADS=1000                                   # High thread count for speed
RESOLVERS="8.8.8.8,1.1.1.1,9.9.9.9"           # Trusted DNS resolvers
WORDLIST_DIR="/opt/wordlists"                  # Custom wordlists
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M%S)"      # Time-stamped output
LOG_FILE="$OUTPUT_DIR/recon.log"
TARGETS=("${@}")                               # Input domains
BLIND_XSS="${BLIND_XSS:-https://your.interact.sh}"  # Blind XSS endpoint
ENCRYPT_DUMPS=true                             # Encrypt sensitive data
ENCRYPT_KEY="supersecret"                      # Encryption key
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"             # Slack webhook
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"         # Discord webhook
CI_MODE="${CI_MODE:-false}"                    # CI/CD mode
API_KEYS_FILE="${API_KEYS_FILE:-/etc/recon_api_keys.conf}"  # API keys
SCHEDULE_MODE="${SCHEDULE_MODE:-false}"        # Scheduled scans

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Required Tools (Expanded)
declare -A REQUIRED_TOOLS=(
    ["amass"]="latest"        ["subfinder"]="latest"   ["httpx"]="v1.3.7"
    ["nuclei"]="v3.1.0"       ["gau"]="latest"         ["ffuf"]="2.0.0"
    ["dalfox"]="latest"       ["naabu"]="latest"       ["katana"]="latest"
    ["gowitness"]="latest"    ["rush"]="latest"        ["jq"]="latest"
    ["curl"]="latest"         ["findomain"]="latest"   ["paramspider"]=""
    ["arjun"]=""              ["wapiti"]=""            ["zap"]=""
    ["msfconsole"]=""         ["burpsuite"]=""         ["python3"]=""
    ["sublist3r"]=""          ["waybackurls"]=""       ["nikto"]=""
    ["wkhtmltopdf"]=""        ["parallel"]=""          ["chaos"]=""
    ["dnsdumpster"]=""        ["shodan"]=""            ["zoomeye"]=""
    ["linkfinder"]=""         ["jsfscan"]=""           ["gospider"]=""
    ["kiterunner"]=""         ["testssl.sh"]=""        ["sslyze"]=""
    ["jaws"]=""               ["whatweb"]=""           ["cloudsploit"]=""
    ["trivy"]=""              ["masscan"]=""           ["rustscan"]=""
    ["nmap"]=""               ["dnsrecon"]=""          ["fierce"]=""
    ["sn1per"]=""             ["autosploit"]=""
)

# Load API Keys
load_api_keys() {
    if [[ -f "$API_KEYS_FILE" ]]; then
        source "$API_KEYS_FILE"  # Expects SHODAN_API_KEY, ZOOMEYE_API_KEY, etc.
    else
        echo -e "${RED}[!] API keys file not found at $API_KEYS_FILE${NC}" | tee -a "$LOG_FILE"
    fi
}

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

# Check and Install Tools
auto_update_tools() {
    for tool in "${!REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[!] Missing $tool - Install manually if not Go-based${NC}" | tee -a "$LOG_FILE"
            if [[ ! "$tool" =~ ^(sublist3r|waybackurls|nikto|wkhtmltopdf|parallel|findomain|paramspider|arjun|wapiti|zap|msfconsole|burpsuite|python3|chaos|dnsdumpster|shodan|zoomeye|linkfinder|jsfscan|gospider|kiterunner|testssl.sh|sslyze|jaws|whatweb|cloudsploit|trivy|masscan|rustscan|nmap|dnsrecon|fierce|sn1per|autosploit)$ ]]; then
                go install "github.com/projectdiscovery/${tool}/cmd/${tool}@${REQUIRED_TOOLS[$tool]}"
            fi
        fi
    done
}

# Setup
setup() {
    mkdir -p "$OUTPUT_DIR"/{subdomains,urls,vulns,logs,screenshots,reports,network,cloud,containers}
    ulimit -n 1000000
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
        echo -e "${RED}[!] CPU overload! Reducing threads${NC}" | tee -a "$LOG_FILE"
        THREADS=$((THREADS/2))
    fi
}

# Phase 1: Subdomain Enumeration
subdomain_enum() {
    echo -e "\n${GREEN}[+] Subdomain Enumeration${NC}" | tee -a "$LOG_FILE"
    subfinder -d "${TARGETS[@]}" -o "$OUTPUT_DIR/subdomains/subfinder.txt" &
    assetfinder --subs-only "${TARGETS[@]}" | tee "$OUTPUT_DIR/subdomains/assetfinder.txt" &
    amass enum -passive -d "${TARGETS[@]}" -o "$OUTPUT_DIR/subdomains/passive.txt" &
    chaos -d "${TARGETS[@]}" -o "$OUTPUT_DIR/subdomains/chaos.txt" &
    for domain in "${TARGETS[@]}"; do
        sublist3r -d "$domain" -o "$OUTPUT_DIR/subdomains/sublist3r_$domain.txt" &
        findomain -t "$domain" -o "$OUTPUT_DIR/subdomains/findomain_$domain.txt" &
        curl -s "https://crt.sh/?q=%.$domain" | grep "<TD>" | grep "$domain" | sed 's/<[^>]*>//g' | sort -u > "$OUTPUT_DIR/subdomains/crtsh_$domain.txt" &
        shodan search "hostname:$domain" --fields ip_str,hostnames --limit 1000 > "$OUTPUT_DIR/subdomains/shodan_$domain.txt" &
        zoomeye host search "$domain" > "$OUTPUT_DIR/subdomains/zoomeye_$domain.txt" &
    done
    wait
    cat "$OUTPUT_DIR/subdomains/"*.txt | sort -u > "$OUTPUT_DIR/subdomains/all.txt"
}

# Phase 2: URL and Endpoint Discovery
url_discovery() {
    echo -e "\n${GREEN}[+] URL & Endpoint Discovery${NC}" | tee -a "$LOG_FILE"
    cat "$OUTPUT_DIR/subdomains/all.txt" | httpx -silent -threads $THREADS | tee "$OUTPUT_DIR/urls/live_hosts.txt"
    cat "$OUTPUT_DIR/subdomains/all.txt" | gau | uro | tee "$OUTPUT_DIR/urls/historical.txt"
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | katana -jc -kf all -c $THREADS -o "$OUTPUT_DIR/urls/js_endpoints.txt"
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | gospider -o "$OUTPUT_DIR/urls/gospider.txt" &
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | linkfinder -o "$OUTPUT_DIR/urls/linkfinder.txt" &
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | jsfscan -o "$OUTPUT_DIR/urls/jsfscan.txt" &
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | kiterunner scan -o "$OUTPUT_DIR/urls/kiterunner.txt" &
    wait
    cat "$OUTPUT_DIR/urls/"*.txt | sort -u > "$OUTPUT_DIR/urls/all_urls.txt"
}

# Phase 3: Network Reconnaissance
network_recon() {
    echo -e "\n${GREEN}[+] Network Reconnaissance${NC}" | tee -a "$LOG_FILE"
    masscan -iL "$OUTPUT_DIR/subdomains/all.txt" -p1-65535 --rate 10000 -oL "$OUTPUT_DIR/network/masscan.txt" &
    rustscan -i "$OUTPUT_DIR/subdomains/all.txt" --ulimit 5000 > "$OUTPUT_DIR/network/rustscan.txt" &
    nmap -iL "$OUTPUT_DIR/subdomains/all.txt" -sC -sV -oN "$OUTPUT_DIR/network/nmap.txt" &
    dnsrecon -d "${TARGETS[@]}" -t axfr > "$OUTPUT_DIR/network/dnsrecon.txt" &
    fierce --domain "${TARGETS[@]}" > "$OUTPUT_DIR/network/fierce.txt" &
    wait
}

# Phase 4: Vulnerability Scanning
vulnerability_scan() {
    echo -e "\n${GREEN}[+] Vulnerability Scanning${NC}" | tee -a "$LOG_FILE"
    nuclei -list "$OUTPUT_DIR/urls/live_hosts.txt" -t ~/nuclei-templates/ -severity critical,high -rl $THREADS -json -o "$OUTPUT_DIR/vulns/nuclei.json"
    cat "$OUTPUT_DIR/urls/all_urls.txt" | dalfox pipe -b "$BLIND_XSS" -o "$OUTPUT_DIR/vulns/xss.txt"
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | parallel -j $THREADS nikto -h {} -output "$OUTPUT_DIR/vulns/nikto_{}.txt"
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | parallel -j $THREADS wapiti -u {} -o "$OUTPUT_DIR/vulns/wapiti_{}.json"
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | testssl.sh --jsonfile "$OUTPUT_DIR/vulns/testssl_{}.json" {} &
    cat "$OUTPUT_DIR/urls/live_hosts.txt" | sslyze --json_out="$OUTPUT_DIR/vulns/sslyze_{}.json" {} &
    whatweb -i "$OUTPUT_DIR/urls/live_hosts.txt" > "$OUTPUT_DIR/vulns/whatweb.txt" &
    jaws -i "$OUTPUT_DIR/urls/live_hosts.txt" > "$OUTPUT_DIR/vulns/jaws.txt" &
    wait
}

# Phase 5: Cloud and Container Scanning
cloud_container_scan() {
    echo -e "\n${GREEN}[+] Cloud & Container Scanning${NC}" | tee -a "$LOG_FILE"
    cloudsploit --config "$API_KEYS_FILE" --output "$OUTPUT_DIR/cloud/cloudsploit.json" &
    trivy image --input "$OUTPUT_DIR/subdomains/all.txt" > "$OUTPUT_DIR/containers/trivy.txt" &
    wait
}

# Phase 6: Exploit Validation
validate_findings() {
    echo -e "\n${GREEN}[+] Exploit Validation${NC}" | tee -a "$LOG_FILE"
    sqlmap -m "$OUTPUT_DIR/vulns/nuclei.json" --batch --dump-all --threads 10 &
    nuclei -tags rce -json -o "$OUTPUT_DIR/vulns/rce_verified.json"
    sn1per -f "$OUTPUT_DIR/urls/live_hosts.txt" -m aggressive -o "$OUTPUT_DIR/vulns/sn1per" &
    # Placeholder for custom exploit scripts
    # autosploit -t "$OUTPUT_DIR/urls/live_hosts.txt" > "$OUTPUT_DIR/vulns/autosploit.txt" &
    wait
}

# Phase 7: Threat Intelligence
threat_intel() {
    echo -e "\n${GREEN}[+] Threat Intelligence${NC}" | tee -a "$LOG_FILE"
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${TARGETS[0]}" -H "X-OTX-API-KEY: $OTX_API_KEY" > "$OUTPUT_DIR/vulns/otx.json"
    curl -s "https://www.virustotal.com/api/v3/domains/${TARGETS[0]}" -H "x-apikey: $VT_API_KEY" > "$OUTPUT_DIR/vulns/virustotal.json"
}

# Final Report
generate_report() {
    echo -e "\n${GREEN}[+] Generating Report${NC}" | tee -a "$LOG_FILE"
    nuclei-reporter -format html -input "$OUTPUT_DIR/vulns/nuclei.json" -output "$OUTPUT_DIR/reports/nuclei.html"
    wkhtmltopdf "$OUTPUT_DIR/reports/nuclei.html" "$OUTPUT_DIR/reports/nuclei.pdf"
    echo "Recon Summary for ${TARGETS[*]}" > "$OUTPUT_DIR/reports/summary.txt"
    echo "Subdomains: $(wc -l < "$OUTPUT_DIR/subdomains/all.txt")" >> "$OUTPUT_DIR/reports/summary.txt"
    echo "Live Hosts: $(wc -l < "$OUTPUT_DIR/urls/live_hosts.txt")" >> "$OUTPUT_DIR/reports/summary.txt"
    echo "URLs: $(wc -l < "$OUTPUT_DIR/urls/all_urls.txt")" >> "$OUTPUT_DIR/reports/summary.txt"
    echo "Critical Vulns: $(jq '[.[] | select(.info.severity == "critical")] | length' "$OUTPUT_DIR/vulns/nuclei.json")" >> "$OUTPUT_DIR/reports/summary.txt"
    notify "Recon completed. Report: $OUTPUT_DIR/reports/nuclei.pdf"
}

# Cleanup
cleanup() {
    if [ "$ENCRYPT_DUMPS" = true ]; then
        echo -e "\n${GREEN}[+] Encrypting Data${NC}" | tee -a "$LOG_FILE"
        gpg --batch --passphrase "$ENCRYPT_KEY" -c "$OUTPUT_DIR/vulns/"*.json
        shred -u "$OUTPUT_DIR/vulns/"*.json
    fi
}

# CI/CD Integration
ci_integration() {
    if [[ "$CI_MODE" == "true" ]]; then
        aws s3 cp "$OUTPUT_DIR/reports/" "s3://your-bucket/reports/" --recursive
    fi
}

# Schedule Mode
schedule_scan() {
    if [[ "$SCHEDULE_MODE" == "true" ]]; then
        echo "0 0 * * * $0 ${TARGETS[*]}" | crontab -
        echo -e "${GREEN}[+] Scheduled daily scan${NC}" | tee -a "$LOG_FILE"
    fi
}

# Main Execution
main() {
    load_api_keys
    auto_update_tools
    setup
    validate_domains
    subdomain_enum
    url_discovery
    network_recon
    vulnerability_scan
    cloud_container_scan
    validate_findings
    threat_intel
    generate_report
    cleanup
    ci_integration
    schedule_scan
}

# Argument Handling
if [ $# -eq 0 ]; then
    echo -e "${RED}Usage: $0 <domain1> <domain2> ...${NC}" | tee -a "$LOG_FILE"
    exit 1
fi

# Cleanup Trap
trap 'cleanup; rm -rf "$OUTPUT_DIR"' EXIT

main
