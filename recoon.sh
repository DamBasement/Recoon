#!/bin/bash
# ================================================================
#  recon.sh — Passive recon pipeline + RECOON triage
#
#  Usage:
#    ./recon.sh <domain> [recoon_model] [--diff-only]
#
#  Examples:
#    ./recon.sh water-link.be
#    ./recon.sh water-link.be qwen2.5:7b
#    ./recon.sh water-link.be qwen2.5:7b --diff-only
#
#  Output files (all in the current working directory):
#    subs.txt                          — raw subdomains
#    live_hosts.txt / live_hosts.json  — validated live hosts
#    all_urls.txt                      — historical URLs from gau
#    sensitive_files.txt               — quick grep for interesting patterns
#    recon_report_hosts_*.json / .md   — AI triage on live hosts
#    recon_report_urls_*.json  / .md   — AI triage on historical URLs
# ================================================================

set -euo pipefail

# ----------------------------------------------------------------
# Banner
# ----------------------------------------------------------------
print_banner() {
    local use_color=false
    [ -t 1 ] && use_color=true

    local cyan=""   magenta=""   green=""   bold=""   reset=""
    if $use_color; then
        cyan="\033[96m"; magenta="\033[95m"
        green="\033[92m"; bold="\033[1m"; reset="\033[0m"
    fi

    local taglines=(
        "mapping the attack surface, one subdomain at a time_"
        "find what they forgot to hide_"
        "the raccoon sniffs around before the hunt begins_"
        "passive eyes open, active hands still_"
    )
    local tagline="${taglines[$((RANDOM % ${#taglines[@]}))]}"

    echo -e "${magenta}${bold}  /\\_____/\\${reset}     ${cyan}${bold}R E C O O N . S H${reset}"
    echo -e "${magenta}${bold} (  o   o  )${reset}   ${cyan}passive recon pipeline // v1.0${reset}"
    echo -e "${magenta}${bold} (  =   =  )${reset}   ${green}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${reset}"
    echo -e "${magenta}${bold}  \\ ----- /${reset}    ${cyan}subfinder + amass + httpx + gau${reset}"
    echo -e "${magenta}${bold}   )     (${reset}     ${cyan}+ RECOON AI triage${reset}"
    echo -e "${magenta}${bold}  (_|___|_)${reset}"
    echo -e "${magenta}${bold}  [  [ ]  ]${reset}    ${green}>> ${tagline}${reset}"
    echo
}

print_banner

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# Run a command in background while showing elapsed seconds.
# If watch_file is "-", only shows time (no line count).
run_with_heartbeat() {
    local label="$1"
    local watch_file="$2"
    shift 2
    local start elapsed count line

    "$@" &
    local pid=$!
    start=$(date +%s)

    while kill -0 "$pid" 2>/dev/null; do
        elapsed=$(( $(date +%s) - start ))
        if [ "$watch_file" != "-" ] && [ -f "$watch_file" ]; then
            count=$(wc -l < "$watch_file" 2>/dev/null | tr -d ' ')
            line="[*] ${label}: ${elapsed}s elapsed, ${count} results so far..."
        else
            line="[*] ${label}: ${elapsed}s elapsed..."
        fi
        printf "\r%-80s" "$line"
        sleep 1
    done

    wait "$pid"
    local exit_code=$?
    printf "\r%-80s\n" ""
    return $exit_code
}

require() {
    for cmd in "$@"; do
        command -v "$cmd" &>/dev/null || die "Required tool not found: $cmd — install it and retry."
    done
}

# ----------------------------------------------------------------
# Arguments
# ----------------------------------------------------------------
[ $# -lt 1 ] && die "Usage: $0 <domain> [recoon_model] [--diff-only]\nExamples:\n  $0 water-link.be\n  $0 water-link.be qwen2.5:7b\n  $0 water-link.be qwen2.5:7b --diff-only"

DOMAIN="$1"
MODEL="${2:-qwen2.5:7b}"
RECOON_SCRIPT="$(dirname "$0")/recoon.py"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Optional --diff-only flag: can be passed as any argument after the domain
DIFF_ONLY=""
for arg in "$@"; do
    if [ "$arg" = "--diff-only" ]; then
        DIFF_ONLY="--diff-only"
    fi
done

# ----------------------------------------------------------------
# Sanity checks
# ----------------------------------------------------------------
require subfinder amass httpx gau python3

[ -f "$RECOON_SCRIPT" ] || die "recoon.py not found at $RECOON_SCRIPT — keep it in the same folder as recon.sh."

# Warn if user passed a www.* subdomain instead of the root domain —
# subfinder/amass find far fewer results on www.example.com vs example.com
if [[ "$DOMAIN" == www.* ]]; then
    ROOT="${DOMAIN#www.}"
    echo -e "\033[0;33m[!] Warning: you passed '${DOMAIN}' which looks like a subdomain.\033[0m"
    echo -e "\033[0;33m[!] Did you mean '${ROOT}'? subfinder/amass work best on the root domain.\033[0m"
    echo -e "\033[0;33m[!] Press Ctrl+C to abort, or wait 5 seconds to continue anyway...\033[0m"
    sleep 5
fi

info "Starting recon on: ${DOMAIN}"
info "Model for triage:  ${MODEL}"
[ -n "$DIFF_ONLY" ] && info "Mode:              diff-only (analyzing new URLs only)"
echo

# ----------------------------------------------------------------
# 1. Subdomain enumeration
# ----------------------------------------------------------------
info "Enumerating subdomains (subfinder + amass passive)..."

run_with_heartbeat "subfinder" "-" \
    bash -c "subfinder -d '$DOMAIN' -silent -o subs_subfinder.txt 2>/dev/null"
success "subfinder done ($(wc -l < subs_subfinder.txt | tr -d ' ') subdomains)"

run_with_heartbeat "amass" "-" \
    bash -c "amass enum -passive -d '$DOMAIN' > subs_amass.txt 2>/dev/null; true"
success "amass done ($(wc -l < subs_amass.txt 2>/dev/null | tr -d ' ') subdomains)"

cat subs_subfinder.txt subs_amass.txt | sort -u > subs.txt
rm -f subs_subfinder.txt subs_amass.txt

SUBS_COUNT=$(wc -l < subs.txt)
success "Found ${SUBS_COUNT} unique subdomains → subs.txt"

# ----------------------------------------------------------------
# 2. Validate live hosts
# ----------------------------------------------------------------
info "Probing live hosts (httpx)..."

run_with_heartbeat "httpx" live_hosts.json \
    bash -c "cat subs.txt | httpx -silent -status-code -title -tech-detect -json -o live_hosts.json 2>/dev/null"

# Plain list for gau
cat live_hosts.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        obj = json.loads(line)
        url = obj.get('url') or obj.get('input', '')
        if url:
            print(url)
    except:
        pass
" > live_hosts.txt

LIVE_COUNT=$(wc -l < live_hosts.txt)
success "Live hosts: ${LIVE_COUNT} → live_hosts.txt (full JSON: live_hosts.json)"

if [ "$LIVE_COUNT" -eq 0 ]; then
    error "No live hosts found — check your network or try a different domain."
    exit 1
fi

# ----------------------------------------------------------------
# 3. URL discovery (gau — no --subs to stay on confirmed hosts)
# ----------------------------------------------------------------
info "Extracting historical URLs via gau (this may take a while)..."

run_with_heartbeat "gau" all_urls.txt \
    bash -c "cat live_hosts.txt | gau --from 2023 --mc 100 > all_urls.txt"

URL_COUNT=$(wc -l < all_urls.txt)
success "Collected ${URL_COUNT} URLs → all_urls.txt"

# ----------------------------------------------------------------
# 4. Quick grep for obviously interesting patterns
# ----------------------------------------------------------------
info "Quick-filtering sensitive extensions and paths..."

# Extensions: files that shouldn't be publicly accessible
# Paths: common dev/debug/backup conventions
cat all_urls.txt | grep -Ei \
    "\.(sql|env|json|config|cfg|conf|bak|backup|log|xml|yaml|yml|ini|pem|key|p12|pfx|dump|tar|gz|zip|rar)(\?.*)?$|\
/(admin|debug|staging|dev|test|internal|backup|api|swagger|graphql|actuator|console|shell|phpinfo|\.git|\.env|\.DS_Store)" \
    > sensitive_files.txt 2>/dev/null || true

SENSITIVE_COUNT=$(wc -l < sensitive_files.txt)
success "Potentially interesting patterns: ${SENSITIVE_COUNT} → sensitive_files.txt"

echo
info "------------------------------------------------------"
info "Recon complete. Summary:"
info "  Subdomains found : ${SUBS_COUNT}"
info "  Live hosts       : ${LIVE_COUNT}"
info "  Total URLs       : ${URL_COUNT}"
info "  Sensitive grep   : ${SENSITIVE_COUNT}"
info "------------------------------------------------------"
echo

# ----------------------------------------------------------------
# 5. RECOON triage — two passes:
#    a) live_hosts.json: fast pass on confirmed live hosts with rich
#       metadata (status code, tech, title) for quick wins
#    b) all_urls.txt: full pass on historical URLs from gau where
#       most interesting endpoints (forgotten APIs, reset tokens, etc.)
#       tend to surface
# ----------------------------------------------------------------
info "Launching RECOON triage — pass 1/2: live hosts..."
echo

python3 "$RECOON_SCRIPT" live_hosts.json \
    --target "$DOMAIN" \
    --domain-filter "$DOMAIN" \
    --model "$MODEL" \
    --output "recon_report_hosts_${TIMESTAMP}.json" \
    --markdown-output "recon_report_hosts_${TIMESTAMP}.md" \
    $DIFF_ONLY

echo
info "Launching RECOON triage — pass 2/2: historical URLs (${URL_COUNT} total)..."
echo

python3 "$RECOON_SCRIPT" all_urls.txt \
    --target "$DOMAIN" \
    --domain-filter "$DOMAIN" \
    --model "$MODEL" \
    --output "recon_report_urls_${TIMESTAMP}.json" \
    --markdown-output "recon_report_urls_${TIMESTAMP}.md" \
    $DIFF_ONLY

echo
success "All done! Files:"
success "  subs.txt"
success "  live_hosts.txt / live_hosts.json"
success "  all_urls.txt"
success "  sensitive_files.txt"
success "  recon_report_hosts_${TIMESTAMP}.json / .md  (live hosts triage)"
success "  recon_report_urls_${TIMESTAMP}.json  / .md  (historical URLs triage)"
