#!/usr/bin/env bash

################################################################################
# PortAudit - Professional Linux port and service security audit
################################################################################

set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

OUTPUT_FILE=""
JSON_FILE=""
SAVE_BASELINE_FILE=""
COMPARE_BASELINE_FILE=""
SHOW_PORTS=false
SHOW_SERVICES=false
SHOW_ALL=true
NO_COLOR=false
TOP_N=25

TMP_RAW=""
TMP_DATA=""
TMP_BASELINE_CURRENT=""
TMP_BASELINE_TARGET=""
TMP_ADDED=""
TMP_REMOVED=""

warn() {
    printf "%b[WARN] %s%b\n" "$YELLOW" "$1" "$NC" >&2
}

fail() {
    printf "%b[ERROR] %s%b\n" "$RED" "$1" "$NC" >&2
    exit 1
}

cleanup() {
    rm -f "$TMP_RAW" "$TMP_DATA" "$TMP_BASELINE_CURRENT" "$TMP_BASELINE_TARGET" "$TMP_ADDED" "$TMP_REMOVED"
}

disable_colors_if_needed() {
    if [[ "$NO_COLOR" == true || ! -t 1 ]]; then
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        NC=''
    fi
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Professional audit of listening ports and active services.

Core options:
  -p, --ports                 Show only port analysis
  -s, --services              Show only service analysis
  -a, --all                   Show ports + services (default)
  -o, --output FILE           Save human-readable report to FILE
      --json FILE             Export structured JSON report
      --top N                 Number of top risky sockets to display (default: 25)
      --save-baseline FILE    Save current port baseline to FILE
      --compare-baseline FILE Compare current ports against FILE baseline
      --no-color              Disable ANSI colors
  -h, --help                  Show this help

Examples:
  $0 --all --json report.json --save-baseline baseline.txt
  $0 --ports --compare-baseline baseline.txt
  sudo $0 --all --output audit.txt
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--ports)
                SHOW_PORTS=true
                SHOW_SERVICES=false
                SHOW_ALL=false
                shift
                ;;
            -s|--services)
                SHOW_SERVICES=true
                SHOW_PORTS=false
                SHOW_ALL=false
                shift
                ;;
            -a|--all)
                SHOW_ALL=true
                SHOW_PORTS=false
                SHOW_SERVICES=false
                shift
                ;;
            -o|--output)
                [[ $# -ge 2 ]] || fail "Missing value for --output"
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --json)
                [[ $# -ge 2 ]] || fail "Missing value for --json"
                JSON_FILE="$2"
                shift 2
                ;;
            --top)
                [[ $# -ge 2 ]] || fail "Missing value for --top"
                [[ "$2" =~ ^[0-9]+$ ]] || fail "--top must be an integer"
                TOP_N="$2"
                shift 2
                ;;
            --save-baseline)
                [[ $# -ge 2 ]] || fail "Missing value for --save-baseline"
                SAVE_BASELINE_FILE="$2"
                shift 2
                ;;
            --compare-baseline)
                [[ $# -ge 2 ]] || fail "Missing value for --compare-baseline"
                COMPARE_BASELINE_FILE="$2"
                shift 2
                ;;
            --no-color)
                NO_COLOR=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                fail "Unknown option: $1"
                ;;
        esac
    done
}

init_temp_files() {
    TMP_RAW="$(mktemp)"
    TMP_DATA="$(mktemp)"
    TMP_BASELINE_CURRENT="$(mktemp)"
    TMP_BASELINE_TARGET="$(mktemp)"
    TMP_ADDED="$(mktemp)"
    TMP_REMOVED="$(mktemp)"
    trap cleanup EXIT
}

json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

extract_port() {
    local endpoint="$1"
    if [[ "$endpoint" =~ :([0-9]+)$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        printf '%s' "0"
    fi
}

is_wildcard_bind() {
    local local_addr="$1"
    [[ "$local_addr" == *":*" ]] || return 1
    if [[ "$local_addr" == \*:* || "$local_addr" == "0.0.0.0:"* || "$local_addr" == "[::]:"* || "$local_addr" == ":::"* ]]; then
        return 0
    fi
    return 1
}

port_risk() {
    local port="$1"
    local local_addr="$2"
    local risk="LOW"

    case "$port" in
        23|135|139|445|1433|1521|3389|5432|5900|6379|9200|9300|11211|27017)
            risk="HIGH"
            ;;
        21|22|25|53|80|111|389|443|587|993|995|2049|3306|8080|8443)
            risk="MEDIUM"
            ;;
        *)
            risk="LOW"
            ;;
    esac

    # Escalade le risque si le service est exposé sur toutes les interfaces.
    if is_wildcard_bind "$local_addr"; then
        if [[ "$risk" == "LOW" ]]; then
            risk="MEDIUM"
        elif [[ "$risk" == "MEDIUM" ]]; then
            risk="HIGH"
        fi
    fi

    printf '%s' "$risk"
}

risk_score() {
    local risk="$1"
    case "$risk" in
        HIGH) printf '%s' 3 ;;
        MEDIUM) printf '%s' 2 ;;
        *) printf '%s' 1 ;;
    esac
}

collect_ports() {
    local ss_cmd
    if command -v ss >/dev/null 2>&1; then
        if [[ "$EUID" -eq 0 ]]; then
            ss_cmd=(ss -H -lntu -p)
        else
            ss_cmd=(ss -H -lntu)
        fi

        "${ss_cmd[@]}" 2>/dev/null | awk '
            {
                proto=$1
                state=$2
                local_addr=$5
                peer=$6
                proc=""
                for (i=7; i<=NF; i++) {
                    proc = proc $i " "
                }
                gsub(/[[:space:]]+$/, "", proc)
                print proto "|" state "|" local_addr "|" peer "|" proc
            }
        ' > "$TMP_RAW"
    elif command -v netstat >/dev/null 2>&1; then
        warn "Using netstat fallback. Install iproute2 for best results."
        netstat -lntu 2>/dev/null | awk 'NR>2 {
            proto=$1
            local_addr=$4
            peer=$5
            print proto "|LISTEN|" local_addr "|" peer "|"
        }' > "$TMP_RAW"
    else
        fail "Neither ss nor netstat is available on this system"
    fi

    : > "$TMP_DATA"
    while IFS='|' read -r proto state local_addr peer proc; do
        [[ -n "$proto" ]] || continue
        local port
        local risk
        port="$(extract_port "$local_addr")"
        [[ "$port" =~ ^[0-9]+$ ]] || port=0
        risk="$(port_risk "$port" "$local_addr")"

        # Format: proto|state|local|peer|process|port|risk|score
        printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
            "$proto" "$state" "$local_addr" "$peer" "$proc" "$port" "$risk" "$(risk_score "$risk")" >> "$TMP_DATA"
    done < "$TMP_RAW"
}

print_header() {
    printf "%b============================================================%b\n" "$BLUE" "$NC"
    printf "%bPortAudit Report%b\n" "$BLUE" "$NC"
    printf "%bTimestamp: %s%b\n" "$BLUE" "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$NC"
    printf "%bHostname: %s%b\n" "$BLUE" "$(hostname)" "$NC"
    printf "%bUser: %s%b\n" "$BLUE" "$(id -un)" "$NC"
    printf "%b============================================================%b\n\n" "$BLUE" "$NC"
}

print_ports_report() {
    local total high medium low wildcard
    total=$(wc -l < "$TMP_DATA")
    high=$(awk -F'|' '$7=="HIGH" {c++} END {print c+0}' "$TMP_DATA")
    medium=$(awk -F'|' '$7=="MEDIUM" {c++} END {print c+0}' "$TMP_DATA")
    low=$(awk -F'|' '$7=="LOW" {c++} END {print c+0}' "$TMP_DATA")
    wildcard=$(awk -F'|' '$3 ~ /^(\*|0\.0\.0\.0|\[::\]|:::):/ {c++} END {print c+0}' "$TMP_DATA")

    printf "%b[1] Port Exposure Summary%b\n" "$GREEN" "$NC"
    printf "  Total listening sockets : %s\n" "$total"
    printf "  HIGH risk               : %s\n" "$high"
    printf "  MEDIUM risk             : %s\n" "$medium"
    printf "  LOW risk                : %s\n" "$low"
    printf "  Wildcard bindings       : %s\n\n" "$wildcard"

    printf "%b[2] Top Risky Listening Sockets (Top %s)%b\n" "$GREEN" "$TOP_N" "$NC"
    printf "%-6s %-6s %-26s %-8s %-40s\n" "RISK" "PROTO" "LOCAL" "PORT" "PROCESS"
    awk -F'|' '{print $8"|"$7"|"$1"|"$3"|"$6"|"$5}' "$TMP_DATA" \
        | sort -t'|' -k1,1nr -k5,5n \
        | head -n "$TOP_N" \
        | awk -F'|' '{printf "%-6s %-6s %-26s %-8s %-40s\n", $2, $3, $4, $5, ($6==""?"n/a":$6)}'
    printf "\n"

    printf "%b[3] Actionable Recommendations%b\n" "$GREEN" "$NC"
    if [[ "$high" -gt 0 ]]; then
        printf "  - Review and restrict HIGH-risk ports with firewall rules (nftables/iptables/security groups).\n"
    fi
    if [[ "$wildcard" -gt 0 ]]; then
        printf "  - Replace wildcard binds (0.0.0.0/*/[::]) with explicit trusted interfaces when possible.\n"
    fi
    if [[ "$EUID" -ne 0 ]]; then
        printf "  - Re-run as root to include process ownership details in socket inventory.\n"
    fi
    if [[ "$high" -eq 0 && "$wildcard" -eq 0 ]]; then
        printf "  - No critical exposure detected in current snapshot. Keep baseline and monitor drift.\n"
    fi
    printf "\n"
}

collect_services() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=active --no-pager --no-legend 2>/dev/null \
            | awk '{printf "%s|%s|%s|%s\n", $1, $3, $4, $5}'
    elif command -v service >/dev/null 2>&1; then
        service --status-all 2>&1 | awk '/\[ \+ \]/ {printf "%s|running|n/a|n/a\n", $NF}'
    fi
}

print_services_report() {
    local services
    services="$(collect_services)"

    printf "%b[4] Active Services Snapshot%b\n" "$GREEN" "$NC"
    if [[ -z "$services" ]]; then
        printf "  No service manager data available on this host.\n\n"
        return
    fi

    printf "%-45s %-8s %-10s %-10s\n" "UNIT" "LOAD" "ACTIVE" "SUB"
    printf "%s\n" "$services" | head -n 40 | awk -F'|' '{printf "%-45s %-8s %-10s %-10s\n", $1, $2, $3, $4}'
    printf "\n"
}

build_baseline_current() {
    awk -F'|' '{print $1"|"$3"|"$6"|"$7"|"$5}' "$TMP_DATA" | sort -u > "$TMP_BASELINE_CURRENT"
}

save_baseline() {
    [[ -n "$SAVE_BASELINE_FILE" ]] || return
    build_baseline_current
    {
        printf "# PortAudit baseline generated at %s\n" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf "# Format: proto|local|port|risk|process\n"
        cat "$TMP_BASELINE_CURRENT"
    } > "$SAVE_BASELINE_FILE"
    printf "%bBaseline saved:%b %s\n\n" "$GREEN" "$NC" "$SAVE_BASELINE_FILE"
}

compare_baseline() {
    [[ -n "$COMPARE_BASELINE_FILE" ]] || return
    [[ -f "$COMPARE_BASELINE_FILE" ]] || fail "Baseline file not found: $COMPARE_BASELINE_FILE"

    build_baseline_current
    grep -v '^#' "$COMPARE_BASELINE_FILE" | sed '/^$/d' | sort -u > "$TMP_BASELINE_TARGET"

    comm -13 "$TMP_BASELINE_TARGET" "$TMP_BASELINE_CURRENT" > "$TMP_ADDED"
    comm -23 "$TMP_BASELINE_TARGET" "$TMP_BASELINE_CURRENT" > "$TMP_REMOVED"

    printf "%b[5] Baseline Drift Analysis%b\n" "$GREEN" "$NC"
    printf "  Baseline source: %s\n" "$COMPARE_BASELINE_FILE"
    printf "  Newly opened sockets: %s\n" "$(wc -l < "$TMP_ADDED")"
    printf "  Closed sockets      : %s\n\n" "$(wc -l < "$TMP_REMOVED")"

    if [[ -s "$TMP_ADDED" ]]; then
        printf "%b  New Exposure:%b\n" "$YELLOW" "$NC"
        head -n 20 "$TMP_ADDED" | awk -F'|' '{printf "    + %-5s %-22s %-6s %-6s %s\n", $1, $2, $3, $4, $5}'
        printf "\n"
    fi
    if [[ -s "$TMP_REMOVED" ]]; then
        printf "%b  Removed Exposure:%b\n" "$YELLOW" "$NC"
        head -n 20 "$TMP_REMOVED" | awk -F'|' '{printf "    - %-5s %-22s %-6s %-6s %s\n", $1, $2, $3, $4, $5}'
        printf "\n"
    fi
    if [[ ! -s "$TMP_ADDED" && ! -s "$TMP_REMOVED" ]]; then
        printf "  No drift detected compared to baseline.\n\n"
    fi
}

export_json_report() {
    [[ -n "$JSON_FILE" ]] || return

    local total high medium low
    total=$(wc -l < "$TMP_DATA")
    high=$(awk -F'|' '$7=="HIGH" {c++} END {print c+0}' "$TMP_DATA")
    medium=$(awk -F'|' '$7=="MEDIUM" {c++} END {print c+0}' "$TMP_DATA")
    low=$(awk -F'|' '$7=="LOW" {c++} END {print c+0}' "$TMP_DATA")

    {
        printf '{\n'
        printf '  "metadata": {\n'
        printf '    "timestamp": "%s",\n' "$(json_escape "$(date -Iseconds)")"
        printf '    "hostname": "%s",\n' "$(json_escape "$(hostname)")"
        printf '    "user": "%s"\n' "$(json_escape "$(id -un)")"
        printf '  },\n'
        printf '  "summary": {"total": %s, "high": %s, "medium": %s, "low": %s},\n' "$total" "$high" "$medium" "$low"
        printf '  "sockets": [\n'

        local first=true
        while IFS='|' read -r proto state local_addr peer proc port risk score; do
            if [[ "$first" == true ]]; then
                first=false
            else
                printf ',\n'
            fi
            printf '    {"proto":"%s","state":"%s","local":"%s","peer":"%s","process":"%s","port":%s,"risk":"%s","score":%s}' \
                "$(json_escape "$proto")" \
                "$(json_escape "$state")" \
                "$(json_escape "$local_addr")" \
                "$(json_escape "$peer")" \
                "$(json_escape "$proc")" \
                "$port" \
                "$(json_escape "$risk")" \
                "$score"
        done < "$TMP_DATA"

        printf '\n  ]\n'
        printf '}\n'
    } > "$JSON_FILE"

    printf "%bJSON report exported:%b %s\n\n" "$GREEN" "$NC" "$JSON_FILE"
}

main() {
    parse_arguments "$@"
    disable_colors_if_needed
    init_temp_files

    if [[ -n "$OUTPUT_FILE" ]]; then
        exec > >(tee "$OUTPUT_FILE")
    fi

    collect_ports
    print_header

    if [[ "$SHOW_ALL" == true || "$SHOW_PORTS" == true ]]; then
        print_ports_report
        compare_baseline
        save_baseline
    fi

    if [[ "$SHOW_ALL" == true || "$SHOW_SERVICES" == true ]]; then
        print_services_report
    fi

    export_json_report

    printf "%bAudit completed at %s%b\n" "$BLUE" "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$NC"
    if [[ -n "$OUTPUT_FILE" ]]; then
        printf "%bHuman report saved:%b %s\n" "$GREEN" "$NC" "$OUTPUT_FILE"
    fi
}

main "$@"
