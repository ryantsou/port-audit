#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT_SCRIPT="$ROOT_DIR/port-audit.sh"

BASELINE_FILE="/var/lib/portaudit/baseline.txt"
REPORT_DIR="/var/log/portaudit"
TOP_N=25

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Run daily PortAudit monitoring and alert on security drift.

Options:
  --baseline FILE   Baseline file path (default: /var/lib/portaudit/baseline.txt)
  --report-dir DIR  Report directory (default: /var/log/portaudit)
  --top N           Top risky sockets (default: 25)
  -h, --help        Show help
EOF
}

fail() {
    printf "[ERROR] %s\n" "$1" >&2
    exit 1
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --baseline)
                [[ $# -ge 2 ]] || fail "Missing value for --baseline"
                BASELINE_FILE="$2"
                shift 2
                ;;
            --report-dir)
                [[ $# -ge 2 ]] || fail "Missing value for --report-dir"
                REPORT_DIR="$2"
                shift 2
                ;;
            --top)
                [[ $# -ge 2 ]] || fail "Missing value for --top"
                TOP_N="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "Unknown option: $1"
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    if [[ ! -x "$AUDIT_SCRIPT" ]]; then
        fail "Audit script not executable: $AUDIT_SCRIPT"
    fi

    mkdir -p "$REPORT_DIR"
    mkdir -p "$(dirname "$BASELINE_FILE")"

    local ts txt json
    ts="$(date +%Y%m%d-%H%M%S)"
    txt="$REPORT_DIR/portaudit-$ts.txt"
    json="$REPORT_DIR/portaudit-$ts.json"

    if [[ ! -f "$BASELINE_FILE" ]]; then
        "$AUDIT_SCRIPT" --ports --save-baseline "$BASELINE_FILE" --no-color >/dev/null
        logger -t portaudit "Baseline initialized at $BASELINE_FILE"
    fi

    "$AUDIT_SCRIPT" --ports --top "$TOP_N" --compare-baseline "$BASELINE_FILE" --output "$txt" --json "$json" --no-color >/dev/null

    local high_count new_socket_count
    high_count="$(awk '/HIGH risk/{print $NF}' "$txt" | head -n 1)"
    new_socket_count="$(awk '/Newly opened sockets:/{print $NF}' "$txt" | head -n 1)"

    if [[ -z "$high_count" ]]; then
        high_count=0
    fi
    if [[ -z "$new_socket_count" ]]; then
        new_socket_count=0
    fi

    if [[ "$high_count" -gt 0 || "$new_socket_count" -gt 0 ]]; then
        logger -p auth.warning -t portaudit "ALERT high=$high_count new_sockets=$new_socket_count report=$txt json=$json"
        printf "[ALERT] high=%s new_sockets=%s\n" "$high_count" "$new_socket_count"
        exit 2
    fi

    logger -t portaudit "OK high=$high_count new_sockets=$new_socket_count report=$txt"
    printf "[OK] high=%s new_sockets=%s\n" "$high_count" "$new_socket_count"
}

main "$@"
