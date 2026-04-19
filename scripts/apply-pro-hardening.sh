#!/usr/bin/env bash

set -euo pipefail

SSH_BIND_ADDRESS=""
SSH_ALLOWED_CIDRS=""
DISABLE_SERVICES=""
DRY_RUN=false
APPLY=false

log() {
    printf "[INFO] %s\n" "$1"
}

warn() {
    printf "[WARN] %s\n" "$1" >&2
}

fail() {
    printf "[ERROR] %s\n" "$1" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Apply professional hardening actions:
- Restrict sshd bind address
- Restrict SSH source CIDRs via nftables
- Disable unnecessary network services

Options:
  --ssh-bind ADDRESS        Address for sshd ListenAddress (example: 192.168.1.10)
  --ssh-cidrs "CIDR ..."    Allowed SSH source CIDRs (example: "192.168.1.0/24 10.0.0.0/8")
  --disable "SVC ..."       Services to stop+disable (example: "avahi-daemon wsdd minidlna")
  --apply                   Apply changes (required to modify system)
  --dry-run                 Print planned changes only
  -h, --help                Show help

Examples:
  sudo $0 --ssh-bind 192.168.1.10 --ssh-cidrs "192.168.1.0/24" --disable "avahi-daemon wsdd" --apply
  $0 --ssh-bind 192.168.1.10 --ssh-cidrs "192.168.1.0/24" --dry-run
EOF
}

run_cmd() {
    if [[ "$DRY_RUN" == true ]]; then
        printf "[DRY-RUN]"
        for arg in "$@"; do
            printf " %q" "$arg"
        done
        printf "\n"
    else
        "$@"
    fi
}

require_root_if_applying() {
    if [[ "$APPLY" == true && "$EUID" -ne 0 ]]; then
        fail "--apply requires root privileges"
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ssh-bind)
                [[ $# -ge 2 ]] || fail "Missing value for --ssh-bind"
                SSH_BIND_ADDRESS="$2"
                shift 2
                ;;
            --ssh-cidrs)
                [[ $# -ge 2 ]] || fail "Missing value for --ssh-cidrs"
                SSH_ALLOWED_CIDRS="$2"
                shift 2
                ;;
            --disable)
                [[ $# -ge 2 ]] || fail "Missing value for --disable"
                DISABLE_SERVICES="$2"
                shift 2
                ;;
            --apply)
                APPLY=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
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

    if [[ "$APPLY" == false && "$DRY_RUN" == false ]]; then
        fail "Use either --apply or --dry-run"
    fi
}

configure_sshd_bind() {
    [[ -n "$SSH_BIND_ADDRESS" ]] || return

    local cfg="/etc/ssh/sshd_config.d/99-portaudit-hardening.conf"
    log "Configuring sshd bind address to $SSH_BIND_ADDRESS"

    if [[ "$DRY_RUN" == true ]]; then
        cat <<EOF
[DRY-RUN] Would write file: $cfg
ListenAddress $SSH_BIND_ADDRESS
AddressFamily any
EOF
    else
        mkdir -p /etc/ssh/sshd_config.d
        cat > "$cfg" <<EOF
# Managed by PortAudit hardening script
ListenAddress $SSH_BIND_ADDRESS
AddressFamily any
EOF
    fi

    if command -v sshd >/dev/null 2>&1; then
        run_cmd sshd -t
        if command -v systemctl >/dev/null 2>&1; then
            if [[ "$DRY_RUN" == true ]]; then
                printf "[DRY-RUN] systemctl reload ssh || systemctl reload sshd\n"
            else
                systemctl reload ssh || systemctl reload sshd
            fi
        else
            warn "systemctl not found; reload ssh daemon manually"
        fi
    else
        warn "sshd binary not found; skipping ssh config validation"
    fi
}

configure_nft_ssh_acl() {
    [[ -n "$SSH_ALLOWED_CIDRS" ]] || return

    if ! command -v nft >/dev/null 2>&1; then
        warn "nft command not found; skipping firewall configuration"
        return
    fi

    local script
    script="$(mktemp)"

    {
        echo "add table inet portaudit"
        echo "flush table inet portaudit"
        echo "add chain inet portaudit input { type filter hook input priority 0; policy accept; }"
        echo "add rule inet portaudit input ct state established,related accept"
        echo "add rule inet portaudit input iif lo accept"
        for cidr in $SSH_ALLOWED_CIDRS; do
            if [[ "$cidr" == *:* ]]; then
                echo "add rule inet portaudit input ip6 saddr $cidr tcp dport 22 accept"
            else
                echo "add rule inet portaudit input ip saddr $cidr tcp dport 22 accept"
            fi
        done
        echo "add rule inet portaudit input tcp dport 22 drop"
    } > "$script"

    log "Applying nftables SSH ACL"
    if [[ "$DRY_RUN" == true ]]; then
        printf "[DRY-RUN] nft -f %s\n" "$script"
        cat "$script"
    else
        nft -f "$script"
        if [[ -w /etc/nftables.conf ]]; then
            nft list ruleset > /etc/nftables.conf
        else
            warn "Cannot write /etc/nftables.conf; rules may not persist reboot"
        fi
    fi

    rm -f "$script"
}

disable_unneeded_services() {
    [[ -n "$DISABLE_SERVICES" ]] || return

    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemctl not found; cannot disable services automatically"
        return
    fi

    for svc in $DISABLE_SERVICES; do
        log "Disabling service: $svc"
        run_cmd systemctl stop "$svc"
        run_cmd systemctl disable "$svc"
    done
}

main() {
    parse_args "$@"
    require_root_if_applying

    configure_sshd_bind
    configure_nft_ssh_acl
    disable_unneeded_services

    log "Hardening workflow completed"
}

main "$@"
