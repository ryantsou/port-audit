# PortAudit

Simple tool to audit exposed ports/services on Linux, keep a baseline, and detect drift.

What it does:

- Lists listening TCP/UDP sockets
- Gives a quick risk view (HIGH / MEDIUM / LOW)
- Exports JSON for automation
- Saves a baseline and compares drift over time
- Includes helper scripts for hardening + daily monitoring

## Requirements

- Linux host
- Bash
- `ss` (recommended) or `netstat` (fallback)
- `systemctl` (optional, for service snapshot)

## Installation

```bash
git clone https://github.com/ryantsou/port-audit.git
cd port-audit
chmod +x port-audit.sh
chmod +x scripts/*.sh
```

## Usage

```bash
./port-audit.sh [OPTIONS]
```

Running as root is recommended to see process ownership details on sockets, but not strictly required.

## Options

- `-p, --ports` : show only port analysis
- `-s, --services` : show only active services snapshot
- `-a, --all` : show ports and services (default)
- `-o, --output FILE` : save human-readable report to file
- `--json FILE` : export structured JSON report
- `--top N` : number of top risky sockets to display (default: 25)
- `--save-baseline FILE` : save current baseline
- `--compare-baseline FILE` : compare current state with baseline
- `--no-color` : disable ANSI colors
- `-h, --help` : display help

## Practical workflows

### 1) Quick audit

```bash
sudo ./port-audit.sh --all --top 30 --output audit.txt --json audit.json
```

### 2) Save baseline

```bash
sudo ./port-audit.sh --ports --save-baseline baseline.txt
```

### 3) Check drift

```bash
sudo ./port-audit.sh --ports --compare-baseline baseline.txt
```

### 4) CI-friendly run

```bash
./port-audit.sh --ports --no-color --json report.json
```

## Hardening and monitoring scripts

### 1) Restrict SSH bind

Apply:

```bash
sudo ./scripts/apply-pro-hardening.sh --ssh-bind 192.168.1.10 --apply
```

Preview only:

```bash
./scripts/apply-pro-hardening.sh --ssh-bind 192.168.1.10 --dry-run
```

### 2) Restrict SSH source CIDRs (nftables)

Apply:

```bash
sudo ./scripts/apply-pro-hardening.sh --ssh-cidrs "192.168.1.0/24 10.10.0.0/16" --apply
```

IPv6 CIDRs are supported too.

### 3) Disable non-essential services

Apply:

```bash
sudo ./scripts/apply-pro-hardening.sh --disable "avahi-daemon wsdd minidlna" --apply
```

### 4) Daily monitoring

Install timer:

```bash
sudo ./scripts/install-monitor-systemd.sh
```

Manual run:

```bash
sudo ./scripts/monitor-portaudit.sh --baseline /var/lib/portaudit/baseline.txt --report-dir /var/log/portaudit --top 25
```

Alert behavior:

- Exit code `2` when high risk ports or new sockets are detected
- Event sent to syslog with tag `portaudit`
- Timestamped TXT + JSON reports in report directory

## Operations files

- [scripts/apply-pro-hardening.sh](scripts/apply-pro-hardening.sh)
- [scripts/monitor-portaudit.sh](scripts/monitor-portaudit.sh)
- [scripts/install-monitor-systemd.sh](scripts/install-monitor-systemd.sh)
- [deploy/systemd/portaudit-monitor.service](deploy/systemd/portaudit-monitor.service)
- [deploy/systemd/portaudit-monitor.timer](deploy/systemd/portaudit-monitor.timer)

## Output details

Text report includes:

- Exposure summary (`total`, `high`, `medium`, `low`)
- Top risky sockets sorted by score
- Security recommendations based on findings
- Active services snapshot
- Optional baseline drift section

JSON report includes:

- Metadata (timestamp, host, user)
- Risk summary
- Full socket list with per-socket score

## Notes

- Risk level is heuristic. Always validate with your real context.
- Baseline files are text and versionable in Git for infrastructure traceability.

## License

MIT. See [LICENSE](LICENSE).

## Author

Riantsoa RAJHONSON
