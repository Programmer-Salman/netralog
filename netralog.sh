#!/usr/bin/env bash
# Header and defaults
# =====================================================
# NetraLog - Linux Bash Log Analyzer
# Analyzes web access logs (Apache/Nginx combined format) and SSH auth logs
# It report suspicious PATTERNS (indicators) , not confirmed attacks.
# =====================================================

set -o pipefail

VERSION="1.0.0"
TOP_N=10
LOG_TYPE="auto"
START_DATE=""
END_DATE=""
REPORT_FILE=""
CSV_DIR=""
USE_COLOR=1

BRUTE_THRESHOLD=5
HIGH_REQ_THRESHOLD=150
PROBE_404_THRESHOLD=10
SENSITIVE_THRESHOLD=3
DENIED_THRESHOLD=10

TMP_DIR=""

# Help, errors, and cleanup

usage() {
    cat <<EOF
NetraLog v$VERSION - Linux Bash Log Analyzer

Usage: $(basename "$0") [options] <logfile>

Options:
    -t TYPE     Log type: auto (default), access, auth
    -n NUM      How many top items to show (default: $TOP_N)
    -s DATE     Start date, YYYY-MM-DD (access logs only)
    -e DATE     End date, YYYY-MM-DD (access logs only)
    -o FILE     Save plain-text report to FILE
    -c DIR      Save CSV files into DIR
    -b NUM      Failed-login threshold per IP (default: $BRUTE_THRESHOLD)
    -r NUM      High request volume threshold per IP (default: $HIGH_REQ_THRESHOLD)
    -p NUM      Repeated 404 threshold per IP (default: $PROBE_404_THRESHOLD)
    -N          Disable colored output
    -h          Show this help
    -v          Show version

Examples:
    $(basename "$0") sample-logs/access.log
    $(basename "$0") -t auth -b 3 sample-logs/auth.log
    $(basename "$0") -s 2025-10-11 -e 2025-10-12 -o reports/day2.txt sample-logs/access.log
EOF
}
usage
die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf -- "$TMP_DIR"
    fi
}

trap cleanup EXIT

is_positive_int() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

valid_date() {
    [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1

    date -d "$1" >/dev/null 2>&1 || return 1

    [[ "$(date -d "$1" +%F 2>/dev/null)" == "$1" ]]
}
