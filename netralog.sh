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

# Argument parsing and validation
# ------------------------------------------ Argument parsing ------------------------------------------

while getopts ":t:n:s:e:o:c:b:r:p:Nhv" opt; do
    case "$opt" in
        n) TOP_N="$OPTARG" ;;
        t) LOG_TYPE="$OPTARG" ;;
        s) START_DATE="$OPTARG" ;;
        e) END_DATE="$OPTARG" ;;
        o) REPORT_FILE="$OPTARG" ;;
        c) CSV_DIR="$OPTARG" ;;
        N) USE_COLOR=0 ;;
        b) BRUTE_THRESHOLD="$OPTARG" ;;
        r) HIGH_REQ_THRESHOLD="$OPTARG" ;;
        p) PROBE_404_THRESHOLD="$OPTARG" ;;
        h) usage; exit 0 ;;
        v) echo "NetraLog v$VERSION"; exit 0 ;;
        :)
            die "Option -$OPTARG needs a value. Use -h for help."
            ;;
        \?)
            die "Unknown option -$OPTARG. Use -h for help."
            ;;
    esac
done

shift "$((OPTIND - 1))"

# Validate positional arguments
[ "$#" -eq 1 ] || {
    usage >&2
    exit 1
}

LOG_FILE="$1"

# Validate the input log file
[ -e "$LOG_FILE" ] || die "File not found: $LOG_FILE"
[ -f "$LOG_FILE" ] || die "Not a regular file: $LOG_FILE"
[ -r "$LOG_FILE" ] || die "Cannot read file (permission denied): $LOG_FILE"
[ -s "$LOG_FILE" ] || die "File is empty: $LOG_FILE"

# Validate log type
case "$LOG_TYPE" in
    auto|access|auth) ;;
    *) die "Invalid type '$LOG_TYPE'. Use auto, access or auth." ;;
esac

# Validate numeric thresholds
for pair in \
    "TOP_N:$TOP_N" \
    "BRUTE_THRESHOLD:$BRUTE_THRESHOLD" \
    "HIGH_REQ_THRESHOLD:$HIGH_REQ_THRESHOLD" \
    "PROBE_404_THRESHOLD:$PROBE_404_THRESHOLD"
do
    is_positive_int "${pair#*:}" ||
        die "${pair%%:*} must be a positive whole number."
done

# Validate dates
[ -z "$START_DATE" ] ||
    valid_date "$START_DATE" ||
    die "Invalid start date: $START_DATE (use YYYY-MM-DD)"

[ -z "$END_DATE" ] ||
    valid_date "$END_DATE" ||
    die "Invalid end date: $END_DATE (use YYYY-MM-DD)"

# Validate date range
if [ -n "$START_DATE" ] &&
   [ -n "$END_DATE" ] &&
   [[ "$START_DATE" > "$END_DATE" ]]; then
    die "Start date is after end date."
fi

# Create CSV directory if requested
if [ -n "$CSV_DIR" ]; then
    mkdir -p "$CSV_DIR" 2>/dev/null ||
        die "Cannot create CSV directory: $CSV_DIR"
fi

# Create temporary working directory
TMP_DIR="$(mktemp -d)" ||
    die "Cannot create temp directory."

NORM="$TMP_DIR/normalized.tsv"
SUSP="$TMP_DIR/suspicious.tsv"
REPORT_TMP="$TMP_DIR/reports.txt"
BAD_COUNT_FILE="$TMP_DIR/bad.count"

# Initialize temporary files
: > "$SUSP"
