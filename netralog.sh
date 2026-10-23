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

# ----------------------------------- Log type detection ------------------------------------------
detect_type() {
    if grep -m1 -qE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:' "$LOG_FILE"; then
        echo access
    elif grep -m1 -qE 'sshd(\[[0-9]+\])?:' "$LOG_FILE"; then
        echo auth
    else
        echo unknown
    fi
}

if [ "$LOG_TYPE" = "auto" ]; then
    LOG_TYPE="$(detect_type)"
    [ "$LOG_TYPE" != "unknown" ] ||
        die "Could not detect log type. Use -t access or -t auth."
fi

normalize_access() {
    local s="${START_DATE//-/}"
    local e="${END_DATE//-/}"

    awk -v s="$s" -v e="$e" -v badfile="$BAD_COUNT_FILE" '
    BEGIN {
        split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
        for (i = 1; i <= 12; i++)
            mon[m[i]] = sprintf("%02d", i)
        bad = 0
    }

    {
        ts = $4

        if (substr(ts, 1, 1) != "[" ||
            !(substr(ts, 5, 3) in mon) ||
            $9 !~ /^[0-9][0-9][0-9]$/) {
            bad++
            next
        }

        d = substr(ts, 9, 4) mon[substr(ts, 5, 3)] substr(ts, 2, 2)

        if (s != "" && d < s)
            next

        if (e != "" && d > e)
            next

        method = substr($6, 2)

        printf "%s\t%s\t%s\t%s\t%s\n", $1, d, $9, method, $7
    }

    END {
        print bad > badfile
        close(badfile)
    }
    ' "$LOG_FILE" > "$NORM"
}

# ------------------------------- Helper functions ------------------------------------
# count_file FILE FIELD -> "count<TAB>value", highest first
count_field() {
    cut -f "$2" "$1" |
        sort |
        uniq -c |
        sort -k1,1nr -k2,2 |
        awk '{print $1 "\t" $2}'
}

print_top() {
    head -n "$TOP_N" |
        awk -F'\t' '{printf " %-42s %8d\n", $2, $1}'
}

csv_from_counts() {
    awk -F'\t' -v h1="$1" -v h2="$2" '
    function csv(s) {
        gsub(/"/, "\"\"", s)
        return "\"" s "\""
    }
    BEGIN {
        print csv(h1) "," csv(h2)
    }
    {
        print csv($2) "," csv($1)
    }'
}

section() {
    echo
    echo "== $1 =="
}

flag() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$SUSP"
}

indicator() {
    if [ "$2" -gt 0 ]; then
        printf ' [!] %-34s DETECTED (%d IP)\n' "$1" "$2"
    else
        printf ' [ok] %-33s none\n' "$1"
    fi
}

report_access() {
    local total unique bad

    total=$(wc -l < "$NORM")
    bad=$(cat "$BAD_COUNT_FILE" 2>/dev/null || echo 0)

    echo "========= NETRALOG REPORT =============="
    echo "File:         $LOG_FILE"
    echo "Log type:     Web access log (Apache2/Nginx combined)"
    echo "Generated:    $(date '+%Y-%m-%d %H:%M:%S')"

    [ -z "$START_DATE" ] || echo "From date: $START_DATE"
    [ -z "$END_DATE" ] || echo "To date: $END_DATE"

    if [ "$total" -eq 0 ]; then
        echo
        echo "No valid log entries found for this filter."
        echo "Skipped (malformed) lines: $bad"
        return
    fi

    unique=$(cut -f1 "$NORM" | sort -u | wc -l)

    section "OVERVIEW"

    printf ' %-28s %s\n' "Total log entries:" "$total"
    printf ' %-28s %s\n' "Unique IP Addresses:" "$unique"
    printf ' %-28s %s\n' "Malformed lines skipped:" "$bad"

    printf ' %-28s %s to %s\n' "Date range:" \
        "$(cut -f2 "$NORM" | sort | head -n1)" \
        "$(cut -f2 "$NORM" | sort | tail -n1)"

    section "TOP $TOP_N IP ADDRESSES (by requests)"

    count_field "$NORM" 1 | print_top

    section "HTTP STATUS CODES"
    count_field "$NORM" 3 | awk -F'\t' '{printf " %-10s %8d\n", $2, $1}'

    section "HTTP STATUS GROUPS"
    awk -F'\t' '{ group = substr($3, 1, 1) "xx"; count[group]++ }
        END { for (group in count) printf " %-10s %8d\n", group, count[group] }' "$NORM" | sort

    section "TOP $TOP_N REQUESTED URLS"
    count_field "$NORM" 5 | print_top

    section "HTTP METHODS"
    count_field "$NORM" 4 | awk -F'\t' '{printf " %-10s %8d\n", $2, $1}'
}

normalize_auth() {
    awk '
    /sshd/ && /Failed password for/ {
        user = ""; ip = ""
        for (i = 1; i <= NF; i++) {
            if ($i == "for" && user == "") {
                if ($(i+1) == "invalid" && $(i+2) == "user")
                    user = $(i+3)
                else
                    user = $(i+1)
            }
            if ($i == "from" && ip == "") ip = $(i+1)
        }
        if (ip != "" && user != "") print "F\t" ip "\t" user
        next
    }
    /sshd/ && /Accepted (password|publickey) for/ {
        user = ""; ip = ""
        for (i = 1; i <= NF; i++) {
            if ($i == "for" && user == "") user = $(i+1)
            if ($i == "from" && ip == "") ip = $(i+1)
        }
        if (ip != "" && user != "") print "A\t" ip "\t" user
    }
    ' "$LOG_FILE" > "$NORM"
}

report_auth() {
    local total failed accepted

    total=$(wc -l < "$NORM")
    failed=$(awk -F'\t' '$1 == "F"' "$NORM" | wc -l)
    accepted=$(awk -F'\t' '$1 == "A"' "$NORM" | wc -l)
    echo "========= NETRALOG REPORT =============="
    echo "File:         $LOG_FILE"
    echo "Log type:     SSH auth log"
    echo "Generated:    $(date '+%Y-%m-%d %H:%M:%S')"

    if [ "$total" -eq 0 ]; then
        echo
        echo "No SSH auth entries found."
        return
    fi

    section "OVERVIEW"
    printf ' %-28s %s\n' "Total auth events:" "$total"
    printf ' %-28s %s\n' "Failed logins:" "$failed"
    printf ' %-28s %s\n' "Successful SSH logins:" "$accepted"

    if [ "$failed" -eq 0 ]; then
        echo
        echo "No failed login attempts detected."
        return
    fi

    awk -F'\t' '$1 == "F" {print $2 "\t" $3}' "$NORM" > "$TMP_DIR/failed.tsv"
    printf ' %-28s %s\n' "Unique IPs with failed logins:" "$(cut -f1 "$TMP_DIR/failed.tsv" | sort -u | wc -l)"
    printf ' %-28s %s\n' "Unique usernames attempted:" "$(cut -f2 "$TMP_DIR/failed.tsv" | sort -u | wc -l)"

    section "TOP $TOP_N IP ADDRESSES (by failed logins)"
    count_field "$TMP_DIR/failed.tsv" 1 | print_top
    section "TOP $TOP_N USERNAMES (by failed logins)"
    count_field "$TMP_DIR/failed.tsv" 2 | print_top
}

main() {
    if [ "$LOG_TYPE" = "access" ]; then
        normalize_access
        report_access
    elif [ "$LOG_TYPE" = "auth" ]; then
        normalize_auth
        report_auth
    fi

    if [ -n "$REPORT_FILE" ]; then
        : > "$REPORT_FILE"
        if [ "$LOG_TYPE" = "access" ]; then
            normalize_access
            report_access > "$REPORT_FILE"
        else
            normalize_auth
            report_auth > "$REPORT_FILE"
        fi
    fi
}

main "$@"

