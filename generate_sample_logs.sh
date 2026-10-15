#!/usr/bin/env bash
# Generates FICTIONAL sample logs for NetraLog (safe to publish).
# All IPs come from documentation ranges (RFC 5737): 192.0.2.x, 198.51.100.x, 203.0.113.x
# Run: ./generate_sample_logs.sh   (creates sample-logs/access.log and sample-logs/auth.log)
set -e
OUT_DIR="${1:-sample-logs}"
mkdir -p "$OUT_DIR"
RANDOM=42   # fixed seed, so the output is the same every time
ACCESS="$OUT_DIR/access.log"
AUTH="$OUT_DIR/auth.log"
: > "$ACCESS"
: > "$AUTH"
NORMAL_IPS=(192.0.2.10 192.0.2.11 192.0.2.12 192.0.2.13 192.0.2.14 192.0.2.15
            198.51.100.20 198.51.100.21 198.51.100.22 198.51.100.23)
PAGES=(/ /index.html /about.html /contact.html /products /products/1 /products/2
       /blog /blog/post-1 /css/style.css /js/app.js /images/logo.png)
AGENTS=("Mozilla/5.0 (X11; Linux x86_64)"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)")
PROBE_PATHS=(/wp-login.php /.env /phpmyadmin/ /admin /.git/config /xmlrpc.php /backup.zip
             /config.php /old/ /test.php /server-status /login.php)
log_access() { # ip day hour minute second method url status bytes agent
  printf '%s - - [%s/Oct/2025:%02d:%02d:%02d +0000] "%s %s HTTP/1.1" %s %s "-" "%s"\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" >> "$ACCESS"
}
# 1) Normal traffic over 3 days: 900 requests
for i in $(seq 1 900); do
  ip=${NORMAL_IPS[$((RANDOM % ${#NORMAL_IPS[@]}))]}
  day=$((10 + RANDOM % 3))
  page=${PAGES[$((RANDOM % ${#PAGES[@]}))]}
  agent=${AGENTS[$((RANDOM % ${#AGENTS[@]}))]}
  r=$((RANDOM % 100))
  if   [ $r -lt 85 ]; then status=200
  elif [ $r -lt 93 ]; then status=301
  elif [ $r -lt 97 ]; then status=404
  else status=304; fi
  log_access "$ip" "$day" $((RANDOM % 24)) $((RANDOM % 60)) $((RANDOM % 60)) GET "$page" \
    $status $((500 + RANDOM % 5000)) "$agent"
done
# 2) Scanner: 203.0.113.50 probes many paths and gets 404 (day 11)
for i in $(seq 1 60); do
  p=${PROBE_PATHS[$((RANDOM % ${#PROBE_PATHS[@]}))]}
  log_access 203.0.113.50 11 3 $((i / 2)) $((RANDOM % 60)) GET "$p$i" 404 196 "python-requests/2.31"
done
# 3) Heavy client: 203.0.113.77 sends 220 requests in a short time (day 12)
for i in $(seq 1 220); do
  log_access 203.0.113.77 12 14 $((i / 10)) $((RANDOM % 60)) GET \
    /products/$((RANDOM % 5 + 1)) 200 1200 "curl/8.4.0"
done

# 4) Server errors from some real pages (day 12)
for i in $(seq 1 12); do
  log_access 198.51.100.22 12 16 $((i * 3)) 10 POST /checkout 500 340 \
    "Mozilla/5.0 (X11; Linux x86_64)"
done
# 5) Login page hammering with 401/403 (day 10)
for i in $(seq 1 30); do
  log_access 198.51.100.99 10 22 $((i / 3)) $((RANDOM % 60)) POST /login.php 403 220 \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
done
# 6) Two malformed lines to test error handling
echo 'this line is broken and should be skipped' >> "$ACCESS"
echo '192.0.2.10 - - [bad-date] "GET / HTTP/1.1" abc' >> "$ACCESS"
# ---------------------------- SSH auth.log ---------------------------------
auth() { # month-day time message
  printf 'Oct %s %s srv01 sshd[%d]: %s\n' "$1" "$2" $((1000 + RANDOM % 8000)) "$3" >> "$AUTH"
}
# Normal successful logins
for i in 1 2 3 4 5 6; do
  auth 10 "09:0$i:11" "Accepted publickey for alice from 192.0.2.10 port $((40000 + i)) ssh2"
done
for i in 1 2 3; do
  auth 10 "10:1$i:45" "Accepted password for bob from 198.51.100.20 port $((50000 + i)) ssh2"
done
# A user typed the wrong password twice, then success
auth 10 "11:30:01" "Failed password for alice from 192.0.2.11 port 41000 ssh2"
auth 10 "11:30:09" "Failed password for alice from 192.0.2.11 port 41001 ssh2"
auth 10 "11:30:20" "Accepted password for alice from 192.0.2.11 port 41002 ssh2"
# Brute force on root from 203.0.113.5 (47 tries)
for i in $(seq 1 47); do
  t=$(printf '02:%02d:%02d' $((i / 2)) $((i * 7 % 60)))
  auth 11 "$t" "Failed password for root from 203.0.113.5 port $((30000 + i)) ssh2"
done
# Username guessing from 203.0.113.9
for u in admin test oracle ubuntu postgres user guest ftp git pi; do
  auth 11 "05:10:$((10 + RANDOM % 50))" \
    "Failed password for invalid user $u from 203.0.113.9 port $((20000 + RANDOM % 9000)) ssh2"
  auth 11 "05:11:$((10 + RANDOM % 50))" \
    "Failed password for invalid user $u from 203.0.113.9 port $((20000 + RANDOM % 9000)) ssh2"
done
# Attacker fails many times and then gets in (needs a human check)
for i in $(seq 1 8); do
  auth 12 "01:2$i:10" "Failed password for bob from 203.0.113.66 port $((33000 + i)) ssh2"
done
auth 12 "01:30:44" "Accepted password for bob from 203.0.113.66 port 33100 ssh2"
# Noise that must be ignored
auth 12 "08:00:01" "pam_unix(sshd:session): session opened for user alice by (uid=0)"
auth 12 "08:05:09" "Connection closed by 192.0.2.10 port 40001 [preauth]"
echo "Created:"
wc -l "$ACCESS" "$AUTH"