#!/usr/bin/env bash
#
# ssh-setup.sh - interactive SSH hardening + fail2ban for Ubuntu 24.04+ / Debian 12+
#
# Run as root:   sudo bash ssh-setup.sh          (see README.md for details)
# Help:          bash ssh-setup.sh --help
#
set -Eeuo pipefail

readonly SCRIPT_VERSION="1.0.0"

readonly CONF_DIR="/etc/ssh-setup"
readonly STATE_DIR="/var/lib/ssh-setup"
readonly LOG_FILE="/var/log/ssh-setup.log"
readonly WHITELIST_FILE="$CONF_DIR/whitelist.list"
readonly BLACKLIST_FILE="$CONF_DIR/blacklist.list"

readonly SSHD_DROPIN="/etc/ssh/sshd_config.d/00-ssh-setup.conf"
readonly SOCKET_DROPIN_DIR="/etc/systemd/system/ssh.socket.d"
readonly SOCKET_DROPIN="$SOCKET_DROPIN_DIR/ssh-setup.conf"
readonly BANNER_FILE="/etc/ssh/ssh-setup-banner"

readonly F2B_JAIL="/etc/fail2ban/jail.d/ssh-setup.local"
readonly F2B_WHITELIST="/etc/fail2ban/jail.d/ssh-setup-whitelist.local"
readonly F2B_DB_CONF="/etc/fail2ban/fail2ban.d/ssh-setup.local"
readonly F2B_FILTER="/etc/fail2ban/filter.d/ssh-setup-blacklist.conf"
readonly F2B_BLACKLIST_LOG="/var/log/ssh-setup-blacklist.log"
readonly F2B_BLACKLIST_JAIL="ssh-setup-blacklist"

readonly CONFIRM_TIMEOUT=180 # seconds the admin has to confirm the new login works

DRY_RUN=0
INPUT_SRC="${SSH_SETUP_INPUT:-/dev/tty}"
BACKUP_DIR=""
ANSWER=""

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
if [ -t 1 ]; then
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; BOLD=""; DIM=""; RESET=""
fi

log()     { { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG_FILE"; } 2>/dev/null || true; }
info()    { printf '%s\n' "$*"; }
ok()      { printf '%s[ok]%s %s\n' "$GREEN" "$RESET" "$*"; log "OK: $*"; }
warn()    { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; log "WARN: $*"; }
err()     { printf '%s[error]%s %s\n' "$RED" "$RESET" "$*" >&2; log "ERROR: $*"; }
die()     { err "$*"; exit 1; }
section() { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$RESET"; }
desc()    { printf '%s%s%s\n' "$DIM" "$*" "$RESET"; }

on_error() {
    err "Unexpected failure at line $1 (command: $2)."
    err "If SSH settings were already changed, run: sudo bash $0 --rollback"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

# --------------------------------------------------------------------------
# Input helpers (read from the terminal, so it also works via "curl | bash")
# --------------------------------------------------------------------------
open_input() {
    [ -r "$INPUT_SRC" ] || die "No terminal available for questions. Run the script from an interactive shell."
    exec 3<"$INPUT_SRC"
}

# ask "Prompt" ["default"]  -> sets ANSWER
ask() {
    local prompt=$1 def=${2-} line
    if [ -n "$def" ]; then
        printf '%s%s%s [%s]: ' "$BOLD" "$prompt" "$RESET" "$def"
    else
        printf '%s%s%s: ' "$BOLD" "$prompt" "$RESET"
    fi
    IFS= read -r -u 3 line || die "Input closed."
    ANSWER=${line:-$def}
}

# ask_yn "Question" y|n  -> returns 0 for yes, 1 for no
ask_yn() {
    local q=$1 def=${2:-y} hint
    if [ "$def" = y ]; then hint="Y/n"; else hint="y/N"; fi
    while true; do
        ask "$q ($hint)" ""
        case "${ANSWER,,}" in
            "") if [ "$def" = y ]; then return 0; else return 1; fi ;;
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) warn "Please answer y or n." ;;
        esac
    done
}

# ask_regex "Prompt" "default" 'regex' "error message" -> sets ANSWER
ask_regex() {
    local prompt=$1 def=$2 re=$3 msg=$4
    while true; do
        ask "$prompt" "$def"
        if [[ $ANSWER =~ $re ]]; then return 0; fi
        warn "$msg"
    done
}

# --------------------------------------------------------------------------
# Validators / small utilities
# --------------------------------------------------------------------------
valid_ip() {
    local v=$1 ip prefix o x
    ip=${v%%/*}
    if [[ $v == */* ]]; then prefix=${v#*/}; else prefix=""; fi
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS=. read -ra o <<<"$ip"
        for x in "${o[@]}"; do
            if (( 10#$x > 255 )); then return 1; fi
        done
        if [ -n "$prefix" ]; then
            [[ $prefix =~ ^[0-9]{1,2}$ ]] || return 1
            if (( 10#$prefix > 32 )); then return 1; fi
        fi
        return 0
    fi
    if [[ $ip == *:* && $ip =~ ^[0-9a-fA-F:]+$ ]]; then
        if [ -n "$prefix" ]; then
            [[ $prefix =~ ^[0-9]{1,3}$ ]] || return 1
            if (( 10#$prefix > 128 )); then return 1; fi
        fi
        return 0
    fi
    return 1
}

port_listening() { ss -H -ltn "sport = :$1" 2>/dev/null | grep -q .; }

wait_listening() {
    local port=$1
    for _ in $(seq 10); do
        if port_listening "$port"; then return 0; fi
        sleep 1
    done
    return 1
}

# Ports sshd is really listening on (works with socket activation too)
current_ssh_ports() {
    local ports
    ports=$(ss -H -ltnp 2>/dev/null | awk '/"sshd"/ {n=split($4, a, ":"); print a[n]}' | sort -un || true)
    if [ -z "$ports" ]; then
        ports=$(sshd -T 2>/dev/null | awk '$1=="port" {print $2}' | sort -un || true)
    fi
    printf '%s\n' "${ports:-22}"
}

server_ip() {
    if [ -n "${SSH_CONNECTION:-}" ]; then
        set -- $SSH_CONNECTION
        printf '%s' "${3:-}"
    else
        hostname -I 2>/dev/null | awk '{print $1}'
    fi
}

client_ip() {
    local ip=""
    if [ -n "${SSH_CONNECTION:-}" ]; then
        ip=${SSH_CONNECTION%% *}
    else
        ip=$(who -m 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p' || true)
    fi
    if valid_ip "$ip"; then printf '%s' "$ip"; fi
}

random_free_port() {
    local p
    while true; do
        p=$(shuf -i 20000-59999 -n 1)
        if ! port_listening "$p"; then printf '%s' "$p"; return 0; fi
    done
}

# filter_algs <ssh -Q query> <comma list>: keep only algorithms this OpenSSH knows
filter_algs() {
    local query=$1 list=$2 avail a out="" arr
    avail=$(ssh -Q "$query" 2>/dev/null || true)
    IFS=, read -ra arr <<<"$list"
    for a in "${arr[@]}"; do
        if grep -qxF -- "$a" <<<"$avail"; then out+="${out:+,}$a"; fi
    done
    printf '%s' "$out"
}

shred_file() { shred -u "$1" 2>/dev/null || rm -f "$1"; }

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
preflight() {
    section "Preflight checks"
    [ "$(id -u)" -eq 0 ] || die "Run as root (use: sudo bash $0)."
    (( BASH_VERSINFO[0] >= 4 )) || die "bash 4 or newer is required."
    command -v systemctl >/dev/null || die "systemd is required."
    mkdir -p "$CONF_DIR" "$STATE_DIR"
    chmod 700 "$CONF_DIR" "$STATE_DIR"

    local id ver pretty supported=0
    id=$(. /etc/os-release && printf '%s' "${ID:-unknown}")
    ver=$(. /etc/os-release && printf '%s' "${VERSION_ID:-0}")
    pretty=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}")
    case "$id" in
        ubuntu) if dpkg --compare-versions "$ver" ge 24.04; then supported=1; fi ;;
        debian) if dpkg --compare-versions "$ver" ge 12; then supported=1; fi ;;
    esac
    if [ "$supported" -eq 1 ]; then
        ok "OS: $pretty"
    else
        warn "Detected $pretty. This script targets Ubuntu 24.04+ and Debian 12+."
        ask_yn "Continue anyway?" n || exit 1
    fi

    if ! command -v sshd >/dev/null && [ ! -x /usr/sbin/sshd ]; then
        warn "OpenSSH server is not installed."
        ask_yn "Install openssh-server now?" y || die "openssh-server is required."
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server
    fi
    PATH="$PATH:/usr/sbin:/sbin"
    export PATH
    command -v sshd >/dev/null || die "sshd not found."
    command -v ss >/dev/null || die "'ss' (iproute2) not found."

    mapfile -t OLD_PORTS < <(current_ssh_ports)
    CLIENT_IP=$(client_ip || true)
    ok "SSH currently listens on port(s): ${OLD_PORTS[*]}"
    if [ -n "$CLIENT_IP" ]; then
        ok "Your current connection comes from: $CLIENT_IP"
    fi
}

# --------------------------------------------------------------------------
# Questions
# --------------------------------------------------------------------------
q_port() {
    section "1/8  SSH port"
    desc "SSH listens on port 22 by default and bots scan it all day long."
    desc "A different port does not replace real security (keys + fail2ban do that),"
    desc "but it removes most of the automatic noise from your logs."
    desc "Choose 1-65535. Press Enter to use the suggested random free port."
    local suggested p
    suggested=$(random_free_port)
    while true; do
        ask_regex "SSH port" "$suggested" '^[0-9]{1,5}$' "Enter a number from 1 to 65535."
        p=$((10#$ANSWER))
        if (( p < 1 || p > 65535 )); then warn "Port must be 1-65535."; continue; fi
        if printf '%s\n' "${OLD_PORTS[@]}" | grep -qx "$p"; then
            ok "Port $p is already used by SSH itself - fine."
            PORT=$p; return
        fi
        if port_listening "$p"; then
            err "Port $p is already in use by another program. Choose a different one."
            continue
        fi
        if (( p < 1024 && p != 22 )); then
            warn "Ports below 1024 are reserved for well-known services."
            ask_yn "Use $p anyway?" n || continue
        fi
        ok "Port $p is free."
        PORT=$p; return
    done
}

q_user_and_key() {
    section "2/8  Login user"
    desc "Which account will you use to log in over SSH?"
    desc "Default is root (key-only login, password login is always disabled)."
    desc "You can choose another account: it will be created if it does not exist,"
    desc "and root login over SSH will then be disabled."
    ask_regex "Login user" "root" '^[a-z_][a-z0-9_-]{0,31}$' "Use a valid Linux user name (lowercase letters, digits, _ and -)."
    LOGIN_USER=$ANSWER
    CREATE_USER=0
    GRANT_SUDO=0
    if getent passwd "$LOGIN_USER" >/dev/null; then
        HOME_DIR=$(getent passwd "$LOGIN_USER" | cut -d: -f6)
        ok "User '$LOGIN_USER' exists (home: $HOME_DIR)."
    else
        CREATE_USER=1
        HOME_DIR="/home/$LOGIN_USER"
        warn "User '$LOGIN_USER' does not exist and will be created (no password, key login only)."
        desc "A user without a password cannot use sudo unless sudo is allowed without a password."
        if ask_yn "Give '$LOGIN_USER' sudo rights without password (NOPASSWD)?" n; then GRANT_SUDO=1; fi
    fi

    section "3/8  SSH key"
    desc "Passwords are disabled, so you need an SSH key. Only modern ed25519 keys are accepted:"
    desc "they are short, fast and strong. Choose how to get one:"
    info "  1) Paste an existing PUBLIC key (from your own computer)"
    info "  2) Generate a new key pair here on the server"
    ask_regex "Choice" "1" '^[12]$' "Enter 1 or 2."
    KEY_MODE=$ANSWER
    PASTED_KEY=""
    KEY_KEEP="keep"
    KEY_PASSPHRASE=0
    KEY_PATH=""
    if [ "$KEY_MODE" = 1 ]; then
        desc "Paste one line, e.g.:  ssh-ed25519 AAAAC3Nza... comment"
        while true; do
            ask "Public key" ""
            if [ -z "$ANSWER" ]; then warn "The key cannot be empty."; continue; fi
            if ! ssh-keygen -l -f /dev/stdin <<<"$ANSWER" >/dev/null 2>&1; then
                warn "This is not a valid public key. Paste the .pub file content (one line)."
                continue
            fi
            case "${ANSWER%% *}" in
                ssh-ed25519|sk-ssh-ed25519@openssh.com) ;;
                *) warn "Only ed25519 keys are accepted (line must start with ssh-ed25519). Create one with: ssh-keygen -t ed25519"; continue ;;
            esac
            PASTED_KEY=$(awk '{print $1" "$2" "$3}' <<<"$ANSWER" | sed 's/ *$//')
            ok "Key accepted: $(ssh-keygen -l -f /dev/stdin <<<"$PASTED_KEY")"
            break
        done
    else
        local base="$HOME_DIR/.ssh/ssh-setup_ed25519"
        if [ -e "$base" ]; then base="${base}_$(date +%Y%m%d%H%M%S)"; fi
        KEY_PATH=$base
        desc "A key pair will be created at: $KEY_PATH (private) and $KEY_PATH.pub (public)."
        if ask_yn "Protect the private key with a passphrase? (asked by ssh-keygen)" n; then KEY_PASSPHRASE=1; fi
        desc "What to do with the PRIVATE key when everything works?"
        info "  1) Keep it on the server, just show me the path"
        info "  2) Show it on screen once, then delete it from the server (safer)"
        ask_regex "Choice" "2" '^[12]$' "Enter 1 or 2."
        if [ "$ANSWER" = 2 ]; then KEY_KEEP="show"; fi
    fi
}

q_access() {
    section "4/8  Who may log in"
    desc "AllowUsers makes SSH accept logins ONLY for the chosen user. Everyone else is refused,"
    desc "even if they somehow get a valid key. Recommended."
    ALLOW_ONLY=0
    if ask_yn "Allow SSH logins only for '$LOGIN_USER'?" y; then ALLOW_ONLY=1; fi
}

q_bruteforce() {
    section "5/8  Brute-force protection (SSH side)"
    desc "MaxAuthTries: how many login attempts one connection may make before it is dropped."
    ask_regex "MaxAuthTries" "3" '^[1-9][0-9]?$' "Enter a number from 1 to 99."
    MAX_TRIES=$ANSWER
    desc "LoginGraceTime: seconds a client has to finish logging in before the server closes the connection."
    ask_regex "LoginGraceTime (seconds)" "30" '^[1-9][0-9]{0,3}$' "Enter a number of seconds."
    GRACE=$ANSWER
    desc "MaxStartups 10:30:60 is set automatically: with 10+ unauthenticated connections the server starts"
    desc "dropping new ones at random (30%), and drops all of them at 60. This limits connection floods."
    desc "ClientAlive: every 5 minutes the server checks that the client is still there;"
    desc "after 2 missed checks the connection is closed. This cleans up dead/abandoned sessions."
    KEEPALIVE=0
    if ask_yn "Enable ClientAlive checks (300s x 2)?" y; then KEEPALIVE=1; fi
}

q_forwarding() {
    section "6/8  Forwarding and extras"
    desc "X11Forwarding lets remote graphical programs show windows on your PC. Servers rarely need it."
    X11=no
    if ask_yn "Allow X11 forwarding?" n; then X11=yes; fi
    desc "AllowTcpForwarding controls SSH tunnels (ssh -L / -R / -D, used for port forwarding and proxies)."
    desc "  no    = no tunnels at all (most secure)"
    desc "  local = only 'ssh -L' style tunnels from your PC to the server's network"
    desc "  yes   = everything allowed"
    ask_regex "AllowTcpForwarding (no/local/yes)" "no" '^(no|local|yes)$' "Type no, local or yes."
    TCP_FWD=$ANSWER
    desc "AllowAgentForwarding lets you use your local SSH keys from this server to hop further (ssh -A)."
    desc "It is convenient but risky if the server is compromised."
    AGENT_FWD=no
    if ask_yn "Allow agent forwarding?" n; then AGENT_FWD=yes; fi
    desc "Login banner: a text shown to everyone before login (legal notice, warning). Optional."
    BANNER_TEXT=""
    if ask_yn "Set a login banner?" n; then
        ask "Banner text (one line)" "Authorized access only. All activity may be logged."
        BANNER_TEXT=$ANSWER
    fi
    desc "LogLevel VERBOSE (set automatically) also logs the fingerprint of the key used for each login,"
    desc "so you can see WHO logged in when several keys are allowed."
}

q_firewall() {
    section "7/8  Firewall"
    FW=none
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
        FW=ufw
    elif systemctl is-active --quiet firewalld 2>/dev/null; then
        FW=firewalld
    elif { command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)'; } \
        || { command -v nft >/dev/null && nft list ruleset 2>/dev/null | grep -q 'policy drop'; }; then
        FW=other
    fi
    FW_AUTO=0
    case "$FW" in
        none)
            ok "No active host firewall detected." ;;
        ufw|firewalld)
            info "Detected active firewall: $FW."
            desc "If the new port is not opened, you will lock yourself out after the port change."
            if ask_yn "Open TCP port $PORT in $FW automatically?" y; then FW_AUTO=1; fi ;;
        other)
            warn "A firewall with a default DROP/REJECT policy (iptables/nftables) is active."
            desc "The script cannot safely edit custom rules. You must open the port yourself." ;;
    esac
}

q_fail2ban() {
    section "8/8  fail2ban"
    desc "fail2ban reads the SSH log and temporarily blocks (bans) IP addresses that fail to log in too often."
    F2B=0
    if ! ask_yn "Install and configure fail2ban for SSH?" y; then return; fi
    F2B=1
    desc "Time values accept s, m, h, d, w (e.g. 10m, 1h, 1w)."
    ask_regex "maxretry - failed attempts before a ban" "3" '^[1-9][0-9]{0,2}$' "Enter a number."
    F2B_MAXRETRY=$ANSWER
    ask_regex "findtime - window in which failures are counted" "10m" '^[1-9][0-9]*[smhdw]?$' "Example: 10m"
    F2B_FINDTIME=$ANSWER
    ask_regex "bantime - how long an IP stays banned" "1h" '^([1-9][0-9]*[smhdw]?|-1)$' "Example: 1h (or -1 for permanent)"
    F2B_BANTIME=$ANSWER
    desc "recidive: an IP that gets banned again and again is banned for a whole week."
    F2B_RECIDIVE=0
    if ask_yn "Enable recidive (repeat offenders, 1 week ban)?" y; then F2B_RECIDIVE=1; fi
    desc "Whitelisted IPs are never banned. Add your own IP so you cannot ban yourself."
    F2B_WL=()
    if [ -n "$CLIENT_IP" ] && ask_yn "Whitelist your current IP ($CLIENT_IP)?" y; then F2B_WL+=("$CLIENT_IP"); fi
    while true; do
        ask "More IPs/CIDRs to whitelist (space separated, Enter = none)" ""
        if [ -z "$ANSWER" ]; then break; fi
        local bad=0 ip
        for ip in $ANSWER; do
            if ! valid_ip "$ip"; then warn "Not a valid IP/CIDR: $ip"; bad=1; fi
        done
        if [ "$bad" -eq 0 ]; then
            # shellcheck disable=SC2206
            F2B_WL+=($ANSWER)
            break
        fi
    done
}

# --------------------------------------------------------------------------
# Config rendering
# --------------------------------------------------------------------------
# render_sshd_config <port> [<port>...]
render_sshd_config() {
    local p kex ciphers macs
    kex=$(filter_algs kex "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org")
    ciphers=$(filter_algs cipher "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com")
    macs=$(filter_algs mac "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com")

    printf '# Managed by ssh-setup.sh v%s - re-run the script instead of editing by hand.\n' "$SCRIPT_VERSION"
    printf '# Loaded first (00-) because sshd uses the FIRST value it sees for most options.\n\n'
    for p in "$@"; do printf 'Port %s\n' "$p"; done
    cat <<EOF

# Authentication: keys only
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
HostbasedAuthentication no
PermitUserEnvironment no
PermitRootLogin $ROOT_LOGIN

# Brute-force limits
MaxAuthTries $MAX_TRIES
LoginGraceTime $GRACE
MaxStartups 10:30:60
EOF
    if [ "$KEEPALIVE" -eq 1 ]; then
        printf 'ClientAliveInterval 300\nClientAliveCountMax 2\n'
    fi
    cat <<EOF

# Forwarding
X11Forwarding $X11
AllowTcpForwarding $TCP_FWD
AllowAgentForwarding $AGENT_FWD

# Logging
LogLevel VERBOSE
EOF
    if [ -n "$BANNER_TEXT" ]; then printf 'Banner %s\n' "$BANNER_FILE"; fi
    if [ "$ALLOW_ONLY" -eq 1 ]; then printf '\nAllowUsers %s\n' "$LOGIN_USER"; fi
    cat <<EOF

# Modern cryptography only (ed25519 keys)
HostKey /etc/ssh/ssh_host_ed25519_key
HostKeyAlgorithms ssh-ed25519
PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com
KexAlgorithms $kex
Ciphers $ciphers
MACs $macs
EOF
}

render_f2b_jail() {
    cat <<EOF
# Managed by ssh-setup.sh v$SCRIPT_VERSION
[sshd]
enabled = true
port = $PORT
filter = sshd[mode=aggressive]
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service
maxretry = $F2B_MAXRETRY
findtime = $F2B_FINDTIME
bantime = $F2B_BANTIME

[$F2B_BLACKLIST_JAIL]
enabled = true
filter = ssh-setup-blacklist
logpath = $F2B_BLACKLIST_LOG
backend = polling
maxretry = 1
findtime = 1d
bantime = -1
banaction = %(banaction_allports)s
EOF
    if [ "$F2B_RECIDIVE" -eq 1 ]; then
        cat <<EOF

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
backend = auto
maxretry = 3
findtime = 1d
bantime = 1w
EOF
    else
        printf '\n[recidive]\nenabled = false\n'
    fi
}

render_f2b_whitelist() {
    local ips="127.0.0.1/8 ::1"
    if [ -s "$WHITELIST_FILE" ]; then ips+=" $(tr '\n' ' ' <"$WHITELIST_FILE")"; fi
    printf '# Managed by ssh-setup.sh - edit with: ssh-setup.sh --f2b-whitelist-add/-del\n[DEFAULT]\nignoreip = %s\n' "$ips"
}

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
show_summary() {
    section "Summary - this is what will be configured"
    local old_txt="${OLD_PORTS[*]}"
    info "${BOLD}SSH${RESET}"
    if [ "$old_txt" = "$PORT" ]; then
        info "  Port:              $PORT (unchanged)"
    else
        info "  Port:              $old_txt -> $PORT (the old port stays open until you confirm the new one works)"
    fi
    info "  Login user:        $LOGIN_USER$([ "$CREATE_USER" -eq 1 ] && echo ' (will be created)')"
    if [ "$GRANT_SUDO" -eq 1 ]; then info "  sudo:              passwordless sudo for $LOGIN_USER"; fi
    info "  Root login:        $ROOT_LOGIN"
    info "  Authentication:    public key only (ed25519); passwords and keyboard-interactive are OFF"
    if [ "$KEY_MODE" = 1 ]; then
        info "  Key:               your pasted public key"
    else
        info "  Key:               new ed25519 pair at $KEY_PATH$([ "$KEY_PASSPHRASE" -eq 1 ] && echo ' (with passphrase)')"
        if [ "$KEY_KEEP" = show ]; then
            info "  Private key:       shown once on screen, then deleted from the server"
        else
            info "  Private key:       kept on the server"
        fi
    fi
    info "  Allowed users:     $([ "$ALLOW_ONLY" -eq 1 ] && echo "only $LOGIN_USER" || echo 'no restriction')"
    info "  Brute-force:       MaxAuthTries $MAX_TRIES, LoginGraceTime ${GRACE}s, MaxStartups 10:30:60"
    info "  Keep-alive check:  $([ "$KEEPALIVE" -eq 1 ] && echo 'every 300s, 2 misses = disconnect' || echo off)"
    info "  Forwarding:        X11 $X11, TCP $TCP_FWD, agent $AGENT_FWD"
    info "  Logging / banner:  LogLevel VERBOSE, banner $([ -n "$BANNER_TEXT" ] && echo on || echo off)"
    info "  Crypto:            ed25519 host key, modern KEX/ciphers/MACs only"
    info "${BOLD}Firewall${RESET}"
    case "$FW" in
        none) info "  No active firewall detected" ;;
        ufw|firewalld)
            if [ "$FW_AUTO" -eq 1 ]; then info "  $FW: port $PORT/tcp will be opened by the script"
            else info "  $FW: ${RED}you must open port $PORT/tcp yourself${RESET}"; fi ;;
        other) info "  ${RED}Custom firewall: you must open port $PORT/tcp yourself${RESET}" ;;
    esac
    info "${BOLD}fail2ban${RESET}"
    if [ "$F2B" -eq 1 ]; then
        info "  sshd jail:         ban after $F2B_MAXRETRY failures in $F2B_FINDTIME, ban for $F2B_BANTIME (aggressive mode)"
        info "  recidive:          $([ "$F2B_RECIDIVE" -eq 1 ] && echo 'on (1 week)' || echo off)"
        info "  Whitelist:         ${F2B_WL[*]:-none}"
    else
        info "  not installed / not configured"
    fi
}

# --------------------------------------------------------------------------
# Apply
# --------------------------------------------------------------------------
socket_mode() { systemctl is-enabled --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null; }

restart_sshd() {
    systemctl daemon-reload
    if socket_mode; then
        systemctl restart ssh.socket
        systemctl restart ssh.service
    else
        systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service
    fi
}

write_socket_dropin() {
    if ! socket_mode; then return 0; fi
    mkdir -p "$SOCKET_DROPIN_DIR"
    {
        printf '# Managed by ssh-setup.sh\n[Socket]\nListenStream=\n'
        local p
        for p in "$@"; do printf 'ListenStream=%s\n' "$p"; done
    } >"$SOCKET_DROPIN"
    log "Wrote socket drop-in for ports: $*"
}

neutralize_ports() {
    local f b
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f" ] || continue
        if [ "$f" = "$SSHD_DROPIN" ]; then continue; fi
        if grep -qE '^[[:space:]]*Port[[:space:]]+[0-9]' "$f"; then
            b="$BACKUP_DIR/neutralized/$(printf '%s' "$f" | tr / _)"
            mkdir -p "$BACKUP_DIR/neutralized"
            cp -a "$f" "$b"
            printf '%s\t%s\n' "$b" "$f" >>"$BACKUP_DIR/neutralized.list"
            sed -i -E 's/^([[:space:]]*Port[[:space:]]+[0-9])/# disabled by ssh-setup: \1/' "$f"
            warn "Commented out an active 'Port' line in $f (backup kept)."
        fi
    done
}

# Self-contained rollback script (also used by the systemd watchdog timer)
write_rollback_script() {
    local list="$BACKUP_DIR/neutralized.list"
    touch "$list"
    cat >"$STATE_DIR/rollback.sh" <<EOF
#!/usr/bin/env bash
# Generated by ssh-setup.sh - restores the SSH configuration from before the change.
set -u
rm -f "$SSHD_DROPIN" "$SOCKET_DROPIN"
while IFS=\$'\t' read -r b o; do
    if [ -n "\$b" ] && [ -f "\$b" ]; then cp -a "\$b" "\$o"; fi
done <"$list"
systemctl daemon-reload
if systemctl is-enabled --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null; then
    systemctl restart ssh.socket
fi
systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service
echo "\$(date '+%F %T') ssh-setup rollback executed" >>"$LOG_FILE"
echo "SSH configuration rolled back."
EOF
    chmod 700 "$STATE_DIR/rollback.sh"
}

fw_open() {
    case "$FW" in
        ufw)
            ufw allow "$PORT/tcp" comment 'SSH (ssh-setup)' >/dev/null
            ok "ufw: opened $PORT/tcp" ;;
        firewalld)
            firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null
            firewall-cmd --reload >/dev/null
            ok "firewalld: opened $PORT/tcp" ;;
    esac
}

ensure_user() {
    if [ "$CREATE_USER" -eq 1 ]; then
        adduser --disabled-password --gecos "" "$LOGIN_USER" >/dev/null
        ok "Created user $LOGIN_USER"
        if [ "$GRANT_SUDO" -eq 1 ]; then
            local sf="/etc/sudoers.d/90-ssh-setup-$LOGIN_USER"
            printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$LOGIN_USER" >"$sf"
            chmod 440 "$sf"
            visudo -cf "$sf" >/dev/null || { rm -f "$sf"; die "Invalid sudoers file, removed."; }
            ok "Granted passwordless sudo to $LOGIN_USER"
        fi
    fi
    HOME_DIR=$(getent passwd "$LOGIN_USER" | cut -d: -f6)
}

install_key() {
    local grp ssh_dir ak pub
    grp=$(id -gn "$LOGIN_USER")
    ssh_dir="$HOME_DIR/.ssh"
    ak="$ssh_dir/authorized_keys"
    install -d -m 700 -o "$LOGIN_USER" -g "$grp" "$ssh_dir"
    if [ -f "$ak" ]; then cp -a "$ak" "$BACKUP_DIR/authorized_keys.bak"; fi

    if [ "$KEY_MODE" = 2 ]; then
        local args=(-t ed25519 -a 100 -C "$LOGIN_USER@$(hostname)-$(date +%F)" -f "$KEY_PATH")
        if [ "$KEY_PASSPHRASE" -eq 0 ]; then args+=(-N ""); fi
        ssh-keygen "${args[@]}" -q
        chown "$LOGIN_USER:$grp" "$KEY_PATH" "$KEY_PATH.pub"
        chmod 600 "$KEY_PATH"; chmod 644 "$KEY_PATH.pub"
        pub=$(cat "$KEY_PATH.pub")
        ok "Generated key pair: $KEY_PATH"
    else
        pub=$PASTED_KEY
    fi

    touch "$ak"
    if ! grep -qF -- "$(awk '{print $2}' <<<"$pub")" "$ak"; then
        printf '%s\n' "$pub" >>"$ak"
    fi
    chown "$LOGIN_USER:$grp" "$ak"
    chmod 600 "$ak"
    # sshd (StrictModes) refuses keys if the home directory is writable by others
    chmod go-w "$HOME_DIR"
    ok "Public key installed in $ak"
}

verify_effective() {
    local out
    out=$(sshd -T -C "user=$LOGIN_USER,host=localhost,addr=127.0.0.1" 2>/dev/null) || return 1
    grep -qx 'passwordauthentication no' <<<"$out" || { err "sshd still allows password authentication (another config overrides ours)."; return 1; }
    grep -qx 'kbdinteractiveauthentication no' <<<"$out" || { err "sshd still allows keyboard-interactive authentication."; return 1; }
    return 0
}

do_rollback_now() {
    err "Rolling back SSH configuration..."
    "$STATE_DIR/rollback.sh" || true
}

apply_ssh() {
    section "Applying SSH configuration"
    BACKUP_DIR="$STATE_DIR/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    cp -a /etc/ssh "$BACKUP_DIR/etc-ssh"
    ln -sfn "$BACKUP_DIR" "$STATE_DIR/last-backup"
    ok "Backup of /etc/ssh saved in $BACKUP_DIR"
    log "Apply started: port=$PORT user=$LOGIN_USER"

    neutralize_ports
    if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
        ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
        ok "Generated missing ed25519 host key"
    fi
    if [ -n "$BANNER_TEXT" ]; then printf '%s\n' "$BANNER_TEXT" >"$BANNER_FILE"; fi

    ensure_user
    install_key
    write_rollback_script

    # Phase 1: listen on old AND new ports so nothing can lock you out.
    local phase1=("${OLD_PORTS[@]}")
    if ! printf '%s\n' "${OLD_PORTS[@]}" | grep -qx "$PORT"; then phase1+=("$PORT"); fi
    render_sshd_config "${phase1[@]}" >"$SSHD_DROPIN"
    chmod 644 "$SSHD_DROPIN"
    if ! sshd -t; then
        rm -f "$SSHD_DROPIN"
        die "sshd rejected the new configuration; nothing was changed."
    fi
    verify_effective || { do_rollback_now; die "Effective configuration is not what was requested."; }
    ok "Configuration is valid (sshd -t)"

    if [ "$FW_AUTO" -eq 1 ]; then fw_open; fi

    write_socket_dropin "${phase1[@]}"
    systemd-run --quiet --unit=ssh-setup-watchdog --on-active="${CONFIRM_TIMEOUT}s" "$STATE_DIR/rollback.sh" \
        || warn "Could not schedule the automatic rollback timer."
    restart_sshd
    if ! wait_listening "$PORT"; then
        do_rollback_now
        die "sshd is not listening on port $PORT; configuration rolled back."
    fi
    ok "sshd is listening on port $PORT"
}

confirm_new_login() {
    section "Test the new login - IMPORTANT"
    local host
    host=$(server_ip)
    local key_opt=""
    if [ "$KEY_MODE" = 2 ]; then key_opt=" -i <path-to-private-key>"; fi
    if [ "$KEY_MODE" = 2 ] && [ "$KEY_KEEP" = show ]; then
        info "Your new PRIVATE key (copy everything, including the BEGIN/END lines, to a file on your PC"
        info "and run: chmod 600 <file>):"
        printf '%s\n' "${YELLOW}----------------------------------------------------------------${RESET}"
        cat "$KEY_PATH"
        printf '%s\n' "${YELLOW}----------------------------------------------------------------${RESET}"
    elif [ "$KEY_MODE" = 2 ]; then
        info "Private key is on the server: $KEY_PATH  (download it, e.g. with scp)"
    fi
    info ""
    info "Open a ${BOLD}NEW${RESET} terminal (keep this one open!) and connect:"
    info "  ${GREEN}ssh -p $PORT$key_opt $LOGIN_USER@${host:-<server-ip>}${RESET}"
    info ""
    info "You have $CONFIRM_TIMEOUT seconds. Type ${BOLD}yes${RESET} when the new login works."
    info "Anything else (or no answer) rolls the SSH configuration back automatically."
    local line=""
    IFS= read -r -u 3 -t "$CONFIRM_TIMEOUT" line || line=""
    if [ "${line,,}" != "yes" ]; then
        do_rollback_now
        die "Not confirmed - SSH configuration was rolled back. Nothing else was changed."
    fi
    systemctl stop ssh-setup-watchdog.timer 2>/dev/null || true
    ok "Confirmed. Automatic rollback cancelled."
}

finalize_ports() {
    if printf '%s\n' "${OLD_PORTS[@]}" | grep -qvx "$PORT"; then
        section "Closing the old SSH port(s)"
        local prev
        prev=$(cat "$SSHD_DROPIN")
        render_sshd_config "$PORT" >"$SSHD_DROPIN"
        if ! sshd -t; then
            printf '%s\n' "$prev" >"$SSHD_DROPIN"
            die "Final configuration invalid; kept both ports."
        fi
        write_socket_dropin "$PORT"
        restart_sshd
        wait_listening "$PORT" || die "sshd is not listening on $PORT after the final restart! Run: sudo bash $0 --rollback"
        ok "sshd now listens only on port $PORT"
    fi
    if [ "$KEY_MODE" = 2 ] && [ "$KEY_KEEP" = show ]; then
        ask "Have you saved the private key? Press Enter to delete it from the server (type 'keep' to keep it)" ""
        if [ "${ANSWER,,}" = keep ]; then
            KEY_KEEP=keep
            warn "Private key kept at $KEY_PATH"
        else
            shred_file "$KEY_PATH"
            ok "Private key deleted from the server (public key stays in authorized_keys)"
        fi
    fi
}

# --------------------------------------------------------------------------
# fail2ban
# --------------------------------------------------------------------------
f2b_reload_and_sync() {
    fail2ban-client reload >/dev/null 2>&1 || systemctl restart fail2ban
    f2b_wait_ready
    if [ -s "$BLACKLIST_FILE" ]; then
        local ip
        while read -r ip; do
            if [ -n "$ip" ]; then fail2ban-client set "$F2B_BLACKLIST_JAIL" banip "$ip" >/dev/null 2>&1 || true; fi
        done <"$BLACKLIST_FILE"
    fi
}

f2b_wait_ready() {
    for _ in $(seq 10); do
        if fail2ban-client ping >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    return 1
}

setup_fail2ban() {
    section "Installing and configuring fail2ban"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban python3-systemd >/dev/null
    if ! command -v nft >/dev/null && ! command -v iptables >/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y nftables >/dev/null
    fi
    mkdir -p "$CONF_DIR"
    : >"$WHITELIST_FILE"
    local ip
    for ip in "${F2B_WL[@]}"; do
        if ! grep -qxF "$ip" "$WHITELIST_FILE"; then printf '%s\n' "$ip" >>"$WHITELIST_FILE"; fi
    done
    touch "$BLACKLIST_FILE" "$F2B_BLACKLIST_LOG"
    printf '[Definition]\ndbpurgeage = 3650d\n' >"$F2B_DB_CONF"
    cat >"$F2B_FILTER" <<'EOF'
# Used by ssh-setup.sh for manually blacklisted IPs (never matches real logs)
[Definition]
failregex = ^ssh-setup-blacklist <HOST>$
ignoreregex =
datepattern = {NONE}
EOF
    render_f2b_jail >"$F2B_JAIL"
    render_f2b_whitelist >"$F2B_WHITELIST"
    if ! fail2ban-client -t >/dev/null 2>&1; then
        warn "fail2ban rejected the configuration. Check: fail2ban-client -t"
        return 0
    fi
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    if f2b_wait_ready && fail2ban-client status sshd >/dev/null 2>&1; then
        ok "fail2ban is running, sshd jail active on port $PORT"
    else
        warn "fail2ban did not start correctly. Check: systemctl status fail2ban"
    fi
}

# --------------------------------------------------------------------------
# fail2ban CLI helpers (--f2b-*)
# --------------------------------------------------------------------------
require_f2b() {
    [ "$(id -u)" -eq 0 ] || die "Run as root (use: sudo bash $0 $*)."
    command -v fail2ban-client >/dev/null || die "fail2ban is not installed. Run the setup first."
    mkdir -p "$CONF_DIR"
    touch "$WHITELIST_FILE" "$BLACKLIST_FILE"
}

need_ip() {
    [ -n "${1:-}" ] || die "Missing IP address argument."
    valid_ip "$1" || die "Not a valid IP or CIDR: $1"
}

list_add() { if ! grep -qxF "$2" "$1"; then printf '%s\n' "$2" >>"$1"; fi; }
list_del() { local tmp; tmp=$(grep -vxF "$2" "$1" || true); printf '%s\n' "$tmp" | sed '/^$/d' >"$1"; }

cmd_f2b() {
    local action=$1 ip=${2:-}
    require_f2b "$action"
    case "$action" in
        status)
            fail2ban-client status
            local jail
            for jail in sshd recidive "$F2B_BLACKLIST_JAIL"; do
                if fail2ban-client status "$jail" >/dev/null 2>&1; then echo; fail2ban-client status "$jail"; fi
            done
            echo; echo "Whitelist ($WHITELIST_FILE):"; sed 's/^/  /' "$WHITELIST_FILE"
            echo "Blacklist ($BLACKLIST_FILE):"; sed 's/^/  /' "$BLACKLIST_FILE" ;;
        unban-all)
            fail2ban-client unban --all
            ok "All current bans were removed." ;;
        unban)
            need_ip "$ip"
            fail2ban-client unban "$ip"
            ok "Unbanned $ip" ;;
        whitelist-list) cat "$WHITELIST_FILE" ;;
        whitelist-add)
            need_ip "$ip"
            list_add "$WHITELIST_FILE" "$ip"
            render_f2b_whitelist >"$F2B_WHITELIST"
            f2b_reload_and_sync
            fail2ban-client unban "$ip" >/dev/null 2>&1 || true
            if grep -qxF "$ip" "$BLACKLIST_FILE"; then warn "$ip is also in the blacklist - remove it there if unintended."; fi
            ok "Whitelisted $ip (never banned by fail2ban)" ;;
        whitelist-del)
            need_ip "$ip"
            list_del "$WHITELIST_FILE" "$ip"
            render_f2b_whitelist >"$F2B_WHITELIST"
            f2b_reload_and_sync
            ok "Removed $ip from the whitelist" ;;
        blacklist-list) cat "$BLACKLIST_FILE" ;;
        blacklist-add)
            need_ip "$ip"
            fail2ban-client status "$F2B_BLACKLIST_JAIL" >/dev/null 2>&1 || die "Blacklist jail is not active. Run the setup with fail2ban enabled first."
            list_add "$BLACKLIST_FILE" "$ip"
            fail2ban-client set "$F2B_BLACKLIST_JAIL" banip "$ip" >/dev/null
            if grep -qxF "$ip" "$WHITELIST_FILE"; then warn "$ip is also whitelisted."; fi
            ok "Permanently banned $ip on all ports" ;;
        blacklist-del)
            need_ip "$ip"
            list_del "$BLACKLIST_FILE" "$ip"
            fail2ban-client set "$F2B_BLACKLIST_JAIL" unbanip "$ip" >/dev/null 2>&1 || true
            ok "Removed $ip from the blacklist" ;;
        sync)
            f2b_reload_and_sync
            ok "Blacklist re-applied, fail2ban reloaded." ;;
    esac
}

# --------------------------------------------------------------------------
# Final report
# --------------------------------------------------------------------------
final_report() {
    section "Done"
    ok "SSH is configured: port $PORT, key-only login for '$LOGIN_USER'."
    if [ "$F2B" -eq 1 ]; then ok "fail2ban is protecting SSH."; fi
    if [ "$KEY_MODE" = 2 ]; then
        info ""
        if [ "$KEY_KEEP" = keep ]; then
            info "${BOLD}Key files on this server:${RESET}"
            info "  private: $KEY_PATH"
            info "  public:  $KEY_PATH.pub"
            info "  Copy the private key to your PC and consider deleting it from the server."
        else
            info "${BOLD}Public key on this server:${RESET} $KEY_PATH.pub (private key was deleted)"
        fi
    fi
    if [ "$FW" != none ] && [ "$FW_AUTO" -eq 0 ]; then
        info ""
        info "${RED}FIREWALL: port $PORT/tcp was NOT opened by the script - open it yourself.${RESET}"
        case "$FW" in
            ufw) info "${RED}  ufw allow $PORT/tcp${RESET}" ;;
            firewalld) info "${RED}  firewall-cmd --permanent --add-port=$PORT/tcp && firewall-cmd --reload${RESET}" ;;
            other) info "${RED}  (use your own iptables/nftables rules)${RESET}" ;;
        esac
    fi
    if [ "$FW" = ufw ] || [ "$FW" = firewalld ]; then
        if ! printf '%s\n' "${OLD_PORTS[@]}" | grep -qx "$PORT"; then
            info ""
            warn "The old SSH port(s) ${OLD_PORTS[*]} may still be open in the firewall. Close them when you are ready:"
            if [ "$FW" = ufw ]; then info "  ufw delete allow ${OLD_PORTS[0]}/tcp   (or: ufw status numbered)"; fi
            if [ "$FW" = firewalld ]; then info "  firewall-cmd --permanent --remove-port=${OLD_PORTS[0]}/tcp && firewall-cmd --reload"; fi
        fi
    fi
    info ""
    warn "If your hosting provider has its own external firewall / security group, open TCP $PORT there too."
    info ""
    info "Useful commands:"
    info "  bash $0 --f2b-status | --f2b-unban-all | --f2b-whitelist-add IP | --f2b-blacklist-add IP"
    info "  bash $0 --rollback     (restore the previous SSH configuration)"
    info "Log file: $LOG_FILE"
}

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
usage() {
    cat <<EOF
ssh-setup.sh v$SCRIPT_VERSION - interactive SSH hardening + fail2ban (Ubuntu 24.04+, Debian 12+)

Usage: sudo bash ssh-setup.sh [option]

  (no option)              start the interactive setup
  --dry-run                ask the questions, show the summary and generated
                           config, change nothing
  --rollback               restore the SSH configuration from before the last run

fail2ban management (after the setup):
  --f2b-status             show jails, bans, whitelist and blacklist
  --f2b-unban-all          remove all current bans
  --f2b-unban IP           unban one IP
  --f2b-whitelist-add IP   never ban this IP/CIDR
  --f2b-whitelist-del IP   remove IP/CIDR from the whitelist
  --f2b-whitelist-list     show the whitelist
  --f2b-blacklist-add IP   ban this IP permanently on all ports
  --f2b-blacklist-del IP   remove IP from the blacklist
  --f2b-blacklist-list     show the blacklist
  --f2b-sync               reload fail2ban and re-apply the blacklist

  -h, --help               this help
  -v, --version            print version
EOF
}

do_setup() {
    open_input
    preflight
    q_port
    q_user_and_key
    if [ "$LOGIN_USER" = root ]; then ROOT_LOGIN="prohibit-password"; else ROOT_LOGIN="no"; fi
    q_access
    q_bruteforce
    q_forwarding
    q_firewall
    q_fail2ban

    show_summary
    if [ "$DRY_RUN" -eq 1 ]; then
        section "Generated sshd config (dry run - nothing was written)"
        render_sshd_config "$PORT"
        if [ "$F2B" -eq 1 ]; then
            section "Generated fail2ban jail (dry run)"
            render_f2b_jail
        fi
        exit 0
    fi
    echo
    ask_yn "Apply these settings now?" n || { info "Aborted. Nothing was changed."; exit 0; }

    apply_ssh
    confirm_new_login
    finalize_ports
    if [ "$F2B" -eq 1 ]; then setup_fail2ban; fi
    final_report
}

main() {
    case "${1:-}" in
        -h|--help) usage ;;
        -v|--version) echo "ssh-setup.sh $SCRIPT_VERSION" ;;
        --dry-run) DRY_RUN=1; do_setup ;;
        --rollback)
            [ "$(id -u)" -eq 0 ] || die "Run as root."
            [ -x "$STATE_DIR/rollback.sh" ] || die "Nothing to roll back (no previous run found)."
            "$STATE_DIR/rollback.sh" ;;
        --f2b-status) cmd_f2b status ;;
        --f2b-unban-all) cmd_f2b unban-all ;;
        --f2b-unban) cmd_f2b unban "${2:-}" ;;
        --f2b-whitelist-add) cmd_f2b whitelist-add "${2:-}" ;;
        --f2b-whitelist-del) cmd_f2b whitelist-del "${2:-}" ;;
        --f2b-whitelist-list) cmd_f2b whitelist-list ;;
        --f2b-blacklist-add) cmd_f2b blacklist-add "${2:-}" ;;
        --f2b-blacklist-del) cmd_f2b blacklist-del "${2:-}" ;;
        --f2b-blacklist-list) cmd_f2b blacklist-list ;;
        --f2b-sync) cmd_f2b sync ;;
        "") do_setup ;;
        *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
}

main "$@"
