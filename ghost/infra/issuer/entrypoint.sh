#!/usr/bin/env bash
# Entrypoint of the GHOST issuer image (Phase 8 design §6.7, §7.1; RUNBOOK.md). One role per
# container of docker-compose.stagenet.yml; the last three join the network namespace of the first:
#   tor         the issuer's v3 onion service (port 443 -> 127.0.0.1:7444) and the SOCKS port
#               monerod's peer-to-peer traffic goes through (127.0.0.1:9050)
#   monerod     the stagenet daemon: peers only through Tor, RPC on loopback with digest auth
#   wallet-rpc  the issuer's view-only wallet (--wallet-file), RPC on loopback with digest auth
#   issuer      ghost-issuer on loopback; GHOST_ISSUER_FLAGS may hold --restore (runbook B1) and
#               --restore-wallet (runbook R5), for one start only
# A role starts as root only to copy what it reads (Docker secrets under /run/secrets and read-only
# mounts, all kept on the issuer host outside the repository) into the tmpfs /run/ghost, readable by
# its own user alone, and to give that user its directories; the process then runs unprivileged
# (setpriv). monerod and monero-wallet-rpc take their RPC login from the RPC_LOGIN environment
# variable, not from their command line; monero-wallet-rpc takes the daemon's login from
# --daemon-login, which has no other form (visible only inside its own container). The Monero
# processes log at level 0 to the tmpfs /var/log/monero (design §6.5). This script prints fixed
# messages only, never a value it read.
set -euo pipefail

RUN_DIR=/run/ghost
MONERO_LOG=/var/log/monero
HS_DIR=/var/lib/tor/ghost-issuer
SEALED_DIR=/var/lib/ghost-issuer/sealed-keys

die() {
  echo "entrypoint: $*" >&2
  exit 64
}

# $1 must be a tmpfs mount point: nothing secret is copied to a disk.
require_tmpfs() {
  awk -v p="$1" '$2 == p && $3 == "tmpfs" { found = 1 } END { exit !found }' /proc/mounts \
    || die "$1 is not a tmpfs mount (docker-compose.stagenet.yml mounts one)"
}

# Makes the tmpfs /run/ghost private to user $1.
private_run_dir() {
  require_tmpfs "$RUN_DIR"
  chown "$1:$1" "$RUN_DIR"
  chmod 0700 "$RUN_DIR"
}

# Copies the file $1 to $RUN_DIR/$2, readable by user $3 only.
take() {
  { [ -f "$1" ] && [ -s "$1" ]; } || die "$1 is missing or empty"
  install -m 0400 -o "$3" -g "$3" "$1" "$RUN_DIR/$2"
}

# The user:password login of Docker secret $1, on standard output; anything else is refused.
login() {
  local value
  [ -s "/run/secrets/$1" ] || die "secret $1 is missing or empty"
  value="$(< "/run/secrets/$1")"
  [[ "$value" =~ ^[^:[:space:]]+:[^[:space:]]+$ ]] || die "secret $1 is not one user:password line"
  printf '%s' "$value"
}

# Gives user $1 the directories $2..., mode 0700.
own() {
  local user="$1" d
  shift
  for d in "$@"; do
    [ -d "$d" ] || die "$d is not mounted"
    chown -R "$user:$user" "$d"
    chmod 0700 "$d"
  done
}

# Replaces this shell with "$@" run as user $1.
run_as() {
  local user="$1"
  shift
  exec setpriv --reuid="$user" --regid="$user" --init-groups --no-new-privs -- "$@"
}

case "${1:-}" in
  tor)
    # The schedule names the issuer's onion: without its key set Tor would create another onion.
    [ -s "$HS_DIR/hs_ed25519_secret_key" ] \
      || die "$HS_DIR holds no onion service key set (RUNBOOK.md, Instalare)"
    # Tor writes hostname from the secret key it loads; a hostname that came with the key set could
    # name another onion. The install checks the file Tor wrote against the ES (RUNBOOK.md).
    rm -f "$HS_DIR/hostname"
    own debian-tor /var/lib/tor/state "$HS_DIR"
    chmod 0600 "$HS_DIR/hs_ed25519_secret_key"
    run_as debian-tor tor -f /etc/tor/torrc
    ;;
  monerod)
    RPC_LOGIN="$(login daemon_rpc_login)"
    export RPC_LOGIN
    require_tmpfs "$MONERO_LOG"
    own monero /var/lib/monerod "$MONERO_LOG"
    run_as monero monerod --stagenet --non-interactive --data-dir /var/lib/monerod --prune-blockchain \
      --proxy socks5://127.0.0.1:9050 --tx-proxy tor,socks5://127.0.0.1:9050,16 --pad-transactions \
      --p2p-bind-ip 127.0.0.1 --hide-my-port --no-igd \
      --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 --rpc-ssl disabled \
      --no-zmq --disable-dns-checkpoints --check-updates disabled \
      --log-level 0 --log-file "$MONERO_LOG/monerod.log" --max-log-files 1 --max-log-file-size 10485760 \
      > /dev/null 2>&1
    ;;
  wallet-rpc)
    RPC_LOGIN="$(login wallet_rpc_login)"
    export RPC_LOGIN
    daemon_login="$(login daemon_rpc_login)"
    [ -s /var/lib/monero-wallet/issuer-view.keys ] \
      || die "no view-only wallet in /var/lib/monero-wallet (RUNBOOK.md, Instalare and R5)"
    private_run_dir monero
    take /run/secrets/wallet_password wallet.password monero
    require_tmpfs "$MONERO_LOG"
    own monero /var/lib/monero-wallet "$MONERO_LOG"
    run_as monero monero-wallet-rpc --stagenet \
      --wallet-file /var/lib/monero-wallet/issuer-view --password-file "$RUN_DIR/wallet.password" \
      --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38083 --rpc-ssl disabled \
      --daemon-address 127.0.0.1:38081 --daemon-login "$daemon_login" --daemon-ssl disabled --trusted-daemon \
      --log-level 0 --log-file "$MONERO_LOG/wallet-rpc.log" --max-log-files 1 --max-log-file-size 10485760 \
      > /dev/null 2>&1
    ;;
  issuer)
    flags=()
    for flag in ${GHOST_ISSUER_FLAGS:-}; do
      case "$flag" in
        --restore | --restore-wallet) flags+=("$flag") ;;
        *) die "GHOST_ISSUER_FLAGS may hold --restore and --restore-wallet only" ;;
      esac
    done
    [ -s /etc/ghost/schedule.ghes ] || die "the Entitlement Schedule is not mounted"
    private_run_dir ghost-issuer
    take /etc/ghost-issuer/issuer.toml issuer.toml ghost-issuer
    take /run/secrets/wallet_rpc_login wallet-rpc.login ghost-issuer
    take /run/secrets/daemon_rpc_login daemon-rpc.login ghost-issuer
    take /run/secrets/ops_key ops.key ghost-issuer
    take /run/secrets/key_load key-load ghost-issuer
    # The sealed key files are encrypted; the copy keeps the host directory read-only.
    install -d -m 0700 -o ghost-issuer -g ghost-issuer "$RUN_DIR/sealed-keys"
    sealed=0
    for f in "$SEALED_DIR"/*.ghks; do
      [ -f "$f" ] || continue
      install -m 0400 -o ghost-issuer -g ghost-issuer "$f" "$RUN_DIR/sealed-keys/"
      sealed=$((sealed + 1))
    done
    [ "$sealed" -gt 0 ] || die "no sealed key file in $SEALED_DIR"
    chmod 0500 "$RUN_DIR/sealed-keys"
    own ghost-issuer /var/lib/ghost-issuer/data /var/lib/ghost-issuer/export
    run_as ghost-issuer ghost-issuer --config "$RUN_DIR/issuer.toml" "${flags[@]}"
    ;;
  *)
    echo "usage: entrypoint.sh tor | monerod | wallet-rpc | issuer" >&2
    exit 2
    ;;
esac
