#!/bin/sh

# ==============================================================================
# - Original Source: https://github.com/hendrikcech/quicheperf/blob/17bc74ce3593492f568543e03c7cc9e229fca6c7/docker_entrypoint.sh
# - Modified By:     Yusuf Erdem Nacar
# - Changes:
#   - Adds the proxy-client role, which waits for the access interfaces to carry an IPv4 address, resolves interface name globs, and routes the configured prefixes into the TUN.
#   - Takes its settings from environment variables instead of docker run flags.
#   - Makes every step idempotent.
#   - Finds the egress interface from the default route instead of with jq.
#   - Sets net.ipv4.ip_forward instead of exiting when it is 0.
#   - Gives the TUN a /24 instead of 11.0.0.1/32.
#   - Drops the rp_filter check and the packet flow comment block.
#   - Passes --mp true and the scheduler from SCHEDULER_ARGS.
#   - Repeats -c once per interface on the proxy client.
#   - Passes --telemetry-listen and --path-log to the proxy server when TELEMETRY_LISTEN and PATH_LOG are set, and one --status per entry of PATH_STATUSES to the proxy client.
# ==============================================================================

set -eu

ROLE="${1:-proxy-server}"

TUN_NAME="${TUN_NAME:-mp0}"
TUN_MTU="${TUN_MTU:-1250}"
FLOW_HANDLER="${FLOW_HANDLER:-reordering}"
SCHEDULER_ARGS="${SCHEDULER_ARGS:-"--pscheduler roundrobin"}"
EXTRA_ARGS="${EXTRA_ARGS:-}"

log() {
    echo "[entrypoint] $*"
}

die() {
    echo "[entrypoint] ERROR: $*" >&2
    exit 1
}

write_sysctl() {
    _path="/proc/sys/$1"
    [ -w "$_path" ] || die "$_path is not writable, the container needs privileged: true"
    printf '%s\n' "$2" > "$_path"
}

# Helper locals carry an underscore prefix, since POSIX sh has no function scope.
ipt_ensure() {
    _table="$1"
    shift
    _chain="$1"
    shift
    iptables -t "$_table" -C "$_chain" "$@" 2>/dev/null || iptables -t "$_table" -A "$_chain" "$@"
}

setup_tun() {
    [ -c /dev/net/tun ] || die "/dev/net/tun is missing, mount it into the container"
    ip link show "$TUN_NAME" >/dev/null 2>&1 || ip tuntap add mode tun multi_queue name "$TUN_NAME"
    ip link set dev "$TUN_NAME" up mtu "$TUN_MTU"
    ip addr replace "$1" dev "$TUN_NAME"
    log "$TUN_NAME is up, mtu $TUN_MTU, address $1"
}

# The access interfaces appear only after attach and registration, so this waits for one matching the glob to carry an IPv4 address.
await_interface() {
    _pattern="$1"
    _elapsed=0
    while [ "$_elapsed" -lt "$2" ]; do
        for _ifname in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
            case "$_ifname" in
                $_pattern)
                    if ip -4 -o addr show dev "$_ifname" | grep -q inet; then
                        echo "$_ifname"
                        return 0
                    fi
                    ;;
            esac
        done
        sleep 2
        _elapsed=$((_elapsed + 2))
    done
    return 1
}

run_proxy_server() {
    listen_addr="${LISTEN_ADDR:-0.0.0.0:8000}"
    tun_addr="${TUN_ADDR:-11.0.0.1/24}"
    mark="${RETURN_MARK:-2}"
    table="${RETURN_TABLE:-100}"
    egress_if="${EGRESS_IF:-$(ip -o route show default | awk '{print $5; exit}')}"
    [ -n "$egress_if" ] || die "no default route, set EGRESS_IF"

    setup_tun "$tun_addr"
    write_sysctl net/ipv4/ip_forward 1

    ipt_ensure nat POSTROUTING -o "$egress_if" -j MASQUERADE
    ipt_ensure filter FORWARD -i "$TUN_NAME" -o "$egress_if" -j ACCEPT
    ipt_ensure filter FORWARD -i "$egress_if" -o "$TUN_NAME" -j ACCEPT

    # The reply to a tunnelled flow arrives on the egress interface addressed to this pod, with nothing in the packet tying it back to the TUN.
    # Connections entering on the TUN carry a connmark, the reply restores that connmark as an fwmark, and the fwmark rule routes the reply back into the TUN.
    ipt_ensure mangle PREROUTING -i "$TUN_NAME" -j CONNMARK --set-mark "$mark"
    ipt_ensure mangle PREROUTING -i "$egress_if" -m connmark --mark "$mark" -j CONNMARK --restore-mark

    ip rule show | grep -q "lookup $table" || ip rule add fwmark "$mark" lookup "$table"
    ip route replace default dev "$TUN_NAME" table "$table"

    telemetry_args=""
    if [ -n "${TELEMETRY_LISTEN:-}" ]; then
        telemetry_args="--telemetry-listen $TELEMETRY_LISTEN${TELEMETRY_LOG_EVERY:+ --telemetry-log-every $TELEMETRY_LOG_EVERY}"
        log "telemetry listener on $TELEMETRY_LISTEN"
    fi

    path_log_args=""
    if [ -n "${PATH_LOG:-}" ]; then
        path_log_args="--path-log $PATH_LOG${PATH_LOG_INTERVAL:+ --path-log-interval $PATH_LOG_INTERVAL}"
        log "path log to $PATH_LOG"
    fi

    log "proxy-server on $listen_addr, egress $egress_if, scheduler $SCHEDULER_ARGS"
    exec quicheperf -l "$listen_addr" --mp true $SCHEDULER_ARGS $EXTRA_ARGS $telemetry_args \
        proxy-server --tun "$TUN_NAME" --flow-handler "$FLOW_HANDLER" $path_log_args
}

run_proxy_client() {
    server_addr="${SERVER_ADDR:-}"
    [ -n "$server_addr" ] || die "SERVER_ADDR is required"
    tun_addr="${TUN_ADDR:-11.0.0.2/24}"
    interface_timeout="${INTERFACE_TIMEOUT:-300}"

    # quicheperf builds one path per local/peer pair and rejects a length mismatch, so the same server address is repeated once per interface.
    local_args=""
    peer_args=""
    for pattern in ${INTERFACES:-wwan0 gretun-id-*}; do
        interface=$(await_interface "$pattern" "$interface_timeout") || die "no interface matching '$pattern' carried an IPv4 address within ${interface_timeout}s"
        log "interface '$pattern' resolved to $interface"
        local_args="$local_args -l $interface"
        peer_args="$peer_args -c $server_addr"
    done

    setup_tun "$tun_addr"
    for prefix in ${STEER_PREFIXES:-}; do
        ip route replace "$prefix" dev "$TUN_NAME" src "${tun_addr%%/*}"
        log "steering $prefix into $TUN_NAME"
    done

    status_args=""
    for status in ${PATH_STATUSES:-}; do
        status_args="$status_args --status $status"
    done

    log "proxy-client to $server_addr over$local_args, scheduler $SCHEDULER_ARGS${status_args:+, path statuses$status_args}"
    exec quicheperf $local_args --bind true --mp true $SCHEDULER_ARGS $EXTRA_ARGS \
        proxy-client $peer_args --tun "$TUN_NAME" --flow-handler "$FLOW_HANDLER" $status_args
}

case "$ROLE" in
    proxy-server)
        run_proxy_server
        ;;
    proxy-client)
        run_proxy_client
        ;;
    *)
        die "unknown role '$ROLE', expected proxy-server or proxy-client"
        ;;
esac
