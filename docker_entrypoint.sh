#!/usr/bin/env sh
set -eu

if [ "${1:-}" = "proxy-server" ]; then
    # Name of the tun interface that will be created
    TUN=mp0

    # Get name of the container's network interface
    # (hopefully stable)
    DEV="$(ip -j addr | jq -r '.[] | select(.ifname != "lo") | .ifname')"

    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" -ne 1 ]; then
        echo "ERROR: sysctl net.ipv4.ip_forward=1 required"
        echo "Use docker run with --sysctl=net.ipv4.ip_forward=1"
        # echo 1 > "/proc/sys/net/ipv6/conf/${DEV}/forwarding"
        exit 1
    fi

    # TODO: setup tuntap
    if ! stat /dev/net/tun >/dev/null 2>&1; then
        echo "ERROR: failed setting up the internal tun interface"
        echo "Run container with --device /dev/net/tun:/dev/net/tun"
        exit 1
    fi

    ip tuntap add mode tun multi_queue name "$TUN"
    ip link set dev "$TUN" up

    if [ "$(cat /proc/sys/net/ipv4/conf/${TUN}/rp_filter)" -ne 0 ]; then
        echo "ERROR: tun device has wrong rp_filter setting"
        echo "Run container with --sysctl=net.ipv4.conf.default.rp_filter=0"
    fi

    # Configure NAT
    if ! iptables -t nat -A POSTROUTING -o "$DEV" -j MASQUERADE; then
        echo "iptables failed"
        echo "run container with --cap-add=NET_ADMIN"
        exit 1
    fi
fi

exec quicheperf "$@"
