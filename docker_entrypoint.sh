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

    if ! stat /dev/net/tun >/dev/null 2>&1; then
        echo "ERROR: failed setting up the internal tun interface"
        echo "Run container with --device /dev/net/tun:/dev/net/tun"
        exit 1
    fi

    ip tuntap add mode tun multi_queue name "$TUN"
    ip link set dev "$TUN" up
    ip link set dev "$TUN" mtu 1250 # TODO: good change?
    ip addr add dev mp0 11.0.0.1/32 # needed for NAT to work!

    if [ "$(cat /proc/sys/net/ipv4/conf/${TUN}/rp_filter)" -ne 0 ]; then
        echo "ERROR: tun device has wrong rp_filter setting"
        echo "Run container with --sysctl=net.ipv4.conf.default.rp_filter=0"
    fi

    # Configure NAT
    #
    # packets coming from mp0 are supposed to be forwarded according to the
    # normal routing rules. To force the return traffic (e.g., SYN+ACK from a
    # new TCP connection) back to the proxy, we use NAT. To force the traffic
    # back through mp0, we use a connection mark and ip rules.
    #
    # Demo packet flow of the end-to-end connection sender-receiver, flowing
    # through quicheperf proxy.
    #
    # on sender (IP_SNDR):
    # IP out mp0  IP_SNDR:5000 -> IP_RCVR:6000: TCP SYN
    #
    # on quicheperf proxy (IP_PRXY):
    # IP in  mp0  IP_SNDR:5000 -> IP_RCVR:6000: TCP SYN
    # -- NAT applied here. IP_SNDR:5000 is rewritten to IP_PRXY:5000
    # -- connmark (fwmark) 2 is applied to this connection
    # -- the packet is routed to eth0 using the normal routing rules
    # IP out eth0 IP_PRXY:5000 -> IP_RCVR:6000: TCP SYN
    #
    # on receiver (IP_RCVR):
    # IP in  eth0 IP_PRXY:5000 -> IP_RCVR:6000: TCP SYN
    # IP out eth0 IP_RCVR:6000 -> IP_PRXY:5000: TCP SYN+ACK
    #
    # on quicheperf proxy (IP_PRXY):
    # IP in  eth0 IP_RCVR:6000 -> IP_PRXY:5000: TCP SYN+ACK
    # -- NAT reversed here. IP_PRXY:5000 is rewritten to IP_SNDR:5000
    # -- fwmark 2 is copied to this packet from the connection mark
    # -- the ip rule and routing table 100 direct to packt to mp0
    # IP out mp0  IP_RCVR:6000 -> IP_SNDR:5000: TCP SYN+ACK
    #
    # on sender (IP_SNDR):
    # IP in  mp0  IP_RCVR:6000 -> IP_SNDR:5000: TCP SYN+ACK

    if ! iptables -t nat -A POSTROUTING -o "$DEV" -j MASQUERADE; then
        echo "iptables failed"
        echo "run container with --cap-add=NET_ADMIN"
        exit 1
    fi

    # Correctly route return traffic through mp0
    iptables -t mangle -A PREROUTING -j CONNMARK -i eth0 -m connmark --mark 2 --restore-mark
    iptables -t mangle -A PREROUTING -j CONNMARK -i mp0 --set-mark 2

    ip rule add fwmark 2 lookup 100
    ip route add default dev mp0 table 100

    # Allow traffic to be forwarded (routed) between mp0 and eth0
    # This is not strictly necessary since the default policy is "ACCEPT" anyway
    iptables -A FORWARD -i mp0 -o eth0 -j ACCEPT
    iptables -A FORWARD -i eth0 -o mp0 -j ACCEPT
fi

exec quicheperf "$@"
