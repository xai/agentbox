#!/bin/sh
set -eu

CONFIG_FILE="${FIREWALL_CONFIG:-/etc/agentbox/firewall.conf}"
DNSMASQ_CONF="/etc/dnsmasq.d/agentbox.conf"
IPSET_NAME="agentbox_allowed"

log() {
    echo "[agentbox-firewall] $*"
}

if [ ! -f "$CONFIG_FILE" ]; then
    log "Missing firewall config: $CONFIG_FILE"
    exit 1
fi

resolvers=""
if [ -n "${FIREWALL_DNS:-}" ]; then
    for resolver in $(echo "$FIREWALL_DNS" | tr ',' ' '); do
        case "$resolver" in
            ""|127.0.0.1|127.0.0.11|::1)
                continue
                ;;
            *:*)
                continue
                ;;
        esac
        resolvers="$resolvers $resolver"
    done
else
    while IFS= read -r line; do
        case "$line" in
            nameserver\ *)
                resolver="${line#nameserver }"
                resolver="${resolver%% *}"
                case "$resolver" in
                    ""|127.0.0.1|127.0.0.11|::1)
                        continue
                        ;;
                    *:*)
                        continue
                        ;;
                esac
                resolvers="$resolvers $resolver"
                ;;
        esac
    done < /etc/resolv.conf
fi

if [ -z "$resolvers" ]; then
    resolvers="1.1.1.1 8.8.8.8"
fi

if ! printf "nameserver 127.0.0.1\n" > /etc/resolv.conf 2>/dev/null; then
    log "Unable to update /etc/resolv.conf; DNS enforcement may be incomplete"
fi

mkdir -p /etc/dnsmasq.d
{
    echo "no-resolv"
    echo "domain-needed"
    echo "bogus-priv"
    echo "address=/#/0.0.0.0"
} > "$DNSMASQ_CONF"

while IFS= read -r raw_line; do
    line=$(echo "$raw_line" | sed 's/#.*//')
    line=$(echo "$line" | xargs)
    [ -z "$line" ] && continue
    domain=$(echo "$line" | awk '{print $1}')

    for resolver in $resolvers; do
        echo "server=/${domain}/${resolver}" >> "$DNSMASQ_CONF"
    done
    echo "ipset=/${domain}/${IPSET_NAME}" >> "$DNSMASQ_CONF"
done < "$CONFIG_FILE"

ipset create "$IPSET_NAME" hash:net -exist
ipset flush "$IPSET_NAME"

iptables -F OUTPUT || true
iptables -F INPUT || true
iptables -P INPUT ACCEPT
iptables -P OUTPUT DROP

iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.1 -j ACCEPT

dns_uid=$(id -u dnsmasq)
owner_supported=true
if ! iptables -m owner -h >/dev/null 2>&1; then
    owner_supported=false
    log "Owner match unavailable; DNS egress will be less restricted"
fi

for resolver in $resolvers; do
    if [ "$owner_supported" = "true" ]; then
        iptables -A OUTPUT -p udp --dport 53 -d "$resolver" -m owner --uid-owner "$dns_uid" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -d "$resolver" -m owner --uid-owner "$dns_uid" -j ACCEPT
    else
        iptables -A OUTPUT -p udp --dport 53 -d "$resolver" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -d "$resolver" -j ACCEPT
    fi
done

iptables -A OUTPUT -m set --match-set "$IPSET_NAME" dst -j ACCEPT

if command -v sysctl >/dev/null 2>&1; then
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
fi
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F OUTPUT || true
    ip6tables -F INPUT || true
    ip6tables -P INPUT ACCEPT
    ip6tables -P OUTPUT DROP
    ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -A INPUT -i lo -j ACCEPT
fi

log "Firewall gateway ready"
exec su-exec dnsmasq:dnsmasq dnsmasq --no-daemon --conf-file="$DNSMASQ_CONF"
