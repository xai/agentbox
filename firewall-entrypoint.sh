#!/bin/sh
set -eu

CONFIG_FILE="${AGENTBOX_FIREWALL_CONFIG:-/etc/agentbox/firewall.conf}"
DNSMASQ_CONF="/etc/dnsmasq.d/agentbox.conf"
IPSET_NAME="agentbox_allowed"
SNIPROXY_CONF="/etc/sniproxy.conf"
PROXY_MODE="${AGENTBOX_FIREWALL_PROXY:-}"
PROXY_PORT="${AGENTBOX_FIREWALL_PROXY_PORT:-443}"
HTTP_PROXY_PORT=80
proxy_enabled=false

log() {
    echo "[agentbox-firewall] $*"
}

if [ ! -f "$CONFIG_FILE" ]; then
    log "Missing firewall config: $CONFIG_FILE"
    exit 1
fi

resolvers=""
if [ -n "${AGENTBOX_FIREWALL_DNS:-}" ]; then
    for resolver in $(echo "$AGENTBOX_FIREWALL_DNS" | tr ',' ' '); do
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

case "$PROXY_MODE" in
    1|true|enabled|transparent)
        proxy_enabled=true
        ;;
esac

if [ "$proxy_enabled" = "true" ]; then
    if [ "$PROXY_PORT" != "443" ]; then
        log "AGENTBOX_FIREWALL_PROXY_PORT=$PROXY_PORT is unsupported for HTTPS proxying; forcing to 443"
        PROXY_PORT="443"
    fi
    if ! id -u sniproxy >/dev/null 2>&1; then
        adduser -S -D -H -s /sbin/nologin sniproxy
    fi
    {
        echo "user sniproxy"
        echo "pidfile /var/run/sniproxy.pid"
        echo "resolver {"
        echo "    nameserver 127.0.0.1"
        echo "    mode ipv4"
        echo "}"
        echo "listener 0.0.0.0 ${PROXY_PORT} {"
        echo "    proto tls"
        echo "}"
        echo "listener 0.0.0.0 ${HTTP_PROXY_PORT} {"
        echo "    proto http"
        echo "}"
        echo "table {"
    } > "$SNIPROXY_CONF"
fi

while IFS= read -r raw_line; do
    line=$(echo "$raw_line" | sed 's/#.*//')
    line=$(echo "$line" | xargs)
    [ -z "$line" ] && continue
    domain=$(echo "$line" | awk '{print $1}')
    base_domain="$domain"
    case "$base_domain" in
        \*.*)
            base_domain="${base_domain#*.}"
            ;;
    esac
    escaped_domain=$(printf "%s" "$base_domain" | sed 's/[.[\\^$*+?(){|]/\\&/g')

    for resolver in $resolvers; do
        echo "server=/${domain}/${resolver}" >> "$DNSMASQ_CONF"
    done
    echo "ipset=/${domain}/${IPSET_NAME}" >> "$DNSMASQ_CONF"

    if [ "$proxy_enabled" = "true" ]; then
        echo "    ^${escaped_domain}$ *" >> "$SNIPROXY_CONF"
        echo "    ^.*\\.${escaped_domain}$ *" >> "$SNIPROXY_CONF"
    fi
done < "$CONFIG_FILE"

if [ "$proxy_enabled" = "true" ]; then
    echo "}" >> "$SNIPROXY_CONF"
fi

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

if [ "$proxy_enabled" = "true" ]; then
    proxy_uid=$(id -u sniproxy)
    iptables -A OUTPUT -p tcp --dport "$PROXY_PORT" -m addrtype --dst-type LOCAL -j ACCEPT
    iptables -A OUTPUT -p tcp --dport "$HTTP_PROXY_PORT" -m addrtype --dst-type LOCAL -j ACCEPT
    iptables -t nat -F OUTPUT || true
    iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner "$proxy_uid" -j RETURN
    iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner "$proxy_uid" -j RETURN
    iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT
    iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$PROXY_PORT"
    log "Transparent TLS/HTTP proxy enabled on ports ${PROXY_PORT}/${HTTP_PROXY_PORT}"
    su-exec sniproxy:sniproxy sniproxy -f "$SNIPROXY_CONF" -n &
fi

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
