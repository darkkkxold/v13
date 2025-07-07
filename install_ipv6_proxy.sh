#!/bin/bash

# ---- КОНФИГ ----
IPV6_SUPERNET="2a12:5940:e02e::"      # <- Впиши свою /48 подсеть БЕЗ /48!
SUPERNET_PREFIX=48
DAILY64_FILE="/root/proxyserver/daily64.txt"
PROXY_COUNT=300
START_PORT=30000
ROTATE_MINUTES=5
PROXY_TYPE="http"                    # или socks5
INTERFACE_NAME="$(ip -br l | awk '$1 !~ "lo|vir|wl|@NONE" { print $1 }' | awk 'NR==1')"
BACKCONNECT_IPV4="$(hostname -I | awk '{print $1}')"
USER="user"
PASS="pass"
USE_RANDOM_AUTH=true # true/false

mkdir -p /root/proxyserver

# ---- ФУНКЦИЯ: Случайная новая /64 из /48 ----
generate_daily_64() {
    RAND_HEX=$(printf "%x" $((RANDOM % 65536)))
    SUBNET_HEX=$(printf "%04x" "0x$RAND_HEX")
    DAILY64="${IPV6_SUPERNET%::}:${SUBNET_HEX}::/64"
    echo "$DAILY64" > "$DAILY64_FILE"
    echo "$DAILY64"
}

get_or_generate_daily_64() {
    if [ -f "$DAILY64_FILE" ]; then
        MOD_DAY=$(stat -c %Y "$DAILY64_FILE")
        NOW=$(date +%s)
        AGE=$(( (NOW - MOD_DAY) / 86400 ))
        if (( AGE >= 1 )); then
            generate_daily_64
        else
            cat "$DAILY64_FILE"
        fi
    else
        generate_daily_64
    fi
}

gen_random_ipv6_in_64() {
    local prefix64=$1
    local suffix=""
    for i in {1..4}; do
        suffix="${suffix}:$(printf "%x" $((RANDOM % 65536)))"
    done
    echo "${prefix64%%::*}${suffix}"
}

main() {
    CUR64=$(get_or_generate_daily_64)
    PREFIX64="${CUR64%/64}"
    echo "Используем подсеть: $CUR64"

    IP_LIST="/root/proxyserver/ipv6.list"
    if [ -f "$IP_LIST" ]; then
        for ip in $(cat "$IP_LIST"); do
            ip -6 addr del "$ip" dev "$INTERFACE_NAME"
        done
        rm "$IP_LIST"
    fi

    # Генерим новые ip6
    for ((i=0; i<$PROXY_COUNT; i++)); do
        newip=$(gen_random_ipv6_in_64 "$PREFIX64")
        echo "$newip" >> "$IP_LIST"
        ip -6 addr add "$newip" dev "$INTERFACE_NAME"
    done

    # --- ГЕНЕРАЦИЯ КОНФИГА 3proxy ---
    port=$START_PORT
    PROXY_TXT="/root/proxyserver/proxy.txt"
    PROXY_CFG="/root/proxyserver/3proxy.cfg"
    > $PROXY_TXT
    > $PROXY_CFG

    cat >> $PROXY_CFG <<EOF
daemon
maxconn 200
nserver 1.1.1.1
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
setgid 65535
setuid 65535
EOF

    # Генерация пользователей если USE_RANDOM_AUTH
    if [ "$USE_RANDOM_AUTH" = true ]; then
        > /root/proxyserver/users.list
        for ((i=0; i<$PROXY_COUNT; i++)); do
            RANDUSER=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
            RANDPASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
            echo "$RANDUSER:CL:$RANDPASS" >> /root/proxyserver/users.list
        done
        echo "auth strong" >> $PROXY_CFG
        echo "users $(paste -sd, /root/proxyserver/users.list)" >> $PROXY_CFG
    else
        echo "auth strong" >> $PROXY_CFG
        echo "users $USER:CL:$PASS" >> $PROXY_CFG
    fi
    echo "allow *" >> $PROXY_CFG

    # Прокси-лист + запись в конфиг 3proxy
    idx=0
    port=$START_PORT
    while read ip6; do
        if [ "$USE_RANDOM_AUTH" = true ]; then
            user=$(sed -n "$((idx+1))p" /root/proxyserver/users.list | cut -d: -f1)
            pass=$(sed -n "$((idx+1))p" /root/proxyserver/users.list | cut -d: -f3)
        else
            user=$USER
            pass=$PASS
        fi
        echo "$BACKCONNECT_IPV4:$port:$user:$pass:$ip6" >> $PROXY_TXT
        if [ "$PROXY_TYPE" = "http" ]; then
            echo "proxy -6 -n -a -p$port -i$BACKCONNECT_IPV4 -e$ip6" >> $PROXY_CFG
        else
            echo "socks -6 -a -p$port -i$BACKCONNECT_IPV4 -e$ip6" >> $PROXY_CFG
        fi
        ((port++))
        ((idx++))
    done < $IP_LIST

    # --- ЗАПУСК 3proxy ---
    pkill 3proxy
    sleep 1
    if [ ! -f "/root/proxyserver/3proxy/bin/3proxy" ]; then
        cd /root/proxyserver
        wget https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz
        tar -xf 0.9.4.tar.gz
        rm 0.9.4.tar.gz
        mv 3proxy-0.9.4 3proxy
        cd 3proxy
        make -f Makefile.Linux
    fi
    /root/proxyserver/3proxy/bin/3proxy $PROXY_CFG
}

setup_cron_daily() {
    (crontab -l 2>/dev/null; echo "0 0 * * * /bin/bash $0 daily") | sort -u | crontab -
}
setup_cron_minutely() {
    (crontab -l 2>/dev/null; echo "*/$ROTATE_MINUTES * * * * /bin/bash $0 rotate") | sort -u | crontab -
}

case "$1" in
    daily)
        main
        ;;
    rotate)
        main
        ;;
    install)
        setup_cron_daily
        setup_cron_minutely
        main
        ;;
    *)
        echo "Использование: $0 {install|daily|rotate}"
        ;;
esac

exit 0
