#!/bin/bash

# ============== НАСТРОЙКИ ================
PROXY_DIR="$HOME/proxyserver"
MAIN_SUBNET_48="2a12:5940:e02e::"
CUR64_FILE="$PROXY_DIR/.current_64"
START_PORT=30000
PROXY_COUNT=400
PROXIES_TYPE="http"
ROTATING_INTERVAL=5
USER="ojrhgji3"
PASS="38u8r4hujr"
MODE_FLAG="-6"
INTERFACE_NAME="$(ip -br l | awk '$1 !~ "lo|vir|wl|@NONE" { print $1 }' | awk 'NR==1')"

mkdir -p "$PROXY_DIR"

# ============== Ротация /64 ================
gen64_from48() {
    HEX=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c4)
    echo "${MAIN_SUBNET_48}${HEX}::/64"
}

# Только для смены /64 по крону
if [[ "$1" == "--daily64" ]]; then
    subnet=$(gen64_from48)
    echo "$subnet" > "$CUR64_FILE"
    exit 0
fi

# Получить /64 (если нет, сгенерировать)
if [[ -f "$CUR64_FILE" ]]; then
    last_mod=$(stat -c %Y "$CUR64_FILE")
    now=$(date +%s)
    age=$(( (now - last_mod) / 3600 ))
    if (( $age < 24 )); then
        subnet=$(cat "$CUR64_FILE")
    else
        subnet=$(gen64_from48)
        echo "$subnet" > "$CUR64_FILE"
    fi
else
    subnet=$(gen64_from48)
    echo "$subnet" > "$CUR64_FILE"
fi

# Крон на ежедневную смену /64
CRON_MARK="#ipv6_rotate_subnet64"
MYCRON="0 0 * * * bash $0 --daily64 $CRON_MARK"
(crontab -l 2>/dev/null | grep -v "$CRON_MARK" ; echo "$MYCRON" ) | crontab -

# ============ УСТАНОВКА ЗАВИСИМОСТЕЙ ============
required_packages=("openssl" "zip" "curl" "jq")
for package in "${required_packages[@]}"; do
    if ! dpkg -l | grep -q "^ii  $package "; then
        echo "Устанавливаем $package..."
        apt-get update -qq
        apt-get install -y $package
    fi
done

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# ========== УБРАТЬ СТАРЫЕ IPv6 С ИНТЕРФЕЙСА ==========
RANDOM_IPV6_LIST_FILE="$PROXY_DIR/ipv6.list"
rm -f $RANDOM_IPV6_LIST_FILE
for addr in $(ip -6 addr show dev $INTERFACE_NAME | grep "inet6 " | awk '{print $2}' | grep ":$"); do
    ip -6 addr del ${addr} dev $INTERFACE_NAME 2>/dev/null
done

# ========== ГЕНЕРАЦИЯ IPv6 АДРЕСОВ ==========
prefix6=$(echo $subnet | cut -d'/' -f1 | awk -F: '{printf "%s:%s:%s:%s:%s:%s", $1, $2, $3, $4, $5, $6}')
for i in $(seq 1 $PROXY_COUNT); do
    hex1=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c4)
    hex2=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c4)
    ip6="$prefix6:$hex1:$hex2"
    echo $ip6 >> $RANDOM_IPV6_LIST_FILE
    ip -6 addr add $ip6 dev $INTERFACE_NAME 2>/dev/null
done

# ============= КОНФИГ 3PROXY ================
mkdir -p "$PROXY_DIR/3proxy"
PROXY_CFG="$PROXY_DIR/3proxy/3proxy.cfg"

cat > $PROXY_CFG <<EOF
daemon
nserver 1.1.1.1
maxconn 200
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
setgid 65535
setuid 65535
auth strong
users $USER:CL:$PASS
allow *
EOF

port=$START_PORT
if [ "$PROXIES_TYPE" = "http" ]; then
    proxy_startup_depending_on_type="proxy $MODE_FLAG -n -a"
else
    proxy_startup_depending_on_type="socks $MODE_FLAG -a"
fi

for ip6 in $(cat $RANDOM_IPV6_LIST_FILE); do
    echo "$proxy_startup_depending_on_type -p$port -i0.0.0.0 -e$ip6" >> $PROXY_CFG
    ((port++))
done

# ============= ЗАПУСК 3PROXY =================
if [ ! -f "$PROXY_DIR/3proxy/bin/3proxy" ]; then
    cd $PROXY_DIR
    wget https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz
    tar -xf 0.9.4.tar.gz
    mv 3proxy-0.9.4 3proxy
    cd 3proxy
    make -f Makefile.Linux
    cd ..
fi

if pgrep -x 3proxy > /dev/null; then
    pkill 3proxy
    sleep 1
fi

$PROXY_DIR/3proxy/bin/3proxy $PROXY_CFG

# ============ ПРОКСИ-ФАЙЛ ===============
PROXY_TXT="$PROXY_DIR/proxy.txt"
backconnect_ipv4=$(curl -s ipv4.icanhazip.com)
rm -f $PROXY_TXT
i=0
for ip6 in $(cat $RANDOM_IPV6_LIST_FILE); do
    p=$((START_PORT + i))
    echo "http://$USER:$PASS@$backconnect_ipv4:$p" >> $PROXY_TXT
    ((i++))
done

header="Наши контакты:\n===========================================================================\nНаш ТГ — https://t.me/nppr_team\nНаш ВК — https://vk.com/npprteam\nТГ нашего магазина — https://t.me/npprteamshop\nМагазин аккаунтов, бизнес-менеджеров ФБ и Google— https://npprteam.shop\nНаш антидетект-браузер Antik Browser — https://antik-browser.com/\n===========================================================================\n"
echo -e $header | cat - $PROXY_TXT > temp && mv temp $PROXY_TXT

# ============= АРХИВ И ЗАЛИВКА =============
archive_password=$(openssl rand -base64 12)
zip -P "$archive_password" $PROXY_DIR/proxy.zip $PROXY_TXT
upload_response=$(curl -F "file=@$PROXY_DIR/proxy.zip" https://file.io)
upload_url=$(echo $upload_response | jq -r '.link')
echo "Архивный пароль: $archive_password" > $PROXY_DIR/upload_info.txt
echo "Ссылка для скачивания: $upload_url" >> $PROXY_DIR/upload_info.txt

GREEN='\033[0;32m'
NC='\033[0m'
echo -e "${GREEN}##################################################${NC}"
echo -e "${GREEN}# Ваша ссылка на скачивание архива с прокси - ${upload_url}${NC}"
echo -e "${GREEN}# Пароль к архиву - ${archive_password}${NC}"
echo -e "${GREEN}# Файл с прокси можно найти по адресу - $PROXY_TXT${NC}"
echo -e "${GREEN}##################################################${NC}"

exit 0
