#!/bin/bash

GREEN='\033[0;32m'
NC='\033[0m'

LOGFILE="/var/tmp/ipv6-proxy-server-install.log"

# Пути и глобальные переменные
cd ~
user_home_dir="$(pwd)"
proxy_dir="$user_home_dir/proxyserver"
if [ ! -d $proxy_dir ]; then mkdir -p $proxy_dir; fi

proxyserver_config_path="$proxy_dir/3proxy/3proxy.cfg"
random_ipv6_list_file="$proxy_dir/ipv6.list"
random_users_list_file="$proxy_dir/random_users.list"
startup_script_path="$proxy_dir/proxy-startup.sh"
cron_script_path="$proxy_dir/proxy-server.cron"
backconnect_proxies_file="$proxy_dir/backconnect_proxies.list"
interface_name="$(ip -br l | awk '$1 !~ "lo|vir|wl|@NONE" { print $1 }' | awk 'NR==1')"
start_port=30000
ipv6_random64_file="$proxy_dir/active_64_subnet.txt"
conf_file="$proxy_dir/proxyserver.conf"

# ============ Функции работы с настройками =============
save_settings() {
cat > "$conf_file" << EOF
ipv6_main_subnet="$ipv6_main_subnet"
user="$user"
password="$password"
use_random_auth="$use_random_auth"
proxies_type="$proxies_type"
rotating_interval="$rotating_interval"
proxy_count="$proxy_count"
mode_flag="$mode_flag"
EOF
}

load_settings() {
    if [ -f "$conf_file" ]; then
        source "$conf_file"
        return 0
    else
        return 1
    fi
}

# ============= Ввод настроек только при первом запуске ==========
get_user_input() {
    echo "Введите вашу /48 IPv6 подсеть (пример: 2a01:4f8:10a:2f4::):"
    read ipv6_main_subnet
    ipv6_main_subnet="${ipv6_main_subnet%%::*}"

    echo "Логин и пароль:"
    echo "1) Указать"
    echo "2) Без логина и пароля"
    echo "3) Рандомные"
    read auth_choice
    case $auth_choice in
        1)
            echo "Введите логин:"
            read user
            echo "Введите пароль:"
            read password
            use_random_auth=false
            ;;
        2)
            user=""
            password=""
            use_random_auth=false
            ;;
        3)
            user=""
            password=""
            use_random_auth=true
            ;;
        *)
            use_random_auth=true
            ;;
    esac

    echo "Тип прокси (по умолчанию socks5):"
    echo "1) Socks5"
    echo "2) Http"
    read proxies_choice

    if [[ "$proxies_choice" == "1" || -z "$proxies_choice" ]]; then
        proxies_type="socks5"
    elif [[ "$proxies_choice" == "2" ]]; then
        proxies_type="http"
    else
        proxies_type="socks5"
    fi

    echo "Интервал ротации (в минутах, 0 для отключения, по умолчанию 0):"
    read rotating_interval
    if [[ -z "$rotating_interval" ]]; then rotating_interval=0; fi

    echo "Количество прокси:"
    read proxy_count
    if [[ -z "$proxy_count" ]]; then proxy_count=100; fi

    echo "Режим работы:"
    echo "1) Универсальные (ipv4/ipv6)"
    echo "2) Только ipv6"
    read mode_choice
    case $mode_choice in
        1)
            mode_flag="-64"
            ;;
        2)
            mode_flag="-6"
            ;;
        *)
            mode_flag="-64"
            ;;
    esac
}

# =================== Функции генерации IPv6 =====================

gen_random_64_from_48() {
    base="${ipv6_main_subnet%::*}"
    HEX=$(head -c2 /dev/urandom | od -A n -t x2 | tr -d ' \n')
    echo "${base}:$HEX:0:0:0:0:0:0/64"
}

set_new_active_64() {
    new64=$(gen_random_64_from_48)
    echo "$new64" > $ipv6_random64_file
}

get_active_64() {
    if [ -f "$ipv6_random64_file" ]; then
        cat "$ipv6_random64_file"
    else
        set_new_active_64
        cat "$ipv6_random64_file"
    fi
}

clean_old_64_addresses() {
    if [ -f $random_ipv6_list_file ]; then
        for ipv6_address in $(cat $random_ipv6_list_file); do
            ip -6 addr del $ipv6_address dev $interface_name 2>/dev/null
        done
        rm $random_ipv6_list_file
    fi
}

get_subnet_mask() {
    active_64=$(get_active_64)
    echo "$active_64" | cut -d/ -f1
}

# =================== Прочие рабочие функции ======================

create_random_string() {
  tr -dc A-Za-z0-9 </dev/urandom | head -c $1; echo ''
}

generate_random_users_if_needed() {
  if [ "$use_random_auth" != "true" ]; then return; fi
  rm -f $random_users_list_file
  for i in $(seq 1 $proxy_count); do
    echo $(create_random_string 8):$(create_random_string 8) >> $random_users_list_file
  done
}

create_startup_script() {
  rm -f $startup_script_path

  cat > $startup_script_path <<-EOF
  #!$(which bash)
  proxyserver_process_pids=()
  while read -r pid; do proxyserver_process_pids+=\$pid; done < <(ps -ef | awk '/[3]proxy/{print \$2}')

  old_ipv6_list_file="$random_ipv6_list_file.old"
  if test -f $random_ipv6_list_file; then cp $random_ipv6_list_file \$old_ipv6_list_file; rm $random_ipv6_list_file; fi

  array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
  function rh () { echo \${array[\$RANDOM%16]}; }

  function get_subnet_mask() {
      cat "$ipv6_random64_file" | cut -d/ -f1
  }
  rnd_subnet_ip () {
    echo -n \$(get_subnet_mask)
    symbol=64
    while (( \$symbol < 128)); do
      if ((\$symbol % 16 == 0)); then echo -n :; fi
      echo -n \$(rh)
      let "symbol += 4"
    done
    echo
  }
  count=1
  while [ "\$count" -le $proxy_count ]
  do
    rnd_subnet_ip >> $random_ipv6_list_file
    ((count+=1))
  done
  immutable_config_part="daemon
    nserver 1.1.1.1
    maxconn 200
    nscache 65536
    timeouts 1 5 30 60 180 1800 15 60
    setgid 65535
    setuid 65535"
  auth_part="auth iponly"
  if [ "$use_random_auth" != "false" ] && [ -n "$user" ]; then
    auth_part="
      auth strong
      users $user:CL:$password"
  fi
  echo "\$immutable_config_part"\$'\n'"\$auth_part" > $proxyserver_config_path
  port=$start_port
  count=0
  if [ "$proxies_type" = "http" ]; then proxy_startup_depending_on_type="proxy $mode_flag -n -a"; else proxy_startup_depending_on_type="socks $mode_flag -a"; fi
  if [ "$use_random_auth" = "true" ]; then readarray -t proxy_random_credentials < $random_users_list_file; fi
  for random_ipv6_address in \$(cat $random_ipv6_list_file); do
      if [ "$use_random_auth" = "true" ]; then
        IFS=":"
        read -r username password <<< "\${proxy_random_credentials[\$count]}"
        echo "flush" >> $proxyserver_config_path
        echo "users \$username:CL:\$password" >> $proxyserver_config_path
        IFS=\$' \t\n'
      fi
      echo "\$proxy_startup_depending_on_type -p\$port -i$backconnect_ipv4 -e\$random_ipv6_address" >> $proxyserver_config_path
      ((port+=1))
      ((count+=1))
  done
  ulimit -n 600000
  ulimit -u 600000
  for ipv6_address in \$(cat ${random_ipv6_list_file}); do ip -6 addr add \$ipv6_address dev $interface_name; done
  ${user_home_dir}/proxyserver/3proxy/bin/3proxy ${proxyserver_config_path}
  for pid in "\${proxyserver_process_pids[@]}"; do kill \$pid; done
  if test -f \$old_ipv6_list_file; then
    for ipv6_address in \$(cat \$old_ipv6_list_file); do ip -6 addr del \$ipv6_address dev $interface_name; done
    rm \$old_ipv6_list_file
  fi
  exit 0
EOF
}

run_proxy_server() {
  chmod +x $startup_script_path
  $startup_script_path
}

write_backconnect_proxies_to_file() {
  rm -f $backconnect_proxies_file
  if [ "$use_random_auth" = "true" ]; then
    local proxy_random_credentials
    local count=0
    readarray -t proxy_random_credentials < $random_users_list_file
  fi
  last_port=$(($start_port + $proxy_count - 1))
  for port in $(eval echo "{$start_port..$last_port}"); do
    if [ "$use_random_auth" = "true" ]; then
      proxy_credentials=":${proxy_random_credentials[$count]}"
      ((count+=1))
    else
      if [ -n "$user" ] && [ -n "$password" ]; then
        proxy_credentials=":$user:$password"
      else
        proxy_credentials=""
      fi
    fi
    echo "$backconnect_ipv4:$port$proxy_credentials" >> $backconnect_proxies_file
  done
}

get_backconnect_ipv4() {
  local maybe_ipv4=$(ip addr show $interface_name | awk '$1 == "inet" {gsub(/\/.*$/, "", $2); print $2}')
  if [[ "$maybe_ipv4" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then echo $maybe_ipv4; return; fi
  (maybe_ipv4=$(curl https://ipinfo.io/ip)) &> /dev/null
  if [[ "$maybe_ipv4" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then echo $maybe_ipv4; return; fi
  echo "Error: can't get IPv4"; exit 1
}

# ================== Системная подготовка =========================
required_packages=("openssl" "zip" "curl" "jq")
for package in "${required_packages[@]}"; do
    if ! dpkg -l | grep -q "^ii  $package "; then
        apt-get update -qq
        apt-get install -y $package
    fi
done

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Первый запуск: если нет конфига, спросить всё и сохранить
if ! load_settings; then
    get_user_input
    save_settings
fi

# Теперь весь вывод в лог
exec > $LOGFILE 2>&1

echo "* hard nofile 999999" >> /etc/security/limits.conf
echo "* soft nofile 999999" >> /etc/security/limits.conf
echo "net.ipv4.route.min_adv_mss = 1460" >> /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.conf
echo "net.ipv4.tcp_window_scaling=0" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv4.ip_nonlocal_bind = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.proxy_ndp=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv6.ip_nonlocal_bind = 1" >> /etc/sysctl.conf
sysctl -p
systemctl stop firewalld
systemctl disable firewalld
echo "net.ipv4.ip_default_ttl=128" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syn_retries=2" >> /etc/sysctl.conf
echo "net.ipv4.tcp_fin_timeout=30" >> /etc/sysctl.conf
echo "net.ipv4.tcp_keepalive_time=7200" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem=4096 87380 6291456" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem=4096 16384 6291456" >> /etc/sysctl.conf
sysctl -p

if [ ! -d "$proxy_dir/3proxy" ]; then
    cd $proxy_dir
    wget https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz &> /dev/null
    tar -xf 0.9.4.tar.gz
    rm 0.9.4.tar.gz
    mv 3proxy-0.9.4 3proxy
    cd 3proxy
    make -f Makefile.Linux &> /dev/null
    cd ..
fi

backconnect_ipv4=$(get_backconnect_ipv4)

# ==================== Основная логика запуска ======================
# Если скрипт запущен с --daily64: только смена /64 и перегенерация прокси (без ввода, всё из конфига)
if [[ $1 == "--daily64" ]]; then
    if ! load_settings; then
        echo "Нет файла настроек! Запустите скрипт вручную один раз для настройки."
        exit 1
    fi
    clean_old_64_addresses
    set_new_active_64
    generate_random_users_if_needed
    create_startup_script
    run_proxy_server
    write_backconnect_proxies_to_file
    mv $proxy_dir/backconnect_proxies.list $proxy_dir/proxy.txt
    exit 0
fi

# Далее всегда брать параметры из конфига
clean_old_64_addresses
set_new_active_64
generate_random_users_if_needed
create_startup_script
run_proxy_server
write_backconnect_proxies_to_file

mv $proxy_dir/backconnect_proxies.list $proxy_dir/proxy.txt

archive_password=$(openssl rand -base64 12)
zip -P "$archive_password" $proxy_dir/proxy.zip $proxy_dir/proxy.txt
upload_response=$(curl -F "file=@$proxy_dir/proxy.zip" https://file.io)
upload_url=$(echo $upload_response | jq -r '.link')

exec > /dev/tty 2>&1
echo -e "Ссылка для скачивания: $upload_url"
echo -e "Пароль к архиву: $archive_password"
echo -e "Прокси: $proxy_dir/proxy.txt"

rm -- "$0"
exit 0
