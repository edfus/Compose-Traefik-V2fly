#!/bin/bash

# set -e

#NOTE"' -y'
#NOTE store command

blue () {
  echo -e "\033[34m\033[01m$1\033[0m"
}
green () {
  echo -e "\033[32m\033[01m$1\033[0m"
}
red () {
  echo -e "\033[31m\033[01m$1\033[0m"
}

urandom_lc () {
  cat /dev/urandom | head -c $1 | hexdump -e '"%x"'
}

urandom () {
  tr -dc A-Za-z0-9 </dev/urandom | head -c $(( $1 * 2 ))
}

if [[ -f /etc/redhat-release ]]; then
  RELEASE="centos"
  PKGMANAGER="yum"
  SYSTEMPWD="/usr/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "debian"; then
  RELEASE="debian"
  PKGMANAGER="apt-get"
  SYSTEMPWD="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
  RELEASE="ubuntu"
  PKGMANAGER="apt-get"
  SYSTEMPWD="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
  RELEASE="centos"
  PKGMANAGER="yum"
  SYSTEMPWD="/usr/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "debian"; then
  RELEASE="debian"
  PKGMANAGER="apt-get"
  SYSTEMPWD="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "ubuntu"; then
  RELEASE="ubuntu"
  PKGMANAGER="apt-get"
  SYSTEMPWD="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
  RELEASE="centos"
  PKGMANAGER="yum"
  SYSTEMPWD="/usr/lib/systemd/system/"
fi

install_docker () {  
  docker -v >/dev/null 2>&1
  if [ $? != 0 ]; then
    curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
    systemctl start docker
    systemctl enable docker
    usermod -aG docker $USER
  fi
}

install_docker_compose () {
  set +e
  docker-compose -v >/dev/null 2>&1
  if [ $? != 0 ]; then
    $PKGMANAGER -y install python-pip
    pip install --upgrade pip
    pip install docker-compose

    if [ $? != 0 ]; then
      curl -L "https://github.com/docker/compose/releases/download/v2.2.3/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
      chmod +x /usr/local/bin/docker-compose
      ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
    fi
  fi
}

get_ipv6_cidr () {
  ip -6 addr | awk '/inet6/{print $2}' | grep -v ^::1 | grep -v ^fe80 | grep -v ^fd00 | awk -F'/' '
    NR==1 || $2<max_block_size {max_block_size=$2; line=$1"/"$2}
    END {print line}
  '
}

compose_cmd () {
  docker-compose -p "$1" -f "$1.yml" --env-file ".$1.env" $2 $3
}

compose_up () {
  compose_cmd "$1" "$2" "up -d $3"
  if [ $? != 0 ]; then
    compose_cmd "$1" "$2" "down"
    compose_cmd "$1" "$2" "up -d $3"
  fi
}

# https://stackoverflow.com/a/18451819/13910382
ls_all_envfiles () {
  LC_ALL=C ls .env .*.env
}

stat_files () {
  stat -c "%U:%G %a %n" $1
}

function check_env () {
  if [ -f .profiles.env.stat ]; then
    echo "$(stat_files `ls_all_envfiles`)" > ".tmp.profiles.env.stat"
    green "Comparing status of all environment files..."
    set +e
    cmp .profiles.env.stat ".tmp.profiles.env.stat"
    if [ $? != "0" ]; then
      set -e
      green "====================="
      green "before: (.profiles.env.stat)"
      green "$(cat .profiles.env.stat)"
      green
      blue  "========V.S.=========="
      red "after: (.tmp.profiles.env.stat)"
      red "$(cat .tmp.profiles.env.stat)"
      red
      read -e -p "$(blue 'Press Enter to continue at your own risk.')" 
      mv .profiles.env.stat .profiles.env.stat.bak
      mv .tmp.profiles.env.stat .profiles.env.stat
      chmod 0744 .profiles.env.stat
    else
      set -e
      rm .tmp.profiles.env.stat
    fi
  fi
}

function initialize () {
  set +e
  install_docker
  install_docker_compose
}

function create_traefik_network () {
  set +e
  green "Checking if IPv6 is supported..."

  ipv6_enabled="false"
  network_interface="0.0.0.0"
  ipv6_disabled=`sysctl net.ipv6.conf.all.disable_ipv6 | sed -r 's/net.ipv6.conf.all.disable_ipv6\s=\s//'`
  ipv6_cidr=`get_ipv6_cidr`
  if [ $? != 0 ] || [ $ipv6_disabled != 0 ]; then
    red "IPv6 is not available, falling back to IPv4 only"
    network_interface="0.0.0.0"
  elif [ "$ipv6_cidr" == "" ]; then
    red "IPv6 is enabled on this machine,"
    red "but not a single public IPv6 address can be found."
    red "Falling back to IPv4 only."
    network_interface="0.0.0.0"
  else
    green "Enabling IPv6 support in Docker containers..."
    jq -h > /dev/null
    if [ $? != 0 ]; then
      $PKGMANAGER install -y jq
    fi
    test -f /etc/docker/daemon.json || echo '{}' > /etc/docker/daemon.json
    jq -s add <(cat <<EOF
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00:dead:beef:abcd::/64",
  "experimental": true,
  "ip6tables": true
}
EOF
) /etc/docker/daemon.json | tee /etc/docker/daemon.json
    systemctl reload docker

    docker network inspect traefik >/dev/null 2>&1
    traefik_network_exists=`[ $? == 0 ] && echo "true" || echo "false"`

    if [ "$traefik_network_exists" == "true" ]; then
      traefik_ipv6_enabled=`docker network inspect traefik | jq '.[0].EnableIPv6'`
      traefik_backends=`docker ps -qf "network=traefik"`

      if [ "$traefik_ipv6_enabled" == "false" ]; then
        for backend in $traefik_backends; do
          docker network disconnect -f traefik $backend
        done
        docker network rm traefik > /dev/null
      fi
    fi

    if [ "$traefik_network_exists" != "true" ] || [ "$traefik_ipv6_enabled" == "false" ]; then
      IFS=/ read ipv6_cidr_addr ipv6_cidr_subnet <<< "$ipv6_cidr"
      ipv6_addr_split=`awk -F'::' '{for(i=1;i<=NF;i++){print $i}}'  <<< "$ipv6_cidr_addr"`
      IFS=$'\n' read ipv6_network_addr ipv6_trailing_addr <<< "$ipv6_addr_split"

      ipv6_network_addr_colon_occurrences=`tr -dc ':' <<<"$ipv6_network_addr" | wc -c`
      ipv6_network_prefix="$(( "$ipv6_network_addr_colon_occurrences" * 16 + 16 ))"

      # https://github.com/Jimdo/facter/blob/534ee7f7d9ff62c31a32664258af89c8e1f95c37/lib/facter/util/manufacturer.rb#L7
      if [ "`/usr/sbin/dmidecode 2>/dev/null | grep Droplet`" != "" ]; then 
        ipv6_network_prefix=124 # Digital ocean droplet
      else
        if [ "${ipv6_network_prefix}" -ge 112 ]; then
          if [ "${ipv6_cidr_subnet}" -lt 112 ]; then
            ipv6_network_prefix=$(( $ipv6_cidr_subnet + 16 )) #NOTE
          else
            ipv6_network_prefix=$ipv6_cidr_subnet
          fi
        else
          ipv6_network_prefix=$(( $ipv6_network_prefix + 16 )) #NOTE
        fi
      fi

      read -e -i "${ipv6_cidr_addr}/${ipv6_network_prefix}" -p "$(blue 'IPv6 subnet range for the traefik network: ')" ipv6_range

      echo "+ docker network create --ipv6 --subnet $ipv6_range traefik"
      docker network create --ipv6 --subnet "$ipv6_range" traefik > /dev/null
      echo "+ docker run --rm --network traefik curlimages/curl curl -s -6 -m 5 icanhazip.com"
    fi

    ipv6_addr_result=`docker run --rm --network traefik curlimages/curl curl -s -6 -m 5 icanhazip.com`
    if [ "$ipv6_addr_result" == "" ]; then
      red "+ docker run --rm --network traefik curlimages/curl curl -s -6 -m 5 icanhazip.com"
      red "+ failed"
      red "`printf '=%.0s' $(seq 1 $(tput cols))`"
      red "`docker network inspect traefik`"
      red "`printf '=%.0s' $(seq 1 $(tput cols))`"
      red "+ IP configurations:"
      red "`ip -6 addr | grep global | grep -v '\s::1' | grep -v '\sfe80' | grep -v '\sfd00'`"
      blue "+ systemctl restart docker"
      systemctl restart docker
      blue "+ docker run --rm --network traefik curlimages/curl curl -s -6 -m 5 icanhazip.com"
      ipv6_addr_result=`docker run --rm --network traefik curlimages/curl curl -s -6 -m 5 icanhazip.com`
      if [ "$ipv6_addr_result" == "" ]; then
        red "+ docker run --rm --network traefik curlimages/curl curl -s -6 -m 5 icanhazip.com"
        red "+ failed"
        return 1
      fi
    fi
    traefik_ipv6_cidr="`docker network inspect traefik | jq -c '(.[0].IPAM.Config[] | select(.Subnet | contains(":")).Subnet)'`"
    # stripping double quotes
    traefik_ipv6_cidr="${traefik_ipv6_cidr%\"}"
    traefik_ipv6_cidr="${traefik_ipv6_cidr#\"}" 

    echo "IPv6 subnet assigned: $traefik_ipv6_cidr"
    echo "IPv6 address in containers: $ipv6_addr_result"

    if [ "$traefik_network_exists" == "true" ]; then
      if [ "$traefik_ipv6_enabled" == "false" ]; then
        for backend in $traefik_backends; do
          docker network connect traefik $backend
        done
      fi
    fi

    network_interface="::"
    ipv6_enabled="true"
  fi

  set +e
  [ "`docker network inspect traefik >/dev/null 2>&1; echo $?`" != 0 ] \
  && docker network create traefik
}

function up_v2fly () {
  set -e
  green "Creating V2ray config..."
  mkdir -p ./v2ray/config
	cat > ./v2ray/config/config.json <<-EOF
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "warning"
  },
  "dns": {},
  "stats": {},
  "inbounds": [
    {
      "port": "$PORT",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuidgen}",
            "alterId": 32
          }
        ]
      },
      "tag": "in-0",
      "streamSettings": {
        "network": "tcp",
        "security": "none",
        "tcpSettings": {}
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "blocked",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      }
    ]
  },
  "policy": {},
  "reverse": {},
  "transport": {}
}
EOF

  cat > .profile-traefik.env <<EOF
DOMAIN_NAME=$DOMAIN_NAME
EOF

  set +e

}

function up_client_configs () {
  set -e
  mkdir -p ./client-configs
  declare -a client_configs_params=()

  # --- hosts

  hosts='
hosts:
'

  domains="$(printf -v joined '%s ' "${CONFIG_HARDCODED_HOSTS[@]}")"
  local_addr=`curl -4 --silent ipv4.icanhazip.com`
  read -e -i "$domains" -p "$(blue 'Enter the domain name[s] (space-delimited): ')" -a CONFIG_HARDCODED_HOSTS

  if [[ ! "$(declare -p CONFIG_HARDCODED_HOSTS)" =~ "declare -a" ]]; then
    echo no array CONFIG_HARDCODED_HOSTS
    declare -a CONFIG_HARDCODED_HOSTS = ()
  fi


  # https://doc.traefik.io/traefik/v1.6/configuration/acme/
  domainnum=${#CONFIG_HARDCODED_HOSTS[@]}

  for (( i=0; i<${domainnum}; i++ ));
  do
    domain="${CONFIG_HARDCODED_HOSTS[$i]}"
    ishardcoded="${HARDCODE_DOMAINS[$i]:-y}"
    read -e -i "${ishardcoded}" -p "$(blue "Hard code IP address $local_addr for $i? (Y/n) ")" yn
    [ -z "${yn}" ] && yn="n"
    if [[ $yn == [Yy] ]]; then
      HARDCODE_DOMAINS[$i]=y
      hosts="$hosts$(echo $'\n  '"${CONFIG_HARDCODED_HOSTS[$i]}: $local_addr"$'')"
    else
      HARDCODE_DOMAINS[$i]=n
    fi
  done

  read -e -i "${CONFIG_PROFILE_NAME:-$DOMAIN_NAME}" -p "$(blue 'Enter the profile name: ')" CONFIG_PROFILE_NAME
  set +e
  POSSIBLE_DUE_TIMESTAMP="${CONFIG_DUE_TIMESTAMP:+@$CONFIG_DUE_TIMESTAMP}"
  read -e -i "$(date "+%m/%d/%Y" -d "${POSSIBLE_DUE_TIMESTAMP:-3 months}")" -p "$(blue 'Any determined due date? [%m/%d/%Y] ')" DUE_DATE 
  # Test if input is valid 
  date -d "${DUE_DATE:-"No input is given."}" "+%m/%d/%Y" >/dev/null
  if [ $? != 0 ]; then
    DUE_DATE=$(date "+%m/%d/%Y" -d "2 years")
    red "Due date has been set to dummy date $DUE_DATE"
  fi

  CONFIG_DUE_TIMESTAMP=$(date "+%s" -d "${DUE_DATE}")
  
  # --- doh
  set -e
  read -e -i "${CONFIG_DOH_PATH-/$(urandom_lc 4)}" -p "$(blue 'Enter the DoH URI path (Leave empty to disable): ')" CONFIG_DOH_PATH 
  CONFIG_DOH_PATH="$(echo "$CONFIG_DOH_PATH" | sed -r 's/^\/*([^\/])/\/\1/')"
  
  if [ "$CONFIG_DOH_PATH" != "" ]; then
    read -r -d '' dns << EOM
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  use-hosts: true
  nameserver:
    - https://${DOMAIN_NAME}${CONFIG_DOH_PATH}
  fallback-filter:
    geoip: false
EOM
    client_configs_params+="--profile client-configs-doh"
  else
    dns=
  fi

  CONFIG_FILENAME="$CONFIG_PROFILE_NAME $local_addr"
  if [[ ! "$(declare -p CONFIG_USERS)" =~ "declare -a" ]]; then
    red "no array CONFIG_USERS"
    declare -a CONFIG_USERS = ("clash")
  fi

  if [[ ! "$(declare -p CONFIG_PASSWORDS)" =~ "declare -a" ]]; then
    red "no array CONFIG_PASSWORDS"
    declare -a CONFIG_PASSWORDS = ("$(urandom 8)")
  fi

  users="$(printf -v joined '%s ' "${CONFIG_USERS[@]}")"

  # https://stackoverflow.com/a/53839433/13910382
  read -e -i "${users:-clash}" -p "$(blue 'Privileged user[s] for client config access (space-delimited): ')" -a CONFIG_USERS 

  declare -a CONFIG_AUTH_BCRYPTED = ()

  usernum=${#CONFIG_USERS[@]}

  # use for loop to read all values and indexes
  for (( i=0; i<${usernum}; i++ ));
  do
    user="${CONFIG_USERS[$i]}"
    password="${CONFIG_PASSWORDS[$i]:-$(urandom 8)}"
    CONFIG_AUTH_BCRYPTED+="$user:$(echo "$(htpasswd -nb "${user}" "${password}")" | sed -e s/\\$/\\$\\$/g)"
  done

  mkdir -p ./credentials
  printf '%s\n' "${CONFIG_AUTH_BCRYPTED[@]}" > ./credentials/profile-client-configs
  # admin:$2y$10$uFGdAIp/0EEUegJjqF55AOc79.8Rv2TSnsO2BLN7uUm0g.BCx4JsW
  # someone:$Ay$10$uFGdAIp/0EEUegJjqF55AOc79.8Rv2TSnsO2BLN7uUm0g.BFx4JsW

  cat > .secrets.profile-client-configs.env <<EOF
$(declare -p CONFIG_USERS)
$(declare -p CONFIG_PASSWORDS)
EOF
  chmod 0700 .secrets.profile-client-configs.env

  cat > .profile-client-configs.env <<EOF
CONFIG_PROFILE_NAME="$CONFIG_PROFILE_NAME"
CONFIG_FILENAME="$CONFIG_FILENAME"
CONFIG_DUE_TIMESTAMP="$CONFIG_DUE_TIMESTAMP"
CONFIG_DOH_PATH="$CONFIG_DOH_PATH"
EOF

  cat >./client-configs/clash.yml<< EOF
port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: 127.0.0.1:9090
experimental:
  ignore-resolve-fail: true
proxies:
  - name: "$CONFIG_PROFILE_NAME"
    type: trojan
    server: $DOMAIN_NAME
    port: 443
    password: "$TROJAN_PASSWORD"
    udp: true
    alpn:
      - h2
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - "$CONFIG_PROFILE_NAME"
  - name: Quick UDP Internet Connections
    type: select
    proxies:
      - REJECT
      - Proxy
script:
  shortcuts:
    QUIC: network == 'udp' and dst_port == 443

rules:
  - SCRIPT,QUIC,Quick UDP Internet Connections
  - DOMAIN,localhost,DIRECT
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,lan,DIRECT  
  - IP-CIDR,0.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.0.0.0/24,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,198.18.0.0/15,DIRECT,no-resolve
  - IP-CIDR,224.0.0.0/3,DIRECT,no-resolve
  - IP-CIDR6,::1/128,DIRECT,no-resolve
  - IP-CIDR6,fc00::/7,DIRECT,no-resolve
  - IP-CIDR6,fe80::/10,DIRECT,no-resolve
  - MATCH,Proxy
$hosts
$dns
EOF

  compose_up "profile-client-configs" "${client_configs_params[@]}"

  read -r -d '' prompt << EOM
  $(declare -p CONFIG_USERS)
  $(declare -p CONFIG_PASSWORDS)

  green "======================="
  blue "USER: \${CONFIG_USERS[@]}"
  blue "PASSWORD: \${CONFIG_PASSWORDS[@]}"
  blue "Config files are available at"
  usernum=\${#CONFIG_USERS[@]}
  for (( i=0; i<\${usernum}; i++ ));
  do
    user="\${CONFIG_USERS[\$i]}"
    password="\${CONFIG_PASSWORDS[\$i]}"
    blue "https://\$user:\${password}@\${CONFIG_MAIN_DOMAIN}/.config/clash.yml" 
  done  
  green "======================="
EOM

  COMMANDS_ON_EXIT+=(
    "$prompt"
  )
}

function up_decoys () {
  set -e
  read -e -i "y" -p "$(blue 'Set up a decoy site? (Y/n) ')" decoy
  [ -z "${decoy}" ] && decoy="y"

  if [[ $decoy == [Yy] ]]; then
    read -e -i "1" -p "$(blue '1) Goscrape website copier 2) Archivebox') " choice

    case $choice in
      1) # Goscrape
        read -e -i "${GOSCRAPE_HOST:-"nic.eu.org"}" -p "$(blue 'Web host to be cloned (only https is supported): ')" GOSCRAPE_HOST
        [ -z "${GOSCRAPE_HOST}" ] && echo "An input is required" && return 1
        [ ! -z "`echo -n ${GOSCRAPE_HOST} | grep :`" ] && echo "${GOSCRAPE_HOST}: Do not enter the protocol, type hostname only" && return 1
        read -e -i "${GOSCRAPE_ARGS:-"--depth 3 --imagequality 4"}" -p "$(blue 'Arguments for Goscrape: ')" GOSCRAPE_ARGS
       ;;
      2) # Archivebox
        read -e -i "${ARCHIVEBOX_SCHEDULE_ENABLE:-n}" -p "$(blue 'Any URL for scheduled regular imports? ')" yn
        [ -z "${yn}" ] && yn="n"
        if [[ $yn == [Nn] ]]; then
          ARCHIVEBOX_SCHEDULE_ENABLE="n"
          ARCHIVEBOX_SCHEDULE_PRECEDING_CMD="sleep infinity; /bin/false"
        else
          ARCHIVEBOX_SCHEDULE_ENABLE="$yn"
          ARCHIVEBOX_SCHEDULE_PRECEDING_CMD=""
          ARCHIVEBOX_SCHEDULE_TARGET="$yn"
          read -e -i "${ARCHIVEBOX_SCHEDULE_ARGS:-"--every=month --depth=0"}" -p "$(blue 'Schedule configuration parameters: ')" ARCHIVEBOX_SCHEDULE_ARGS
        fi
      ;;
      *) echo "Unrecognized selection: $choice" return 1 ;;
    esac

      cat > .profile-decoys.env <<EOF
GOSCRAPE_HOST="$GOSCRAPE_HOST"
GOSCRAPE_ARGS="$GOSCRAPE_ARGS"
ARCHIVEBOX_SCHEDULE_ENABLE="$ARCHIVEBOX_SCHEDULE_ENABLE"
ARCHIVEBOX_SCHEDULE_PRECEDING_CMD="$ARCHIVEBOX_SCHEDULE_PRECEDING_CMD"
ARCHIVEBOX_SCHEDULE_TARGET="$ARCHIVEBOX_SCHEDULE_TARGET"
ARCHIVEBOX_SCHEDULE_ARGS="$ARCHIVEBOX_SCHEDULE_ARGS"
EOF
    case $choice in
      1) # Goscrape
        compose_up "profile-decoys" "--profile decoy-goscrape"
        COMMANDS_ON_EXIT_BLOCKING+=(
          'compose_cmd "profile-decoys" "logs --follow"'
        )
       ;;
      2) # Archivebox
        compose_cmd "profile-decoys" "--profile decoy-archivebox run" "archivebox init --setup"
        compose_up "profile-decoys" "--profile decoy-archivebox"
      ;;
      *) echo "Unrecognized selection: $choice" return 1 ;;
    esac
  fi
}

function import_envfiles () {
  check_env

  all_envfiles="`ls_all_envfiles`"
  # https://stackoverflow.com/a/30969768
  set +e
  set -o allexport
  for envfile in $all_envfiles; do source "$envfile"; done
  set +o allexport
}

function secure_envfiles () {
  check_env

  set -e
  all_envfiles="`ls_all_envfiles`"
  chmod 0700 $all_envfiles
  echo "$(stat_files $all_envfiles)" > .profiles.env.stat
  chmod 0744 .profiles.env.stat
}

function check_privileged_ports () {
  set +e
  netstat --version >/dev/null 2>&1
  if [ $? != 0 ]; then
    $PKGMANAGER install -y net-tools
  fi

  port80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
  port443=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 443`
  if [ -n "$port80" ]; then
      process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
      red "==========================================================="
      red "Port 80 is already in use by process ${process80}"
      red "==========================================================="
  fi

  if [ -n "$port443" ]; then
      process443=`netstat -tlpn | awk -F '[: ]+' '$5=="443"{print $9}'`
      red "============================================================="
      red "Port 443 is already in use by process ${process443}"
      red "============================================================="
  fi
}

function up_traefik () {
  set -e
  green "Spinning up the reverse proxy..."

  touch traefik/acme.json
  chmod 600 traefik/acme.json

  mkdir -p ./secrets/cloudflare
  chmod 0600 ./secrets/cloudflare
  set +e
  chown root:root ./secrets/cloudflare
  read -e -i "$(cat ./secrets/cloudflare/CF_DNS_API_TOKEN)" -p "$(blue 'Traefik CF_DNS_API_TOKEN: ')" tmp
  echo -n "$tmp" >"./secrets/cloudflare/CF_DNS_API_TOKEN"
  read -e -i "$(cat ./secrets/cloudflare/CF_ZONE_API_TOKEN)" -p "$(blue 'Traefik CF_ZONE_API_TOKEN: ')" tmp
  echo -n "$tmp" >"./secrets/cloudflare/CF_ZONE_API_TOKEN"
  unset tmp
  chmod -R 0600 ./secrets/cloudflare
  chown -R root:root ./secrets/cloudflare

  read -e -i "${TRAEFIK_ACME_EMAIL:-GLOBAL_EMAIL}" -p "$(blue 'Traefik ACME email address: ')" TRAEFIK_ACME_EMAIL
  if [ -z "$GLOBAL_EMAIL" ]; then
    return 1
  fi

  if [ ! -f ./userfiles/profile-traefik.yml ]; then
    read -e -i "${TRAEFIK_ACME_DOMAIN_MAIN:-GLOBAL_DOMAIN_MAIN}" -p "$(blue 'Traefik ACME main domain (Do NOT use wildcard): ')" TRAEFIK_ACME_DOMAIN_MAIN
    if [ ! -z "$TRAEFIK_ACME_DOMAIN_MAIN" ]; then
      GLOBAL_DOMAIN_MAIN="$TRAEFIK_ACME_DOMAIN_MAIN"
    fi
    read -e -i "${TRAEFIK_ACME_DOMAIN_SANS}" -p "$(blue 'Traefik ACME domain SANs (Subject Alternative Name, supports wildcard, space delimited): ')" -a  TRAEFIK_ACME_DOMAIN_SANS
    # if [ ! -z "$TRAEFIK_ACME_DOMAIN_SANS" ]; then
    #   GLOBAL_DOMAIN_SANS="${TRAEFIK_ACME_DOMAIN_SANS[@]}"
    # fi
    declare -a labels=()
    labels+="traefik.http.routers.acme-domains.tls.domains[0].main=\"${TRAEFIK_ACME_DOMAIN_MAIN}\""
    labels+="traefik.http.routers.acme-domains.tls.domains[0].sans=$(printf '"%s",' "${TRAEFIK_ACME_DOMAIN_SANS[@]}")"

    read -e -i "${TRAEFIK_ADDITIONAL_ENTRYPOINTS}" -p "$(blue 'Traefik additional entrypoints (SYNTAX: name,host-port,traefik-endpoint. e.g. nginx,8443,:8443/tcp): ')" -a TRAEFIK_ADDITIONAL_ENTRYPOINTS
    mkdir -p userfiles
    entrynum=${#TRAEFIK_ADDITIONAL_ENTRYPOINTS[@]}
    declare -a command=()
    declare -a ports=()

    for (( i=0; i<${entrynum}; i++ ));
    do
      IFS=',' read -ra split_parts <<< "${TRAEFIK_ADDITIONAL_ENTRYPOINTS[$i]}"
      entrypoint="${split_parts[0]}"
      host_port="${split_parts[1]}"
      traefik_endpoint="${split_parts[2]}"
      command+="--entrypoints.${entrypoint}.address=${traefik_endpoint}"
      ports+="${host_port}${traefik_endpoint}"
    done


    cat > ./userfiles/profile-traefik.yml <<EOF
services:
  traefik:
    command:
$(printf '      - "%s"\n' "${command[@]}")
    ports:
$(printf '      - "%s"\n' "${ports[@]}")
    labels:
$(printf '      - "%s"\n' "${labels[@]}")
EOF
  else
    nano ./userfiles/profile-traefik.yml
  fi


  docker run -i --rm -v "${PWD}":/workdir mikefarah/yq \
  m profile-traefik.yml ./userfiles/profile-traefik.yml > "profile-traefik.yml.new"
  
  mv profile-traefik.yml profile-traefik.yml.bak
  mv profile-traefik.yml.new profile-traefik.yml

  compose_up "profile-traefik"
}

function up () {
  initialize

  check_privileged_ports

  import_envfiles

  create_traefik_network
  
  up_traefik

  green "Starting docker services..."

  up_client_configs

  up_v2fly

  up_decoys

  secure_envfiles
}

function check_traefik_network () {
  set +e
  if [ "`docker network inspect traefik >/dev/null 2>&1; echo $?`" != 0 ]; then
    red "Unrecoverable error: can't find a pre-existing network named 'traefik'"
    red "If you are settng up a server dedicated to V2fly services,"
    red "run this script again with switch --up"
    red "Or create a traefik network manually (./index.sh --command 'create_traefik_network')."
    return 1
  fi
}

function schedule-ipv6-rotation () {
  ./srv-ipv6-rotation.sh "$@"
}

function down () {
  set +e
  traefik_backends=`docker ps -qf "network=traefik"`
  for backend in $traefik_backends; do
    docker network disconnect -f traefik $backend
    docker stop $backend && docker rm $backend
  done
  docker network rm traefik
}

function update () {
  set -e
  git reset --hard HEAD
  git pull origin master
  chmod +x *.sh
}

function consolidate () {
  set +e
  git --version > /dev/null 2>&1
  if [ $? != 0 ]; then
    set -e
    $PKGMANAGER -y install git
  fi
  set -e
  CONSOLIDATION_REPOSITORY_NAME=${CONSOLIDATION_REPOSITORY_NAME:-consolidate-clash-profiles}
  if [ -d "$CONSOLIDATION_REPOSITORY_NAME" ]; then
    CWD=$PWD
    cd "$CONSOLIDATION_REPOSITORY_NAME"
    set +e
    git fetch --all
    git reset --hard origin/master
    set -e
    cd "$CWD"
  else
    git clone --depth 1 https://github.com/edfus/"$CONSOLIDATION_REPOSITORY_NAME"
  fi

  check_traefik_network
  if [ "$?" != 0 ]; then
    return 1
  fi

  if [ "$CONSOLIDATION_PROFILES_SRC" == "" ] || ! [ -f  "$CONSOLIDATION_PROFILES_SRC" ]; then
    if ! [ -f profiles.js ]; then
      cat>profiles.js<<EOF
export default [

]
EOF
    fi
    nano profiles.js
    CONSOLIDATION_PROFILES_SRC=profiles.js
  fi

  if [ "$CONSOLIDATION_INJECTIONS_SRC" == "" ] || ! [ -f  "$CONSOLIDATION_INJECTIONS_SRC" ]; then
    if ! [ -f injections.yml ]; then
      cat>injections.yml<<EOF
Microsoft Network Connectivity Status Indicator:
  payload:
    - DOMAIN,dns.msftncsi.com,Microsoft Network Connectivity Status Indicator
    - DOMAIN,www.msftncsi.com,Microsoft Network Connectivity Status Indicator
    - DOMAIN,www.msftconnecttest.com,Microsoft Network Connectivity Status Indicator

EOF
    fi
    nano injections.yml
    CONSOLIDATION_INJECTIONS_SRC=injections.yml
  fi

  if [ "$CONSOLIDATION_WRANGLER_CONFIG" == "" ] || ! [ -f  "$CONSOLIDATION_WRANGLER_CONFIG" ]; then
    if [ -f wrangler.toml ]; then
      CONSOLIDATION_WRANGLER_CONFIG=wrangler.toml
    elif [ -f "$CONSOLIDATION_REPOSITORY_NAME/wrangler.toml" ]; then
      CONSOLIDATION_WRANGLER_CONFIG="$CONSOLIDATION_REPOSITORY_NAME/wrangler.toml"
    else
      # docker-compose -f "$COMPOSE_FILE" --env-file /dev/null run clash-profiles ./init-wrangler.sh
      chmod +x "./$CONSOLIDATION_REPOSITORY_NAME/init-wrangler.sh"
      "./$CONSOLIDATION_REPOSITORY_NAME/init-wrangler.sh"
      CONSOLIDATION_WRANGLER_CONFIG="./$CONSOLIDATION_REPOSITORY_NAME/wrangler.toml"
    fi
  fi

  CONSOLIDATION_ACCESS_USERNAME=${CONSOLIDATION_ACCESS_USERNAME:-$(urandom_lc 2)}
  CONSOLIDATION_ACCESS_PASSWORD=${CONSOLIDATION_ACCESS_PASSWORD:-$(urandom 6)}
  CONSOLIDATION_ACCESS_PASSWORD_BCRYPTED=$(docker run --rm caddy/caddy:2.4.0-alpine caddy hash-password -algorithm "bcrypt" -plaintext "$CONSOLIDATION_ACCESS_PASSWORD")

  if [ -z "$CONSOLIDATION_PROFILES_OUTPUT" ]; then
    CONSOLIDATION_PROFILES_OUTPUT="external-rulesets"
  fi

  cat > ".profile-clash-consolidation.env" <<EOF
CONSOLIDATION_REPOSITORY_NAME="${CONSOLIDATION_REPOSITORY_NAME}"
CONSOLIDATION_PROFILES_OUTPUT="${CONSOLIDATION_PROFILES_OUTPUT:+$(readlink -f "$CONSOLIDATION_PROFILES_OUTPUT")}"
CONSOLIDATION_PROFILES_SRC="$(readlink -f "$CONSOLIDATION_PROFILES_SRC")"
CONSOLIDATION_INJECTIONS_SRC="$(readlink -f "$CONSOLIDATION_INJECTIONS_SRC")"
CONSOLIDATION_WRANGLER_CONFIG="${CONSOLIDATION_WRANGLER_CONFIG:+$(readlink -f "$CONSOLIDATION_WRANGLER_CONFIG")}"
CONSOLIDATION_ACCESS_USERNAME="$CONSOLIDATION_ACCESS_USERNAME"
CONSOLIDATION_ACCESS_PASSWORD="$CONSOLIDATION_ACCESS_PASSWORD"
CONSOLIDATION_ACCESS_PASSWORD_BCRYPTED="$CONSOLIDATION_ACCESS_PASSWORD_BCRYPTED"
EOF

  cat >> ".profile-clash-consolidation.env" <<EOF
CONSOLIDATION_CUTOFF_TIMESTAMP=${CONFIG_DUE_TIMESTAMP:-$CONSOLIDATION_CUTOFF_TIMESTAMP}
EOF

  compose_up "profile-clash-consolidation" "" "--build"

  if [ "$DOMAIN_NAME" == "" ]; then
    read -e -p "$(blue 'Enter the domain name: ')" DOMAIN_NAME
  fi

  green "======================="
  blue "USERNAME: $CONSOLIDATION_ACCESS_USERNAME"
  blue "PASSWORD: ${CONSOLIDATION_ACCESS_PASSWORD}"
  blue "Config files are available at https://$CONSOLIDATION_ACCESS_USERNAME:${CONSOLIDATION_ACCESS_PASSWORD}@${DOMAIN_NAME}/.profiles?code=$(echo "TWFpbmxhbmQlMjBDaGluYQo=" | base64 -d)"
  green "======================="

  compose_cmd "profile-clash-consolidation" "exec clash-profiles" "wrangler config"
  compose_cmd "profile-clash-consolidation" "exec clash-profiles" "wrangler publish"

  COMMANDS_ON_EXIT_BLOCKING+='compose_cmd "profile-clash-consolidation" "logs --follow clash-profiles"'
}

if [[ $# -eq 0 ]]; then
  up
  exit
fi

declare -a COMMANDS_ON_EXIT=()
declare -a COMMANDS_ON_EXIT_BLOCKING=()

# https://stackoverflow.com/a/14203146/13910382
POSITIONAL_ARGS=()

declare -a COMMANDS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--consolidate|consolidate)
      declare -a new_commands = (
        "import_envfiles"
        "check_traefik_network"
        "consolidate"
        "secure_envfiles"
      )
      COMMANDS=( "${COMMANDS[@]}" "${new_commands[@]}")
      shift # past argument
      ;;
    -i|--initialize|--install|initialize|install)
      COMMANDS+="initialize"
      shift # past argument
      ;;
    -u|--up|up)
      declare -a new_commands = (
        "initialize"
        "check_privileged_ports"
        "import_envfiles"
        "create_traefik_network"
        "up_traefik"
        'green "Starting docker services..."'
        "up_client_configs"
        "up_v2fly"
        "up_decoys"
        "secure_envfiles"
      )
      COMMANDS=( "${COMMANDS[@]}" "${new_commands[@]}")
      shift # past argument
      ;;
    -d|--down|down)
      COMMANDS+="down"
      shift # past argument
      ;;
    -U|--update|update)
      COMMANDS+="update"
      shift # past argument
      ;;
    -C|--command|--add-command)
      COMMANDS+="$2"
      shift # past argument
      shift # past value
      ;;
    --commands)
      IFS='; ' read -r -a COMMANDS <<< "$2"
      shift # past argument
      shift # past value
      ;;
    -I|--injections)
      CONSOLIDATION_INJECTIONS_SRC="$2"
      shift # past argument
      shift # past value
      ;;
    -P|--profiles|--config)
      CONSOLIDATION_PROFILES_SRC="$2"
      shift # past argument
      shift # past value
      ;;
    -W|--wranger|--wranger-config)
      CONSOLIDATION_WRANGLER_CONFIG="$2"
      shift # past argument
      shift # past value
      ;;
    -O|--output)
      CONSOLIDATION_PROFILES_OUTPUT="$2"
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      sed -n '/POSITIONAL_ARGS=\(\)/,$p' "$0"
      exit 0
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

for (( i = 0; i < ${#COMMANDS[@]} ; i++ )); do
    printf "\n**** Running: ${COMMANDS[$i]} *****\n\n"
    set +e
    eval "${COMMANDS[$i]}"
done

for command in "${COMMANDS_ON_EXIT[@]}"
do
  eval "$command"
done

# https://stackoverflow.com/a/36220892/13910382
allow_quit() {
    [ $(date +%s) -lt $(( $last + 1 )) ] && echo; exit
    last=$(date +%s)
    echo " Press Ctrl + C twice to force terminate the program"
}
for command in "${COMMANDS_ON_EXIT_BLOCKING[@]}"
do
  last=0
  trap allow_quit SIGINT
  eval "$command"
  trap SIGINT
done