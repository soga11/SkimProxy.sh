#!/bin/bash
#================================================================
# Hysteria2 无限带宽优化版
# 上下行带宽：无限制 (0 = 自动协商)
# SNI: icloud.cdn-apple.com (Apple CDN 伪装)
# BBR: 自动安装（已安装则跳过）
# 版本: 5.0.0 - Unlimited Edition
#================================================================

GREEN_BG='\033[42;30m'
RED_BG='\033[41;97m'
WHITE_BG='\033[47;30m'
YELLOW_BG='\033[43;30m'
CYAN_BG='\033[46;30m'
NORMAL='\033[0m'

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED_BG}This script requires root privileges.${NORMAL} Please run as root or use sudo."
  exit 1
fi

cpu_arch=$(uname -m)
case "$cpu_arch" in
  x86_64) arch="amd64" ;;
  aarch64) arch="arm64" ;;
  *) echo -e "${RED_BG}Unsupported architecture: $cpu_arch${NORMAL}"; exit 1 ;;
esac

if [ -z "$3" ] || [ "$3" = "auto" ]; then
  ip=$(curl -s4 --max-time 5 https://api.ipify.org)
  if [ -z "$ip" ]; then
    ip=$(curl -s --max-time 5 https://cloudflare.com/cdn-cgi/trace -4 | grep -oP '(?<=ip=).*')
  fi
  if [ -z "$ip" ]; then
    ip=$(curl -s --max-time 5 https://cloudflare.com/cdn-cgi/trace -6 | grep -oP '(?<=ip=).*')
  fi
  if echo "$ip" | grep -q ':'; then
    ip="[$ip]"
  fi
else 
  ip=$3
fi

urlencode() {
    local LANG=C
    local input
    if [ -t 0 ]; then
        input="$1"
    else
        input=$(cat)
    fi
    local length="${#input}"
    for (( i = 0; i < length; i++ )); do
        c="${input:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "%s" "$c" ;;
            $'\n') printf "%%0A" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done
    echo
}

install_packages() {
  if command -v apk &> /dev/null; then
    apk update && apk add curl jq tar openssl xz
  elif command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y curl jq tar openssl xz-utils
  elif command -v pacman &> /dev/null; then
    pacman -Syu --noconfirm curl jq tar openssl xz
  elif command -v dnf &> /dev/null; then
    dnf install -y curl jq tar openssl xz
  elif command -v yum &> /dev/null; then
    yum install -y curl jq tar openssl xz
  else
    echo -e "${RED_BG}[ERROR] Unsupported package manager.${NORMAL}"
    exit 1
  fi
}

is_busybox_grep() {
  grep --version 2>&1 | grep -q BusyBox
}

if is_busybox_grep; then
  echo -e "${GREEN_BG}[Requirements] BusyBox grep detected. Installing GNU grep.${NORMAL}"
  if command -v apk >/dev/null; then
    apk add grep
  elif command -v apt-get >/dev/null; then
    apt-get update && apt-get install -y grep
  fi
fi

for tool in curl jq tar openssl xz; do
  if ! command -v "$tool" &> /dev/null; then
    echo -e "${GREEN_BG}[Requirements] Installing missing dependencies...${NORMAL}"
    install_packages
    break
  fi
done

get_latest_version() {
  latest_version=$(curl -s --max-time 10 "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r .tag_name)
  if [[ "$latest_version" == "null" || -z "$latest_version" ]]; then
    echo "app/v2.6.1"
  else
    echo "$latest_version"
  fi
}

download_hy2_core() {
  mkdir -p /opt/skim-hy2/
  url="https://github.com/apernet/hysteria/releases/download/${version}/hysteria-linux-${arch}"
  echo -e "${GREEN_BG}Downloading ${url}...${NORMAL}"
  curl -s -L -o /opt/skim-hy2/hy2 "$url"
  chmod +x /opt/skim-hy2/hy2
  echo -e "${GREEN_BG}hy2 core installed to /opt/skim-hy2/${NORMAL}"
}

if [ -z "$2" ] || [ "$2" = "auto" ]; then
  version=$(get_latest_version)
else
  version="$2"
fi

if [[ -x "/opt/skim-hy2/hy2" ]]; then
    installed_version=$("/opt/skim-hy2/hy2" version | grep -i '^Version:' | awk '{print $2}')
    if [[ "app/$installed_version" == "$version" ]]; then
        echo -e "${GREEN_BG}[Requirements] Hysteria 2 core ${version} is already installed.${NORMAL}"
    else
        echo -e "${GREEN_BG}[Requirements] Updating from $installed_version to $version...${NORMAL}"
        download_hy2_core
    fi
else
    echo -e "${GREEN_BG}[Requirements] Hysteria 2 core not found. Installing...${NORMAL}"
    download_hy2_core
fi

if [ -z "$1" ] || [ "$1" = "auto" ]; then
  port=52015
else
  port=$1
fi

mkdir -p /opt/skim-hy2/$port
password="Aq112211!"

echo -e "${CYAN_BG}Generating self-signed certificate (SNI: icloud.cdn-apple.com)...${NORMAL}"

cat <<EOF > /opt/skim-hy2/$port/openssl.conf
[ req ]
default_bits           = 2048
prompt                 = no
default_md             = sha256
distinguished_name     = dn
x509_extensions        = v3_ext

[ dn ]
C                      = US
ST                     = California
L                      = Cupertino
O                      = Apple Inc.
OU                     = CDN Services
CN                     = icloud.cdn-apple.com

[ v3_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = icloud.cdn-apple.com
DNS.2 = *.cdn-apple.com
DNS.3 = *.apple.com
DNS.4 = *.icloud.com
EOF

openssl req -x509 -new -nodes -days 3650 \
  -keyout /opt/skim-hy2/$port/server.key \
  -out /opt/skim-hy2/$port/server.crt \
  -config /opt/skim-hy2/$port/openssl.conf 2>/dev/null

rm -f /opt/skim-hy2/$port/openssl.conf

echo -e "${GREEN_BG}Using address${NORMAL}: $ip:$port"
echo -e "${GREEN_BG}Generated password${NORMAL}: $password"
echo -e "${GREEN_BG}Server CA SHA256${NORMAL}: $(openssl x509 -noout -fingerprint -sha256 -in /opt/skim-hy2/$port/server.crt)"

# ==================== 无限带宽配置（0 = 不限制）====================
cat <<EOF > /opt/skim-hy2/$port/config.yaml
listen: :${port}

tls:
  cert: /opt/skim-hy2/${port}/server.crt
  key: /opt/skim-hy2/${port}/server.key

auth:
  type: password
  password: $password

# ========== 无限带宽配置（0 = 不限制）==========
bandwidth:
  up: 0
  down: 0

# ========== QUIC 传输优化（千兆级别）==========
quic:
  initStreamReceiveWindow: 33554432
  maxStreamReceiveWindow: 33554432
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 90s
  maxIncomingStreams: 2048
  disablePathMTUDiscovery: false

ignoreClientBandwidth: false
udpForwarding: true
fastOpen: true

log:
  level: info
EOF

echo -e "${GREEN_BG}Installing system service...${NORMAL}"
init_system=$(cat /proc/1/comm)

if [[ "$init_system" == "systemd" ]]; then
  cat <<EOF > /etc/systemd/system/hy2-${port}.service
[Unit]
Description=Hysteria 2 Server (Unlimited Bandwidth) on :${port}
Documentation=https://v2.hysteria.network/
After=network.target network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment="HYSTERIA_LOG_LEVEL=info"
ExecStart=/opt/skim-hy2/hy2 server -c /opt/skim-hy2/$port/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
LimitNPROC=512
StandardOutput=append:/var/log/hy2-$port.log
StandardError=append:/var/log/hy2-$port.log

Nice=-10
CPUSchedulingPolicy=fifo
IOSchedulingClass=realtime

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hy2-${port}
  systemctl start hy2-${port}
  
  sleep 2
  
  if systemctl is-active --quiet hy2-${port}; then
    echo -e "${GREEN_BG}[Service] ✓ Successfully started${NORMAL}"
  else
    echo -e "${RED_BG}[Service] ✗ Failed to start${NORMAL}"
    journalctl -u hy2-${port} -n 20 --no-pager
  fi
  
  echo ""
  echo -e "${WHITE_BG}========== Service Management ==========${NORMAL}"
  echo "  Status:  systemctl status hy2-${port}"
  echo "  Restart: systemctl restart hy2-${port}"
  echo "  Logs:    journalctl -u hy2-${port} -f"
  echo "  Remove:  systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf /opt/skim-hy2/$port"
  echo -e "${WHITE_BG}=========================================${NORMAL}"

elif [[ "$init_system" == "init" || "$init_system" == "openrc" ]]; then
  cat <<EOF > /etc/init.d/hy2-$port
#!/sbin/openrc-run

name="Hysteria 2 Server (Unlimited) on :$port"
description="Hysteria 2 server on :$port"
command="/opt/skim-hy2/hy2"
command_args="server -c /opt/skim-hy2/$port/config.yaml"
pidfile="/var/run/hy2-$port.pid"
logfile="/var/log/hy2-$port.log"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting \$name"
    start-stop-daemon --start --background --make-pidfile --pidfile \$pidfile \\
      --stdout \$logfile --stderr \$logfile --exec \$command -- \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping \$name"
    start-stop-daemon --stop --pidfile \$pidfile
    eend \$?
}
EOF

  chmod +x /etc/init.d/hy2-${port}
  rc-update add hy2-${port} default
  rc-service hy2-${port} start
  
  echo -e "${WHITE_BG}TO REMOVE:${NORMAL} rc-update del hy2-${port} && rc-service hy2-${port} stop && rm /etc/init.d/hy2-${port} && rm -rf /opt/skim-hy2/$port"
fi

# ==================== 自动安装 BBR 优化（已安装则跳过）====================
echo ""
echo -e "${YELLOW_BG}========== System Network Optimization ==========${NORMAL}"

if grep -q "# Hysteria2 Network Optimization" /etc/sysctl.conf; then
  echo -e "${GREEN_BG}BBR optimization already configured. Skipping...${NORMAL}"
else
  echo -e "${GREEN_BG}Applying Network Optimization (BBR + High Buffer)...${NORMAL}"
  
  cat >> /etc/sysctl.conf << 'SYSCTL_EOF'

# Hysteria2 Network Optimization
net.core.default_qdisc=fq_pie
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.rmem_default=16777216
net.core.wmem_default=16777216
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.core.netdev_max_backlog=50000
net.core.netdev_budget=600
net.core.netdev_budget_usecs=8000
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=15
net.netfilter.nf_conntrack_max=1000000
net.netfilter.nf_conntrack_tcp_timeout_established=7200
fs.file-max=1048576
vm.swappiness=10
vm.dirty_ratio=15
vm.dirty_background_ratio=5
SYSCTL_EOF
  
  sysctl -p > /dev/null 2>&1
  
  echo -e "${GREEN_BG}Network optimization applied!${NORMAL}"
fi

echo ""
echo -e "${CYAN_BG}Current System Configuration:${NORMAL}"
echo "  Congestion Control: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')"
echo "  Queue Discipline: $(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')"
echo "  Max Buffer Size: $(sysctl net.core.rmem_max 2>/dev/null | awk '{print $3/1048576}') MB"

if ! grep -q "* soft nofile 1048576" /etc/security/limits.conf 2>/dev/null; then
  cat >> /etc/security/limits.conf << 'LIMITS_EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
LIMITS_EOF
  echo -e "${GREEN_BG}File descriptor limits increased to 1048576${NORMAL}"
fi

# Generate share links
hy2_url="hysteria2://$(urlencode $password)@${ip//[\[\]]/}:$port/?insecure=1&sni=icloud.cdn-apple.com#$(urlencode "Hysteria2-Unlimited-$port")"

json_config=$(cat <<JSON_EOF
{
  "type": "hysteria2",
  "tag": "hy2-unlimited",
  "server": "${ip//[\[\]]/}",
  "server_port": $port,
  "password": "$password",
  "tls": {
    "enabled": true,
    "insecure": true,
    "server_name": "icloud.cdn-apple.com"
  }
}
JSON_EOF
)

clash_config=$(cat <<CLASH_EOF
proxies:
  - name: "Hysteria2-Unlimited"
    type: hysteria2
    server: ${ip//[\[\]]/}
    port: $port
    password: $password
    skip-cert-verify: true
    sni: icloud.cdn-apple.com
CLASH_EOF
)

echo ""
echo -e "${CYAN_BG}========================================${NORMAL}"
echo -e "${CYAN_BG}  ⚡ Hysteria2 Unlimited Edition ⚡${NORMAL}"
echo -e "${CYAN_BG}========================================${NORMAL}"
echo ""
echo -e "${WHITE_BG}Connection Information:${NORMAL}"
echo "  Server: ${ip//[\[\]]/}"
echo "  Port: $port"
echo "  Password: $password"
echo "  SNI: icloud.cdn-apple.com (Apple CDN)"
echo "  Bandwidth: Unlimited (Auto-negotiated)"
echo ""
echo -e "${GREEN_BG}Hysteria2 URL:${NORMAL}"
echo "$hy2_url"
echo ""
echo -e "${GREEN_BG}JSON Config (sing-box):${NORMAL}"
echo "$json_config"
echo ""
echo -e "${GREEN_BG}Clash Meta Config:${NORMAL}"
echo "$clash_config"
echo ""
echo -e "${YELLOW_BG}Client Configuration:${NORMAL}"
echo "  1. Self-signed certificate: Enable 'Skip Certificate Verification'"
echo "  2. SNI: icloud.cdn-apple.com"
echo "  3. Bandwidth: Unlimited (client auto-negotiated)"
echo "  4. Disguised as Apple iCloud CDN traffic"
echo ""
echo -e "${CYAN_BG}Performance Features:${NORMAL}"
echo "  ✓ Unlimited bandwidth (auto-negotiated)"
echo "  ✓ BBR congestion control"
echo "  ✓ 64 MB network buffers"
echo "  ✓ Apple CDN traffic disguise"
echo "  ✓ Ultra-low latency QUIC optimization"
echo ""
echo -e "${GREEN_BG}Service hy2-${port} has been started successfully!${NORMAL}"
echo -e "${CYAN_BG}========================================${NORMAL}"
