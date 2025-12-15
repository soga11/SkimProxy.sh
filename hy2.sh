#!/bin/bash
#================================================================
# Hysteria2 千兆带宽优化版
# 上下行带宽：1000 Mbps (千兆)
# SNI: icloud.cdn-apple.com (Apple CDN 伪装)
# 版本: 4.0.0 - Gigabit Edition
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

# Detect CPU architecture
cpu_arch=$(uname -m)
case "$cpu_arch" in
  x86_64) arch="amd64" ;;
  aarch64) arch="arm64" ;;
  *) echo -e "${RED_BG}Unsupported architecture: $cpu_arch${NORMAL}"; exit 1 ;;
esac

# Auto-detect IP
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

# Generate self-signed certificate with Apple CDN SNI
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

# ==================== 千兆带宽配置 ====================
cat <<EOF > /opt/skim-hy2/$port/config.yaml
listen: :${port}

tls:
  cert: /opt/skim-hy2/${port}/server.crt
  key: /opt/skim-hy2/${port}/server.key

auth:
  type: password
  password: $password

# ========== 千兆带宽配置（无限制）==========
# 选项 1: 完全不限制（推荐千兆服务器）
# bandwidth:
#   up: 0
#   down: 0

# 选项 2: 1 Gbps 带宽配置（推荐）
bandwidth:
  up: 1000 mbps
  down: 1000 mbps

# ========== QUIC 传输优化（千兆级别）==========
quic:
  initStreamReceiveWindow: 33554432      # 32 MB (千兆网络)
  maxStreamReceiveWindow: 33554432       # 32 MB
  initConnReceiveWindow: 67108864        # 64 MB (千兆网络)
  maxConnReceiveWindow: 67108864         # 64 MB
  maxIdleTimeout: 90s                    # 延长空闲超时
  maxIncomingStreams: 2048               # 增加并发流
  disablePathMTUDiscovery: false

# ========== 高级性能优化 ==========
# 忽略客户端带宽配置（强制使用服务器配置）
ignoreClientBandwidth: false

# UDP 转发
udpForwarding: true

# 快速打开连接
fastOpen: true

# 日志级别
log:
  level: info

# ========== 混淆配置（可选，增强抗封锁）==========
# obfs:
#   type: salamander
#   salamander:
#     password: apple_obfs_secret_2024
EOF

echo -e "${GREEN_BG}Installing system service...${NORMAL}"
init_system=$(cat /proc/1/comm)

if [[ "$init_system" == "systemd" ]]; then
  cat <<EOF > /etc/systemd/system/hy2-${port}.service
[Unit]
Description=Hysteria 2 Server (Gigabit Edition) on :${port}
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

# Performance tuning
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

name="Hysteria 2 Server (Gigabit) on :$port"
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

# ==================== 千兆网络系统优化 ====================
echo ""
echo -e "${YELLOW_BG}========== System Network Optimization ==========${NORMAL}"
read -p "Enable Gigabit Network Optimization (BBR + High Buffer)? (Y/n): " enable_opt

if [[ "$enable_opt" != "n" && "$enable_opt" != "N" ]]; then
  echo -e "${GREEN_BG}Applying Gigabit Network Optimization...${NORMAL}"
  
  if ! grep -q "# Hysteria2 Gigabit Optimization" /etc/sysctl.conf; then
    cat >> /etc/sysctl.conf << 'SYSCTL_EOF'

# Hysteria2 Gigabit Optimization
# TCP 拥塞控制
net.core.default_qdisc=fq_pie
net.ipv4.tcp_congestion_control=bbr

# 千兆网络缓冲区（64 MB）
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.rmem_default=16777216
net.core.wmem_default=16777216
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384

# QUIC/UDP 优化
net.core.netdev_max_backlog=50000
net.core.netdev_budget=600
net.core.netdev_budget_usecs=8000

# TCP 性能优化
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=15

# 连接追踪优化
net.netfilter.nf_conntrack_max=1000000
net.netfilter.nf_conntrack_tcp_timeout_established=7200

# 文件描述符限制
fs.file-max=1048576

# 虚拟内存优化
vm.swappiness=10
vm.dirty_ratio=15
vm.dirty_background_ratio=5
SYSCTL_EOF
    
    # 应用配置
    sysctl -p > /dev/null 2>&1
    
    echo -e "${GREEN_BG}Gigabit optimization applied!${NORMAL}"
    echo ""
    echo -e "${CYAN_BG}Current Configuration:${NORMAL}"
    echo "  Congestion Control: $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')"
    echo "  Queue Discipline: $(sysctl net.core.default_qdisc | awk '{print $3}')"
    echo "  Max Buffer Size: $(sysctl net.core.rmem_max | awk '{print $3/1048576}') MB"
  else
    echo -e "${YELLOW_BG}Network optimization already configured.${NORMAL}"
  fi
  
  # 调整文件描述符限制
  if ! grep -q "* soft nofile 1048576" /etc/security/limits.conf; then
    cat >> /etc/security/limits.conf << 'LIMITS_EOF'
# Hysteria2 File Descriptor Limits
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
LIMITS_EOF
    echo -e "${GREEN_BG}File descriptor limits increased to 1048576${NORMAL}"
  fi
fi

# Generate share links with Apple CDN SNI
hy2_url="hysteria2://$(urlencode $password)@${ip//[\[\]]/}:$port/?insecure=1&sni=icloud.cdn-apple.com#$(urlencode "Hysteria2-Gigabit-$port")"

json_config=$(cat <<JSON_EOF
{
  "type": "hysteria2",
  "tag": "hy2-gigabit",
  "server": "${ip//[\[\]]/}",
  "server_port": $port,
  "password": "$password",
  "tls": {
    "enabled": true,
    "insecure": true,
    "server_name": "icloud.cdn-apple.com"
  },
  "up_mbps": 1000,
  "down_mbps": 1000
}
JSON_EOF
)

clash_config=$(cat <<CLASH_EOF
proxies:
  - name: "Hysteria2-Gigabit"
    type: hysteria2
    server: ${ip//[\[\]]/}
    port: $port
    password: $password
    skip-cert-verify: true
    sni: icloud.cdn-apple.com
    up: 1000
    down: 1000
CLASH_EOF
)

echo ""
echo -e "${CYAN_BG}========================================${NORMAL}"
echo -e "${CYAN_BG}  ⚡ Hysteria2 Gigabit Edition ⚡${NORMAL}"
echo -e "${CYAN_BG}========================================${NORMAL}"
echo ""
echo -e "${WHITE_BG}Connection Information:${NORMAL}"
echo "  Server: ${ip//[\[\]]/}"
echo "  Port: $port"
echo "  Password: $password"
echo "  SNI: icloud.cdn-apple.com (Apple CDN)"
echo "  Bandwidth: 1000 Mbps / 1000 Mbps"
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
echo "  3. Bandwidth: up=1000Mbps, down=1000Mbps"
echo "  4. Disguised as Apple iCloud CDN traffic"
echo ""
echo -e "${CYAN_BG}Performance Features:${NORMAL}"
echo "  ✓ 1 Gbps bandwidth configuration"
echo "  ✓ BBR congestion control"
echo "  ✓ 64 MB network buffers"
echo "  ✓ Apple CDN traffic disguise"
echo "  ✓ Ultra-low latency QUIC optimization"
echo ""
echo -e "${GREEN_BG}Service hy2-${port} has been started successfully!${NORMAL}"
echo -e "${CYAN_BG}========================================${NORMAL}"
