#!/bin/bash

# ========================================
# Hysteria2 Enhanced Edition
# Version: 8.1.0 - 中文推送版
# Date: 2025-12-15
# ========================================

GREEN_BG='\033[42;30m'
RED_BG='\033[41;97m'
YELLOW_BG='\033[43;30m'
WHITE_BG='\033[47;30m'
BLUE_BG='\033[44;97m'
NORMAL='\033[0m'

# ========================================
# Configuration
# ========================================
HOSTNAME="ip-172-31-3-171"
BOT_TOKEN="7808383148:AAF5LglthZukCj6eqbA0rEbJZQMAjlk--I0"
CHAT_ID="-1002145386723"
DEFAULT_PORT="52015"
DEFAULT_PASSWORD="Aq112211!"
SNI_DOMAIN="icloud.cdn-apple.com"

# Check root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED_BG}This script requires root privileges.${NORMAL} Please run as root or use sudo."
  exit 1
fi

# Detect CPU architecture
cpu_arch=$(uname -m)
case "$cpu_arch" in
  x86_64) arch="amd64" ;;
  aarch64) arch="arm64" ;;
  armv7l) arch="arm" ;;
  *) echo -e "${RED_BG}Unsupported architecture: $cpu_arch${NORMAL}"; exit 1 ;;
esac

# Install GNU grep if BusyBox ver grep found
is_busybox_grep() {
  grep --version 2>&1 | grep -q BusyBox
}
if is_busybox_grep; then
  echo -e "${GREEN_BG}[Requirements] BusyBox grep detected. Installing GNU grep.${NORMAL}"
  if command -v apk >/dev/null; then
    apk add grep
  elif command -v apt-get >/dev/null; then
    apt-get update && apt-get install -y grep
  elif command -v pacman >/dev/null; then
    pacman -Sy --noconfirm grep
  else
    echo -e "${RED_BG}[ERROR] Unsupported package manager.${NORMAL} Please install GNU grep manually."
    exit 1
  fi
fi

# URL encode function
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

# Telegram push function with Chinese comments
send_telegram() {
    local message="$1"
    local api_url="https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"
    
    # Escape special characters for JSON
    local escaped_message=$(echo "$message" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
    
    local response=$(curl -s -X POST "$api_url" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\": \"${CHAT_ID}\", \"text\": \"${escaped_message}\", \"parse_mode\": \"Markdown\", \"disable_web_page_preview\": true}" 2>/dev/null)
    
    if echo "$response" | grep -q '"ok":true'; then
        echo -e "${GREEN_BG}✅ Configuration pushed to Telegram${NORMAL}"
        return 0
    else
        echo -e "${YELLOW_BG}⚠️  Telegram push failed (network issue, service continues)${NORMAL}"
        return 1
    fi
}

# Install packages function
install_packages() {
  if command -v apk &> /dev/null; then
    apk update && apk add curl jq tar openssl xz
  elif command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y curl jq tar openssl xz-utils
  elif command -v pacman &> /dev/null; then
    pacman -Syu --noconfirm curl jq tar openssl xz
  elif command -v dnf &> /dev/null; then
    dnf install -y curl jq tar openssl xz
  elif command -v zypper &> /dev/null; then
    zypper install -y curl jq tar openssl xz
  elif command -v yum &> /dev/null; then
    yum install -y curl jq tar openssl xz
  else
    echo -e "${RED_BG}[ERROR] Unsupported package manager.${NORMAL} Please install curl, jq, tar, and openssl manually."
    exit 1
  fi
}

# Install required tools if missing
for tool in curl jq tar openssl xz; do
  if ! command -v "$tool" &> /dev/null; then
    echo -e "${GREEN_BG}[Requirements] Installing missing dependencies...${NORMAL}"
    install_packages
    break
  fi
done

# Get latest version
get_latest_version() {
  latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r .tag_name 2>/dev/null)
  if [[ "$latest_version" == "null" ]] || [[ -z "$latest_version" ]]; then
    echo -e "${YELLOW_BG}Unable to fetch latest version from GitHub. Using fallback.${NORMAL}"
    echo "app/v2.6.5"
  else
    echo "$latest_version"
  fi
}

# Download Hysteria 2 Core
download_hy2_core() {
  mkdir -p /opt/skim-hy2/
  url="https://github.com/apernet/hysteria/releases/download/${version}/hysteria-linux-${arch}"
  echo -e "${GREEN_BG}Downloading ${url}...${NORMAL}"
  if ! curl -s -L -o /opt/skim-hy2/hy2 "$url"; then
    echo -e "${RED_BG}Download failed. Please check your network.${NORMAL}"
    exit 1
  fi
  chmod +x /opt/skim-hy2/hy2
  echo -e "${GREEN_BG}hy2 core installed to /opt/skim-hy2/${NORMAL}"
}

# Set version
if [ -z "$2" ] || [ "$2" = "auto" ]; then
  version=$(get_latest_version)
else
  version="$2"
fi

# Check existing version
if [[ -x "/opt/skim-hy2/hy2" ]]; then
    installed_version=$("/opt/skim-hy2/hy2" version 2>/dev/null | grep -i '^Version:' | awk '{print $2}')
    if [[ "app/$installed_version" == "$version" ]]; then
        echo -e "${GREEN_BG}[Requirements] Hysteria 2 core ${version} is already installed. Skipping download.${NORMAL}"
    else
        echo -e "${GREEN_BG}[Requirements] Installed version ($installed_version) differs from requested ($version). Updating...${NORMAL}"
        download_hy2_core
    fi
else
    echo -e "${GREEN_BG}[Requirements] Hysteria 2 core not found. Proceeding with installation...${NORMAL}"
    download_hy2_core
fi

# Get IP address
if [ -z "$3" ] || [ "$3" = "auto" ]; then
  ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -4 | grep -oP '(?<=ip=).*' 2>/dev/null)
  if [ -z "$ip" ]; then
    ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -6 | grep -oP '(?<=ip=).*' 2>/dev/null)
  fi
  if echo "$ip" | grep -q ':'; then
    ip="[$ip]"
  fi
  if [ -z "$ip" ]; then
    echo -e "${YELLOW_BG}Unable to detect IP automatically. Please enter manually:${NORMAL}"
    read -p "Server IP: " ip
  fi
else 
  ip=$3
fi

# Use fixed port and password
port="${1:-$DEFAULT_PORT}"
password="$DEFAULT_PASSWORD"

# Check port conflict
if ss -tulnp 2>/dev/null | grep -q ":$port "; then
  echo -e "${RED_BG}[ERROR] Port $port is already in use:${NORMAL}"
  ss -tulnp | grep ":$port "
  echo ""
  echo -e "${YELLOW_BG}Please stop the existing service or choose another port.${NORMAL}"
  exit 1
fi

# Make config folder
mkdir -p /opt/skim-hy2/$port

# Self-sign certificate (Apple domain)
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
OU                     = Apple CDN
CN                     = ${SNI_DOMAIN}

[ v3_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${SNI_DOMAIN}
DNS.2 = *.${SNI_DOMAIN}
EOF

openssl req -x509 -new -nodes -days 36500 \
  -keyout /opt/skim-hy2/$port/server.key \
  -out /opt/skim-hy2/$port/server.crt \
  -config /opt/skim-hy2/$port/openssl.conf \
  > /dev/null 2>&1

chmod 600 /opt/skim-hy2/$port/server.key
chmod 644 /opt/skim-hy2/$port/server.crt

# Print config info
echo -e "${GREEN_BG}Using address${NORMAL}: $ip:$port"
echo -e "${GREEN_BG}Using password${NORMAL}: $password"
echo -e "${GREEN_BG}Using SNI${NORMAL}: ${SNI_DOMAIN}"
echo -e "${GREEN_BG}Server CA SHA256${NORMAL}: $(openssl x509 -noout -fingerprint -sha256 -in /opt/skim-hy2/$port/server.crt | cut -d'=' -f2)"

# Create enhanced hy2 config with unlimited bandwidth
cat <<EOF > /opt/skim-hy2/$port/config.yaml
listen: :${port}

tls:
  cert: /opt/skim-hy2/${port}/server.crt
  key: /opt/skim-hy2/${port}/server.key

auth:
  type: password
  password: ${password}

bandwidth:
  up: 0
  down: 0

quic:
  initStreamReceiveWindow: 33554432
  maxStreamReceiveWindow: 33554432
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 60s
  maxIncomingStreams: 2048
  disablePathMTUDiscovery: false

ignoreClientBandwidth: true
disableUDP: false
udpIdleTimeout: 60s

speedTest: false

masquerade:
  type: proxy
  proxy:
    url: https://www.apple.com
    rewriteHost: true
EOF

# Apply BBR optimization (silent check)
apply_bbr() {
  current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  
  if [[ "$current_cc" == "bbr" ]]; then
    echo -e "${GREEN_BG}[Optimization] BBR is already enabled${NORMAL}"
    return 0
  fi
  
  echo -e "${GREEN_BG}[Optimization] Applying BBR + network optimizations...${NORMAL}"
  
  if ! grep -q "Hysteria2 Network Optimization" /etc/sysctl.conf 2>/dev/null; then
    cat >> /etc/sysctl.conf <<EOF

# ============================================
# Hysteria2 Network Optimization
# Hostname: ${HOSTNAME}
# Date: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================

# BBR Congestion Control
net.core.default_qdisc=fq_pie
net.ipv4.tcp_congestion_control=bbr

# Network Buffer (64MB)
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.rmem_default=16777216
net.core.wmem_default=16777216
net.ipv4.tcp_rmem=4096 16777216 67108864
net.ipv4.tcp_wmem=4096 16777216 67108864

# UDP Buffer
net.core.netdev_max_backlog=16384
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192

# Connection Tracking
net.netfilter.nf_conntrack_max=1000000
net.nf_conntrack_max=1000000

# TCP Optimization
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_fin_timeout=15

# File Descriptors
fs.file-max=1048576

EOF
  fi
  
  sysctl -p > /dev/null 2>&1
  
  if ! grep -q "Hysteria2 Optimization" /etc/security/limits.conf 2>/dev/null; then
    cat >> /etc/security/limits.conf <<EOF

# Hysteria2 Optimization
* soft nofile 1048576
* hard nofile 1048576

EOF
  fi
  
  echo -e "${GREEN_BG}[Optimization] Network optimization applied${NORMAL}"
}

apply_bbr

# Create system service
echo -e "${GREEN_BG}Installing system service...${NORMAL}"
init_system=$(cat /proc/1/comm)

if [[ "$init_system" == "systemd" ]]; then
  cat <<EOF > /etc/systemd/system/hy2-${port}.service
[Unit]
Description=Hysteria 2 Server (${HOSTNAME} - Port ${port})
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment="HYSTERIA_LOG_LEVEL=info"
ExecStart=/opt/skim-hy2/hy2 server -c /opt/skim-hy2/${port}/config.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576
StandardOutput=append:/var/log/hy2-${port}.log
StandardError=append:/var/log/hy2-${port}.log

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hy2-${port} > /dev/null 2>&1
  systemctl start hy2-${port}
  
  # Wait and check service status
  sleep 2
  
  if systemctl is-active --quiet hy2-${port}; then
    echo -e "${GREEN_BG}[Service] hy2-${port} started successfully${NORMAL}"
  else
    echo -e "${RED_BG}[ERROR] Service failed to start. Checking logs...${NORMAL}"
    journalctl -u hy2-${port} -n 20 --no-pager
    echo ""
    echo -e "${YELLOW_BG}Trying manual start for debugging:${NORMAL}"
    /opt/skim-hy2/hy2 server -c /opt/skim-hy2/${port}/config.yaml &
    sleep 2
    if ps aux | grep -v grep | grep -q "hy2 server"; then
      echo -e "${GREEN_BG}Manual start successful. Killing and restarting service...${NORMAL}"
      pkill -f "hy2 server"
      systemctl restart hy2-${port}
      sleep 2
    fi
  fi
  
  echo -e "${WHITE_BG}TO REMOVE THIS SERVICE:${NORMAL} systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf /opt/skim-hy2/$port"

elif [[ "$init_system" == "init" || "$init_system" == "openrc" ]]; then
  cat <<EOF > /etc/init.d/hy2-${port}
#!/sbin/openrc-run

name="Hysteria 2 Server (${HOSTNAME} - Port ${port})"
description="Hysteria 2 server on :${port}"
command="/opt/skim-hy2/hy2"
command_args="server -c /opt/skim-hy2/${port}/config.yaml"
pidfile="/var/run/hy2-${port}.pid"
logfile="/var/log/hy2-${port}.log"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting \$name"
    start-stop-daemon --start --background --make-pidfile --pidfile \$pidfile --exec \$command -- \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping \$name"
    start-stop-daemon --stop --pidfile \$pidfile
    eend \$?
}

restart() {
    stop
    start
}
EOF

  chmod +x /etc/init.d/hy2-${port}
  rc-update add hy2-${port} default
  rc-service hy2-${port} start
  echo -e "${WHITE_BG}TO REMOVE THIS SERVICE:${NORMAL} rc-update del hy2-${port} default && rc-service hy2-${port} stop && rm /etc/init.d/hy2-${port} && rm -rf /opt/skim-hy2/$port"

else
  echo -e "${RED_BG}Unsupported init system: $init_system.${NORMAL}"
  exit 1
fi

# Generate share links (fixed for v2rayN)
# Use hysteria2:// instead of hy2://
hy2_url="hysteria2://$(urlencode "$password")@${ip}:${port}/?insecure=1&sni=${SNI_DOMAIN}&alpn=h3#$(urlencode "${HOSTNAME}-HY2-${port}")"

# Also generate hy2:// for compatibility
hy2_url_compat="hy2://$(urlencode "$password")@${ip}:${port}/?insecure=1&sni=${SNI_DOMAIN}#$(urlencode "${HOSTNAME}-HY2-${port}")"

json_config=$(cat <<EOF
{
  "type": "hysteria2",
  "tag": "${HOSTNAME}-HY2-${port}",
  "server": "${ip}",
  "server_port": ${port},
  "password": "${password}",
  "tls": {
    "enabled": true,
    "server_name": "${SNI_DOMAIN}",
    "insecure": true,
    "alpn": ["h3"]
  }
}
EOF
)

clash_config=$(cat <<EOF
- name: ${HOSTNAME}-HY2-${port}
  type: hysteria2
  server: ${ip}
  port: ${port}
  password: ${password}
  skip-cert-verify: true
  sni: ${SNI_DOMAIN}
  alpn:
    - h3
EOF
)

# Display results
echo ""
echo -e "${BLUE_BG}========================================${NORMAL}"
echo -e "${BLUE_BG}  🎉 Hysteria2 Installation Complete${NORMAL}"
echo -e "${BLUE_BG}========================================${NORMAL}"
echo ""
echo -e "${GREEN_BG}Hostname:${NORMAL} ${HOSTNAME}"
echo -e "${GREEN_BG}Server:${NORMAL} ${ip}:${port}"
echo -e "${GREEN_BG}Password:${NORMAL} ${password}"
echo -e "${GREEN_BG}SNI:${NORMAL} ${SNI_DOMAIN}"
echo -e "${GREEN_BG}Bandwidth:${NORMAL} Unlimited (auto-negotiated)"
echo ""
echo -e "${GREEN_BG}Hysteria2 URL (v2rayN):${NORMAL}"
echo "$hy2_url"
echo ""
echo -e "${GREEN_BG}Hysteria2 URL (兼容格式):${NORMAL}"
echo "$hy2_url_compat"
echo ""
echo -e "${GREEN_BG}Sing-box JSON:${NORMAL}"
echo "$json_config"
echo ""
echo -e "${GREEN_BG}Clash Meta YAML:${NORMAL}"
echo "$clash_config"
echo ""
echo -e "${WHITE_BG}Management Commands:${NORMAL}"
echo "  Start:   systemctl start hy2-${port}"
echo "  Stop:    systemctl stop hy2-${port}"
echo "  Status:  systemctl status hy2-${port}"
echo "  Logs:    journalctl -u hy2-${port} -f"
echo ""

# Save config to file
cat > /opt/skim-hy2/$port/client-config.txt <<EOF
========================================
Hysteria2 客户端配置
主机名: ${HOSTNAME}
服务器: ${ip}:${port}
密码: ${password}
SNI: ${SNI_DOMAIN}
带宽: 无限制 (自动协商)
========================================

【Hysteria2 链接 - v2rayN 专用】
${hy2_url}

【Hysteria2 链接 - 兼容格式】
${hy2_url_compat}

【Sing-box 配置】
${json_config}

【Clash Meta 配置】
${clash_config}

========================================
v2rayN 手动配置方法:
1. 打开 v2rayN → 服务器 → 添加 Hysteria2 服务器
2. 填写以下信息：
   - 地址: ${ip}
   - 端口: ${port}
   - 密码: ${password}
   - SNI: ${SNI_DOMAIN}
   - ALPN: h3
   - 跳过证书验证: 勾选

管理命令:
- 启动: systemctl start hy2-${port}
- 停止: systemctl stop hy2-${port}
- 状态: systemctl status hy2-${port}
- 日志: journalctl -u hy2-${port} -f

卸载命令:
systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf /opt/skim-hy2/${port}
========================================
EOF

# Push to Telegram with Chinese comments
telegram_message=$(cat <<EOF
🚀 *Hysteria2 服务器部署成功*

━━━━━━━━━━━━━━━━━━━━
📡 *服务器信息*
━━━━━━━━━━━━━━━━━━━━
• 主机名: \`${HOSTNAME}\`
• 服务器IP: \`${ip}\`
• 端口: \`${port}\`
• 密码: \`${password}\`
• SNI伪装域名: \`${SNI_DOMAIN}\`
• 带宽模式: 无限制 (自动协商)

━━━━━━━━━━━━━━━━━━━━
🔗 *分享链接（v2rayN专用）*
━━━━━━━━━━━━━━━━━━━━
\`${hy2_url}\`

━━━━━━━━━━━━━━━━━━━━
📱 *Sing-box 配置*
━━━━━━━━━━━━━━━━━━━━
\`\`\`json
${json_config}
\`\`\`

━━━━━━━━━━━━━━━━━━━━
📱 *Clash Meta 配置*
━━━━━━━━━━━━━━━━━━━━
\`\`\`yaml
${clash_config}
\`\`\`

━━━━━━━━━━━━━━━━━━━━
⚙️ *性能优化项目*
━━━━━━━━━━━━━━━━━━━━
✅ BBR 拥塞控制算法
✅ 64MB TCP/UDP 缓冲区
✅ 100万 连接追踪上限
✅ 32MB QUIC 接收窗口
✅ 2048 并发流数量

━━━━━━━━━━━━━━━━━━━━
📊 *预期性能指标*
━━━━━━━━━━━━━━━━━━━━
• YouTube 8K: 流畅播放
• 延迟 (东京-香港): 40-60ms
• 支持设备数: 20-50 台
• 峰值带宽: 1500-2500 Mbps

━━━━━━━━━━━━━━━━━━━━
💡 *v2rayN 使用提示*
━━━━━━━━━━━━━━━━━━━━
1. 直接复制上方分享链接导入
2. 或手动添加服务器：
   地址: \`${ip}\`
   端口: \`${port}\`
   密码: \`${password}\`
   SNI: \`${SNI_DOMAIN}\`
   ALPN: \`h3\`
   跳过证书验证: 勾选

⏰ 部署时间: $(date '+%Y-%m-%d %H:%M:%S')
🏷️ 服务器标识: ${HOSTNAME}
EOF
)

send_telegram "$telegram_message"

echo -e "${GREEN_BG}========================================${NORMAL}"
echo -e "${GREEN_BG}✅ 配置已保存到:${NORMAL}"
echo -e "${GREEN_BG}   /opt/skim-hy2/${port}/client-config.txt${NORMAL}"
echo -e "${GREEN_BG}========================================${NORMAL}"
echo ""#!/bin/bash

# ========================================
# Hysteria2 Enhanced Edition
# Version: 8.0.0 - Based on SkimProxy.sh
# Date: 2025-12-15
# ========================================

GREEN_BG='\033[42;30m'
RED_BG='\033[41;97m'
YELLOW_BG='\033[43;30m'
WHITE_BG='\033[47;30m'
BLUE_BG='\033[44;97m'
NORMAL='\033[0m'

# ========================================
# Configuration
# ========================================
HOSTNAME="ip-172-31-3-171"
BOT_TOKEN="7808383148:AAF5LglthZukCj6eqbA0rEbJZQMAjlk--I0"
CHAT_ID="-1002145386723"
DEFAULT_PORT="52015"
DEFAULT_PASSWORD="Aq112211!"
SNI_DOMAIN="icloud.cdn-apple.com"

# Check root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED_BG}This script requires root privileges.${NORMAL} Please run as root or use sudo."
  exit 1
fi

# Detect CPU architecture
cpu_arch=$(uname -m)
case "$cpu_arch" in
  x86_64) arch="amd64" ;;
  aarch64) arch="arm64" ;;
  armv7l) arch="arm" ;;
  *) echo -e "${RED_BG}Unsupported architecture: $cpu_arch${NORMAL}"; exit 1 ;;
esac

# Install GNU grep if BusyBox ver grep found
is_busybox_grep() {
  grep --version 2>&1 | grep -q BusyBox
}
if is_busybox_grep; then
  echo -e "${GREEN_BG}[Requirements] BusyBox grep detected. Installing GNU grep.${NORMAL}"
  if command -v apk >/dev/null; then
    apk add grep
  elif command -v apt-get >/dev/null; then
    apt-get update && apt-get install -y grep
  elif command -v pacman >/dev/null; then
    pacman -Sy --noconfirm grep
  else
    echo -e "${RED_BG}[ERROR] Unsupported package manager.${NORMAL} Please install GNU grep manually."
    exit 1
  fi
fi

# URL encode function
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

# Telegram push function
send_telegram() {
    local message="$1"
    local api_url="https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"
    
    # Escape special characters for JSON
    local escaped_message=$(echo "$message" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
    
    local response=$(curl -s -X POST "$api_url" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\": \"${CHAT_ID}\", \"text\": \"${escaped_message}\", \"parse_mode\": \"Markdown\", \"disable_web_page_preview\": true}" 2>/dev/null)
    
    if echo "$response" | grep -q '"ok":true'; then
        echo -e "${GREEN_BG}✅ Configuration pushed to Telegram${NORMAL}"
        return 0
    else
        echo -e "${YELLOW_BG}⚠️  Telegram push failed (network issue, service continues)${NORMAL}"
        return 1
    fi
}

# Install packages function
install_packages() {
  if command -v apk &> /dev/null; then
    apk update && apk add curl jq tar openssl xz
  elif command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y curl jq tar openssl xz-utils
  elif command -v pacman &> /dev/null; then
    pacman -Syu --noconfirm curl jq tar openssl xz
  elif command -v dnf &> /dev/null; then
    dnf install -y curl jq tar openssl xz
  elif command -v zypper &> /dev/null; then
    zypper install -y curl jq tar openssl xz
  elif command -v yum &> /dev/null; then
    yum install -y curl jq tar openssl xz
  else
    echo -e "${RED_BG}[ERROR] Unsupported package manager.${NORMAL} Please install curl, jq, tar, and openssl manually."
    exit 1
  fi
}

# Install required tools if missing
for tool in curl jq tar openssl xz; do
  if ! command -v "$tool" &> /dev/null; then
    echo -e "${GREEN_BG}[Requirements] Installing missing dependencies...${NORMAL}"
    install_packages
    break
  fi
done

# Get latest version
get_latest_version() {
  latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r .tag_name 2>/dev/null)
  if [[ "$latest_version" == "null" ]] || [[ -z "$latest_version" ]]; then
    echo -e "${YELLOW_BG}Unable to fetch latest version from GitHub. Using fallback.${NORMAL}"
    echo "app/v2.6.5"
  else
    echo "$latest_version"
  fi
}

# Download Hysteria 2 Core
download_hy2_core() {
  mkdir -p /opt/skim-hy2/
  url="https://github.com/apernet/hysteria/releases/download/${version}/hysteria-linux-${arch}"
  echo -e "${GREEN_BG}Downloading ${url}...${NORMAL}"
  if ! curl -s -L -o /opt/skim-hy2/hy2 "$url"; then
    echo -e "${RED_BG}Download failed. Please check your network.${NORMAL}"
    exit 1
  fi
  chmod +x /opt/skim-hy2/hy2
  echo -e "${GREEN_BG}hy2 core installed to /opt/skim-hy2/${NORMAL}"
}

# Set version
if [ -z "$2" ] || [ "$2" = "auto" ]; then
  version=$(get_latest_version)
else
  version="$2"
fi

# Check existing version
if [[ -x "/opt/skim-hy2/hy2" ]]; then
    installed_version=$("/opt/skim-hy2/hy2" version 2>/dev/null | grep -i '^Version:' | awk '{print $2}')
    if [[ "app/$installed_version" == "$version" ]]; then
        echo -e "${GREEN_BG}[Requirements] Hysteria 2 core ${version} is already installed. Skipping download.${NORMAL}"
    else
        echo -e "${GREEN_BG}[Requirements] Installed version ($installed_version) differs from requested ($version). Updating...${NORMAL}"
        download_hy2_core
    fi
else
    echo -e "${GREEN_BG}[Requirements] Hysteria 2 core not found. Proceeding with installation...${NORMAL}"
    download_hy2_core
fi

# Get IP address
if [ -z "$3" ] || [ "$3" = "auto" ]; then
  ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -4 | grep -oP '(?<=ip=).*' 2>/dev/null)
  if [ -z "$ip" ]; then
    ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -6 | grep -oP '(?<=ip=).*' 2>/dev/null)
  fi
  if echo "$ip" | grep -q ':'; then
    ip="[$ip]"
  fi
  if [ -z "$ip" ]; then
    echo -e "${YELLOW_BG}Unable to detect IP automatically. Please enter manually:${NORMAL}"
    read -p "Server IP: " ip
  fi
else 
  ip=$3
fi

# Use fixed port and password
port="${1:-$DEFAULT_PORT}"
password="$DEFAULT_PASSWORD"

# Check port conflict
if ss -tulnp 2>/dev/null | grep -q ":$port "; then
  echo -e "${RED_BG}[ERROR] Port $port is already in use:${NORMAL}"
  ss -tulnp | grep ":$port "
  echo ""
  echo -e "${YELLOW_BG}Please stop the existing service or choose another port.${NORMAL}"
  exit 1
fi

# Make config folder
mkdir -p /opt/skim-hy2/$port

# Self-sign certificate (Apple domain)
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
OU                     = Apple CDN
CN                     = ${SNI_DOMAIN}

[ v3_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${SNI_DOMAIN}
DNS.2 = *.${SNI_DOMAIN}
EOF

openssl req -x509 -new -nodes -days 36500 \
  -keyout /opt/skim-hy2/$port/server.key \
  -out /opt/skim-hy2/$port/server.crt \
  -config /opt/skim-hy2/$port/openssl.conf \
  > /dev/null 2>&1

chmod 600 /opt/skim-hy2/$port/server.key
chmod 644 /opt/skim-hy2/$port/server.crt

# Print config info
echo -e "${GREEN_BG}Using address${NORMAL}: $ip:$port"
echo -e "${GREEN_BG}Using password${NORMAL}: $password"
echo -e "${GREEN_BG}Using SNI${NORMAL}: ${SNI_DOMAIN}"
echo -e "${GREEN_BG}Server CA SHA256${NORMAL}: $(openssl x509 -noout -fingerprint -sha256 -in /opt/skim-hy2/$port/server.crt | cut -d'=' -f2)"

# Create enhanced hy2 config with unlimited bandwidth
cat <<EOF > /opt/skim-hy2/$port/config.yaml
listen: :${port}

tls:
  cert: /opt/skim-hy2/${port}/server.crt
  key: /opt/skim-hy2/${port}/server.key

auth:
  type: password
  password: ${password}

bandwidth:
  up: 0
  down: 0

quic:
  initStreamReceiveWindow: 33554432
  maxStreamReceiveWindow: 33554432
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 60s
  maxIncomingStreams: 2048
  disablePathMTUDiscovery: false

ignoreClientBandwidth: true
disableUDP: false
udpIdleTimeout: 60s

speedTest: false

masquerade:
  type: proxy
  proxy:
    url: https://www.apple.com
    rewriteHost: true
EOF

# Apply BBR optimization (silent check)
apply_bbr() {
  current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  
  if [[ "$current_cc" == "bbr" ]]; then
    echo -e "${GREEN_BG}[Optimization] BBR is already enabled${NORMAL}"
    return 0
  fi
  
  echo -e "${GREEN_BG}[Optimization] Applying BBR + network optimizations...${NORMAL}"
  
  if ! grep -q "Hysteria2 Network Optimization" /etc/sysctl.conf 2>/dev/null; then
    cat >> /etc/sysctl.conf <<EOF

# ============================================
# Hysteria2 Network Optimization
# Hostname: ${HOSTNAME}
# Date: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================

# BBR Congestion Control
net.core.default_qdisc=fq_pie
net.ipv4.tcp_congestion_control=bbr

# Network Buffer (64MB)
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.rmem_default=16777216
net.core.wmem_default=16777216
net.ipv4.tcp_rmem=4096 16777216 67108864
net.ipv4.tcp_wmem=4096 16777216 67108864

# UDP Buffer
net.core.netdev_max_backlog=16384
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192

# Connection Tracking
net.netfilter.nf_conntrack_max=1000000
net.nf_conntrack_max=1000000

# TCP Optimization
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_fin_timeout=15

# File Descriptors
fs.file-max=1048576

EOF
  fi
  
  sysctl -p > /dev/null 2>&1
  
  if ! grep -q "Hysteria2 Optimization" /etc/security/limits.conf 2>/dev/null; then
    cat >> /etc/security/limits.conf <<EOF

# Hysteria2 Optimization
* soft nofile 1048576
* hard nofile 1048576

EOF
  fi
  
  echo -e "${GREEN_BG}[Optimization] Network optimization applied${NORMAL}"
}

apply_bbr

# Create system service
echo -e "${GREEN_BG}Installing system service...${NORMAL}"
init_system=$(cat /proc/1/comm)

if [[ "$init_system" == "systemd" ]]; then
  cat <<EOF > /etc/systemd/system/hy2-${port}.service
[Unit]
Description=Hysteria 2 Server (${HOSTNAME} - Port ${port})
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment="HYSTERIA_LOG_LEVEL=info"
ExecStart=/opt/skim-hy2/hy2 server -c /opt/skim-hy2/${port}/config.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576
StandardOutput=append:/var/log/hy2-${port}.log
StandardError=append:/var/log/hy2-${port}.log

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hy2-${port} > /dev/null 2>&1
  systemctl start hy2-${port}
  
  # Wait and check service status
  sleep 2
  
  if systemctl is-active --quiet hy2-${port}; then
    echo -e "${GREEN_BG}[Service] hy2-${port} started successfully${NORMAL}"
  else
    echo -e "${RED_BG}[ERROR] Service failed to start. Checking logs...${NORMAL}"
    journalctl -u hy2-${port} -n 20 --no-pager
    echo ""
    echo -e "${YELLOW_BG}Trying manual start for debugging:${NORMAL}"
    /opt/skim-hy2/hy2 server -c /opt/skim-hy2/${port}/config.yaml &
    sleep 2
    if ps aux | grep -v grep | grep -q "hy2 server"; then
      echo -e "${GREEN_BG}Manual start successful. Killing and restarting service...${NORMAL}"
      pkill -f "hy2 server"
      systemctl restart hy2-${port}
      sleep 2
    fi
  fi
  
  echo -e "${WHITE_BG}TO REMOVE THIS SERVICE:${NORMAL} systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf /opt/skim-hy2/$port"

elif [[ "$init_system" == "init" || "$init_system" == "openrc" ]]; then
  cat <<EOF > /etc/init.d/hy2-${port}
#!/sbin/openrc-run

name="Hysteria 2 Server (${HOSTNAME} - Port ${port})"
description="Hysteria 2 server on :${port}"
command="/opt/skim-hy2/hy2"
command_args="server -c /opt/skim-hy2/${port}/config.yaml"
pidfile="/var/run/hy2-${port}.pid"
logfile="/var/log/hy2-${port}.log"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting \$name"
    start-stop-daemon --start --background --make-pidfile --pidfile \$pidfile --exec \$command -- \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping \$name"
    start-stop-daemon --stop --pidfile \$pidfile
    eend \$?
}

restart() {
    stop
    start
}
EOF

  chmod +x /etc/init.d/hy2-${port}
  rc-update add hy2-${port} default
  rc-service hy2-${port} start
  echo -e "${WHITE_BG}TO REMOVE THIS SERVICE:${NORMAL} rc-update del hy2-${port} default && rc-service hy2-${port} stop && rm /etc/init.d/hy2-${port} && rm -rf /opt/skim-hy2/$port"

else
  echo -e "${RED_BG}Unsupported init system: $init_system.${NORMAL}"
  exit 1
fi

# Generate share links
hy2_url="hy2://$(urlencode "$password")@${ip}:${port}/?insecure=1&sni=${SNI_DOMAIN}#$(urlencode "${HOSTNAME}-HY2-${port}")"

json_config=$(cat <<EOF
{
  "type": "hysteria2",
  "tag": "${HOSTNAME}-HY2-${port}",
  "server": "${ip}",
  "server_port": ${port},
  "password": "${password}",
  "tls": {
    "enabled": true,
    "server_name": "${SNI_DOMAIN}",
    "insecure": true,
    "alpn": ["h3"]
  }
}
EOF
)

clash_config=$(cat <<EOF
- name: ${HOSTNAME}-HY2-${port}
  type: hysteria2
  server: ${ip}
  port: ${port}
  password: ${password}
  skip-cert-verify: true
  sni: ${SNI_DOMAIN}
  alpn:
    - h3
EOF
)

# Display results
echo ""
echo -e "${BLUE_BG}========================================${NORMAL}"
echo -e "${BLUE_BG}  🎉 Hysteria2 Installation Complete${NORMAL}"
echo -e "${BLUE_BG}========================================${NORMAL}"
echo ""
echo -e "${GREEN_BG}Hostname:${NORMAL} ${HOSTNAME}"
echo -e "${GREEN_BG}Server:${NORMAL} ${ip}:${port}"
echo -e "${GREEN_BG}Password:${NORMAL} ${password}"
echo -e "${GREEN_BG}SNI:${NORMAL} ${SNI_DOMAIN}"
echo -e "${GREEN_BG}Bandwidth:${NORMAL} Unlimited (auto-negotiated)"
echo ""
echo -e "${GREEN_BG}Hysteria2 URL:${NORMAL}"
echo "$hy2_url"
echo ""
echo -e "${GREEN_BG}Sing-box JSON:${NORMAL}"
echo "$json_config"
echo ""
echo -e "${GREEN_BG}Clash Meta YAML:${NORMAL}"
echo "$clash_config"
echo ""
echo -e "${WHITE_BG}Management Commands:${NORMAL}"
echo "  Start:   systemctl start hy2-${port}"
echo "  Stop:    systemctl stop hy2-${port}"
echo "  Status:  systemctl status hy2-${port}"
echo "  Logs:    journalctl -u hy2-${port} -f"
echo ""

# Save config to file
cat > /opt/skim-hy2/$port/client-config.txt <<EOF
========================================
Hysteria2 Client Configuration
Hostname: ${HOSTNAME}
Server: ${ip}:${port}
Password: ${password}
SNI: ${SNI_DOMAIN}
Bandwidth: Unlimited (auto-negotiated)
========================================

【Hysteria2 URL】
${hy2_url}

【Sing-box JSON】
${json_config}

【Clash Meta YAML】
${clash_config}

========================================
Management Commands:
- Start:   systemctl start hy2-${port}
- Stop:    systemctl stop hy2-${port}
- Status:  systemctl status hy2-${port}
- Logs:    journalctl -u hy2-${port} -f

Uninstall:
systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf /opt/skim-hy2/${port}
========================================
EOF

# Push to Telegram
telegram_message=$(cat <<EOF
🚀 *Hysteria2 Server Deployed*

📡 *Server Info*
• Hostname: \`${HOSTNAME}\`
• IP: \`${ip}\`
• Port: \`${port}\`
• Password: \`${password}\`
• SNI: \`${SNI_DOMAIN}\`
• Bandwidth: Unlimited

🔗 *Share Link*
\`${hy2_url}\`

📱 *Sing-box Config*
\`\`\`json
${json_config}
\`\`\`

📱 *Clash Meta Config*
\`\`\`yaml
${clash_config}
\`\`\`

⚙️ *Optimizations*
✅ BBR enabled
✅ 64MB buffers
✅ 1M connections
✅ 32MB QUIC windows
✅ 2048 concurrent streams

📊 *Expected Performance*
• YouTube 8K: Smooth
• Latency: 40-60ms (Tokyo-HK)
• Devices: 20-50
• Peak: 1500-2500 Mbps

⏰ Deployed: $(date '+%Y-%m-%d %H:%M:%S')
EOF
)

send_telegram "$telegram_message"

echo -e "${GREEN_BG}========================================${NORMAL}"
echo -e "${GREEN_BG}✅ Configuration saved to:${NORMAL}"
echo -e "${GREEN_BG}   /opt/skim-hy2/${port}/client-config.txt${NORMAL}"
echo -e "${GREEN_BG}========================================${NORMAL}"
echo ""
