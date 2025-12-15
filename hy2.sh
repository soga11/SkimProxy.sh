#!/bin/bash

# ========================================
# Hysteria2 Enhanced Edition
# Version: 10.0.0 - IPv6 支持 + 地区识别
# Date: 2025-12-15
# ========================================

GREEN_BG='\033[42;30m'
RED_BG='\033[41;97m'
YELLOW_BG='\033[43;30m'
WHITE_BG='\033[47;30m'
BLUE_BG='\033[44;97m'
CYAN_BG='\033[46;30m'
NORMAL='\033[0m'

# ========================================
# Configuration - 自动获取主机名和地区
# ========================================
HOSTNAME=$(hostname)

# 获取服务器地区信息
get_server_region() {
  local region=$(curl -s --max-time 5 https://ipinfo.io/region 2>/dev/null)
  local city=$(curl -s --max-time 5 https://ipinfo.io/city 2>/dev/null)
  local country=$(curl -s --max-time 5 https://ipinfo.io/country 2>/dev/null)
  
  if [ -n "$city" ] && [ -n "$country" ]; then
    echo "${city}, ${country}"
  elif [ -n "$region" ]; then
    echo "$region"
  elif [ -n "$country" ]; then
    echo "$country"
  else
    # 备用方案：通过 CloudFlare 获取
    local cf_colo=$(curl -s --max-time 5 https://www.cloudflare.com/cdn-cgi/trace | grep -oP '(?<=colo=)[A-Z]{3}')
    if [ -n "$cf_colo" ]; then
      echo "$cf_colo"
    else
      echo "Unknown"
    fi
  fi
}

REGION=$(get_server_region)

BOT_TOKEN="7328117252:AAEvFsK0Q9AnckZWvuvZ8lkdx0EDD867x94"
CHAT_ID="-1002347364775"
DEFAULT_PORT="52015"
DEFAULT_PASSWORD="Aq112211!"
SNI_DOMAIN="icloud.cdn-apple.com"

# Check root
if [[ $EEID -ne 0 ]]; then
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

# Get IPv4 and IPv6 addresses
get_ip_addresses() {
  # 获取 IPv4
  ipv4=$(curl -s --max-time 5 -4 https://api.ipify.org 2>/dev/null)
  if [ -z "$ipv4" ]; then
    ipv4=$(curl -s --max-time 5 https://cloudflare.com/cdn-cgi/trace -4 | grep -oP '(?<=ip=).*' 2>/dev/null)
  fi
  
  # 获取 IPv6
  ipv6=$(curl -s --max-time 5 -6 https://api64.ipify.org 2>/dev/null)
  if [ -z "$ipv6" ]; then
    ipv6=$(curl -s --max-time 5 https://cloudflare.com/cdn-cgi/trace -6 | grep -oP '(?<=ip=).*' 2>/dev/null)
  fi
  
  # 如果没有指定 IP 参数，使用自动检测的 IP
  if [ -z "$3" ] || [ "$3" = "auto" ]; then
    if [ -n "$ipv4" ]; then
      ip="$ipv4"
      echo -e "${GREEN_BG}[Network] Detected IPv4${NORMAL}: $ipv4"
    else
      echo -e "${YELLOW_BG}[Network] IPv4 not detected${NORMAL}"
    fi
    
    if [ -n "$ipv6" ]; then
      echo -e "${CYAN_BG}[Network] Detected IPv6${NORMAL}: $ipv6"
    else
      echo -e "${YELLOW_BG}[Network] IPv6 not detected${NORMAL}"
    fi
  else
    ip="$3"
    echo -e "${GREEN_BG}[Network] Using specified IP${NORMAL}: $ip"
  fi
  
  # 如果 IPv4 和 IPv6 都没有，要求手动输入
  if [ -z "$ip" ]; then
    echo -e "${YELLOW_BG}Unable to detect IP automatically. Please enter manually:${NORMAL}"
    read -p "Server IP: " ip
  fi
}

get_ip_addresses

# Use fixed port and password
port="${1:-$DEFAULT_PORT}"
password="$DEFAULT_PASSWORD"

# Check port conflict
if ss -tulnp 2>/dev/null | grep -q ":$port "; then
  echo -e "${YELLOW_BG}[WARNING] Port $port is already in use. Stopping existing service...${NORMAL}"
  systemctl stop hy2-${port} 2>/dev/null
  sleep 1
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
echo -e "${GREEN_BG}Detected hostname${NORMAL}: $HOSTNAME"
echo -e "${GREEN_BG}Detected region${NORMAL}: $REGION"
echo -e "${GREEN_BG}Using address (IPv4)${NORMAL}: $ip:$port"
if [ -n "$ipv6" ]; then
  echo -e "${CYAN_BG}Using address (IPv6)${NORMAL}: [$ipv6]:$port"
fi
echo -e "${GREEN_BG}Using password${NORMAL}: $password"
echo -e "${GREEN_BG}Using SNI${NORMAL}: ${SNI_DOMAIN}"
echo -e "${GREEN_BG}Server CA SHA256${NORMAL}: $(openssl x509 -noout -fingerprint -sha256 -in /opt/skim-hy2/$port/server.crt | cut -d'=' -f2)"

# Create hy2 config (optimized for v2.6.5)
cat <<EOF > /opt/skim-hy2/$port/config.yaml
listen: :${port}

tls:
  cert: /opt/skim-hy2/${port}/server.crt
  key: /opt/skim-hy2/${port}/server.key

auth:
  type: password
  password: ${password}

quic:
  initStreamReceiveWindow: 33554432
  maxStreamReceiveWindow: 33554432
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 60s
  maxIncomingStreams: 2048
  disablePathMTUDiscovery: false

disableUDP: false
udpIdleTimeout: 60s

speedTest: false

masquerade:
  type: proxy
  proxy:
    url: https://www.apple.com
    rewriteHost: true
EOF

# Apply BBR optimization
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
  
  echo -e "${GREEN_BG
  echo -e "${GREEN_BG}[Optimization] Network optimization applied${NORMAL}"
}

apply_bbr

# Create system service
echo -e "${GREEN_BG}Installing system service...${NORMAL}"

cat > /etc/systemd/system/hy2-${port}.service <<EOF
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
systemctl restart hy2-${port}

# Wait and check service status
sleep 3

if systemctl is-active --quiet hy2-${port}; then
  echo -e "${GREEN_BG}[Service] hy2-${port} started successfully${NORMAL}"
else
  echo -e "${RED_BG}[ERROR] Service failed to start. Showing detailed logs:${NORMAL}"
  echo ""
  journalctl -u hy2-${port} -n 30 --no-pager
  echo ""
  echo -e "${YELLOW_BG}Testing manual start:${NORMAL}"
  /opt/skim-hy2/hy2 server -c /opt/skim-hy2/${port}/config.yaml
  exit 1
fi

# Generate share links (IPv4)
hy2_url_v4="hysteria2://$(urlencode "$password")@${ip}:${port}/?insecure=1&sni=${SNI_DOMAIN}&alpn=h3#$(urlencode "${HOSTNAME}-HY2-${port}")"
hy2_url_compat_v4="hy2://$(urlencode "$password")@${ip}:${port}/?insecure=1&sni=${SNI_DOMAIN}#$(urlencode "${HOSTNAME}-HY2-${port}")"

# Generate share links (IPv6) if available
if [ -n "$ipv6" ]; then
  hy2_url_v6="hysteria2://$(urlencode "$password")@[${ipv6}]:${port}/?insecure=1&sni=${SNI_DOMAIN}&alpn=h3#$(urlencode "${HOSTNAME}-HY2-${port}-IPv6")"
  hy2_url_compat_v6="hy2://$(urlencode "$password")@[${ipv6}]:${port}/?insecure=1&sni=${SNI_DOMAIN}#$(urlencode "${HOSTNAME}-HY2-${port}-IPv6")"
fi

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

# Generate IPv6 JSON config if available
if [ -n "$ipv6" ]; then
  json_config_v6=$(cat <<EOF
{
  "type": "hysteria2",
  "tag": "${HOSTNAME}-HY2-${port}-IPv6",
  "server": "${ipv6}",
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
fi

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

# Generate IPv6 Clash config if available
if [ -n "$ipv6" ]; then
  clash_config_v6=$(cat <<EOF
- name: ${HOSTNAME}-HY2-${port}-IPv6
  type: hysteria2
  server: ${ipv6}
  port: ${port}
  password: ${password}
  skip-cert-verify: true
  sni: ${SNI_DOMAIN}
  alpn:
    - h3
EOF
)
fi

# Display results (v2rayN 链接放最下面)
echo ""
echo -e "${BLUE_BG}========================================${NORMAL}"
echo -e "${BLUE_BG}  🎉 Hysteria2 安装成功${NORMAL}"
echo -e "${BLUE_BG}========================================${NORMAL}"
echo ""
echo -e "${GREEN_BG}主机名:${NORMAL} ${HOSTNAME}"
echo -e "${GREEN_BG}地区:${NORMAL} ${REGION}"
echo -e "${GREEN_BG}服务器 (IPv4):${NORMAL} ${ip}:${port}"
if [ -n "$ipv6" ]; then
  echo -e "${CYAN_BG}服务器 (IPv6):${NORMAL} [${ipv6}]:${port}"
fi
echo -e "${GREEN_BG}密码:${NORMAL} ${password}"
echo -e "${GREEN_BG}SNI:${NORMAL} ${SNI_DOMAIN}"
echo -e "${GREEN_BG}带宽:${NORMAL} 自动协商 (无限制)"
echo ""
echo -e "${GREEN_BG}Sing-box 配置 (IPv4):${NORMAL}"
echo "$json_config"
echo ""
if [ -n "$ipv6" ]; then
  echo -e "${CYAN_BG}Sing-box 配置 (IPv6):${NORMAL}"
  echo "$json_config_v6"
  echo ""
fi
echo -e "${GREEN_BG}Clash Meta 配置 (IPv4):${NORMAL}"
echo "$clash_config"
echo ""
if [ -n "$ipv6" ]; then
  echo -e "${CYAN_BG}Clash Meta 配置 (IPv6):${NORMAL}"
  echo "$clash_config_v6"
  echo ""
fi
echo -e "${WHITE_BG}管理命令:${NORMAL}"
echo "  启动: systemctl start hy2-${port}"
echo "  停止: systemctl stop hy2-${port}"
echo "  状态: systemctl status hy2-${port}"
echo "  日志: journalctl -u hy2-${port} -f"
echo "  卸载: systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf /opt/skim-hy2/${port} && rm -f /var/log/hy2-${port}.log"
echo ""
echo -e "${GREEN_BG}v2rayN 专用链接 (IPv4):${NORMAL}"
echo "$hy2_url_v4"
echo ""
if [ -n "$ipv6" ]; then
  echo -e "${CYAN_BG}v2rayN 专用链接 (IPv6):${NORMAL}"
  echo "$hy2_url_v6"
  echo ""
fi

# Save config to file
cat > /opt/skim-hy2/$port/client-config.txt <<EOF
========================================
Hysteria2 客户端配置
主机名: ${HOSTNAME}
地区: ${REGION}
服务器 (IPv4): ${ip}:${port}
$([ -n "$ipv6" ] && echo "服务器 (IPv6): [${ipv6}]:${port}")
密码: ${password}
SNI: ${SNI_DOMAIN}
带宽: 自动协商 (无限制)
========================================

【Sing-box 配置 - IPv4】
${json_config}

$([ -n "$ipv6" ] && echo "【Sing-box 配置 - IPv6】
${json_config_v6}")

【Clash Meta 配置 - IPv4】
${clash_config}

$([ -n "$ipv6" ] && echo "【Clash Meta 配置 - IPv6】
${clash_config_v6}")

========================================
v2rayN 导入方法:
1. 复制下方链接
2. 在 v2rayN 中按 Ctrl+V 粘贴
3. 或点击"从剪贴板导入批量URL"

手动配置方法:
- 地址: ${ip} $([ -n "$ipv6" ] && echo "或 ${ipv6}")
- 端口: ${port}
- 密码: ${password}
- SNI: ${SNI_DOMAIN}
- ALPN: h3
- 跳过证书验证: 勾选

========================================
管理命令:
- 启动: systemctl start hy2-${port}
- 停止: systemctl stop hy2-${port}
- 状态: systemctl status hy2-${port}
- 日志: journalctl -u hy2-${port} -f
- 卸载: systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf /opt/skim-hy2/${port} && rm -f /var/log/hy2-${port}.log

========================================
【v2rayN 链接 - IPv4】
${hy2_url_v4}

$([ -n "$ipv6" ] && echo "【v2rayN 链接 - IPv6】
${hy2_url_v6}")

【兼容格式链接 - IPv4】
${hy2_url_compat_v4}

$([ -n "$ipv6" ] && echo "【兼容格式链接 - IPv6】
${hy2_url_compat_v6}")
========================================
EOF

# Push to Telegram (v2rayN 链接放最下面)
telegram_message=$(cat <<EOF
🚀 *Hysteria2 服务器部署成功*

━━━━━━━━━━━━━━━━━━━━
📡 *服务器信息*
━━━━━━━━━━━━━━━━━━━━
• 主机名: \`${HOSTNAME}\`
• 地区: \`${REGION}\`
• 服务器IPv4: \`${ip}\`$([ -n "$ipv6" ] && echo "
• 服务器IPv6: \`${ipv6}\`")
• 端口: \`${port}\`
• 密码: \`${password}\`
• SNI伪装: \`${SNI_DOMAIN}\`
• 带宽模式: 自动协商 (无限制)

━━━━━━━━━━━━━━━━━━━━
⚙️ *性能优化*
━━━━━━━━━━━━━━━━━━━━
✅ BBR 拥塞控制
✅ 64MB 网络缓冲区
✅ 100万 连接追踪
✅ 32MB QUIC 窗口
✅ 2048 并发流

━━━━━━━━━━━━━━━━━━━━
📱 *Sing-box 配置 (IPv4)*
━━━━━━━━━━━━━━━━━━━━
\`\`\`json
${json_config}
\`\`\`
$([ -n "$ipv6" ] && echo "
━━━━━━━━━━━━━━━━━━━━
📱 *Sing-box 配置 (IPv6)*
━━━━━━━━━━━━━━━━━━━━
\`\`\`json
${json_config_v6}
\`\`\`")

━━━━━━━━━━━━━━━━━━━━
📱 *Clash Meta 配置 (IPv4)*
━━━━━━━━━━━━━━━━━━━━
\`\`\`yaml
${clash_config}
\`\`\`
$([ -n "$ipv6" ] && echo "
━━━━━━━━━━━━━━━━━━━━
📱 *Clash Meta 配置 (IPv6)*
━━━━━━━━━━━━━━━━━━━━
\`\`\`yaml
${clash_config_v6}
\`\`\`")

━━━━━━━━━━━━━━━━━━━━
💡 *v2rayN 使用提示*
━━━━━━━━━━━━━━━━━━━━
1. 复制下方链接
2. 在 v2rayN 按 Ctrl+V 粘贴
3. 或手动添加服务器

━━━━━━━━━━━━━━━━━━━━
🔗 *v2rayN 导入链接 (IPv4)*
━━━━━━━━━━━━━━━━━━━━
\`${hy2_url_v4}\`
$([ -n "$ipv6" ] && echo "
━━━━━━━━━━━━━━━━━━━━
🔗 *v2rayN 导入链接 (IPv6)*
━━━━━━━━━━━━━━━━━━━━
\`${hy2_url_v6}\`")

⏰ 部署时间: $(date '+%Y-%m-%d %H:%M:%S')
🏷️ 主机标识: ${HOSTNAME}
📍 服务器地区: ${REGION}
EOF
)

send_telegram "$telegram_message"

echo -e "${GREEN_BG}========================================${NORMAL}"
echo -e "${GREEN_BG}✅ 配置已保存到:${NORMAL}"
echo -e "${GREEN_BG}   /opt/skim-hy2/${port}/client-config.txt${NORMAL}"
echo -e "${GREEN_BG}========================================${NORMAL}"
echo ""
