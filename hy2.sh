#!/bin/bash

# ========================================
# Hysteria2 Ultimate Edition
# Version: 7.0.0 - Production Ready
# Date: 2025-12-15
# Author: Enhanced from SkimProxy.sh
# ========================================

# Color System (borrowed from original)
GREEN_BG='\033[42;30m'
RED_BG='\033[41;97m'
YELLOW_BG='\033[43;30m'
WHITE_BG='\033[47;30m'
BLUE_BG='\033[44;97m'
NORMAL='\033[0m'

# Configuration
HOSTNAME="ip-172-31-3-171"
BOT_TOKEN="7808383148:AAF5LglthZukCj6eqbA0rEbJZQMAjlk--I0"
CHAT_ID="-1002145386723"
INSTALL_DIR="/opt/skim-hy2"
SNI_DOMAIN="icloud.cdn-apple.com"

# Helper Functions
log_info() {
    echo -e "${GREEN_BG}[INFO]${NORMAL} $1"
}

log_success() {
    echo -e "${GREEN_BG}$1${NORMAL}"
}

log_warn() {
    echo -e "${YELLOW_BG}[WARN]${NORMAL} $1"
}

log_error() {
    echo -e "${RED_BG}[ERROR]${NORMAL} $1"
}

log_important() {
    echo -e "${WHITE_BG}$1${NORMAL}"
}

# URL Encode Function (from original)
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

# Telegram Push Function
send_telegram() {
    local message="$1"
    local api_url="https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"
    
    local escaped_message=$(echo -e "$message" | sed 's/"/\\"/g' | awk '{printf "%s\\n", $0}')
    
    local response=$(curl -s -X POST "$api_url" \
        -H "Content-Type: application/json" \
        -d "{
            \"chat_id\": \"${CHAT_ID}\",
            \"text\": \"${escaped_message}\",
            \"parse_mode\": \"Markdown\",
            \"disable_web_page_preview\": true
        }")
    
    if echo "$response" | grep -q '"ok":true'; then
        log_success "✅ 配置已推送到 Telegram"
        return 0
    else
        log_warn "⚠️ Telegram 推送失败（可能是网络问题，不影响服务运行）"
        return 1
    fi
}

# Check Root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges. Please run as root or use sudo."
        exit 1
    fi
}

# Detect CPU Architecture
detect_arch() {
    cpu_arch=$(uname -m)
    case "$cpu_arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l) arch="arm" ;;
        *) 
            log_error "Unsupported architecture: $cpu_arch"
            exit 1
            ;;
    esac
    log_info "CPU Architecture: $cpu_arch → $arch"
}

# BusyBox Grep Compatibility (from original)
check_grep() {
    if grep --version 2>&1 | grep -q BusyBox; then
        log_warn "BusyBox grep detected. Installing GNU grep..."
        
        if command -v apk >/dev/null; then
            apk add grep
        elif command -v apt-get >/dev/null; then
            apt-get update && apt-get install -y grep
        elif command -v pacman >/dev/null; then
            pacman -Sy --noconfirm grep
        else
            log_error "Unsupported package manager. Please install GNU grep manually."
            exit 1
        fi
        
        log_success "✅ GNU grep installed"
    fi
}

# Install Dependencies
install_packages() {
    local missing_tools=()
    for tool in curl jq tar openssl xz; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -eq 0 ]; then
        log_info "All dependencies are already installed"
        return 0
    fi
    
    log_info "Installing missing dependencies: ${missing_tools[*]}"
    
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
        log_error "Unsupported package manager. Please install dependencies manually."
        exit 1
    fi
    
    log_success "✅ Dependencies installed"
}

# Get Latest Version
get_latest_version() {
    local latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r .tag_name)
    if [[ "$latest_version" == "null" ]] || [[ -z "$latest_version" ]]; then
        log_warn "Unable to fetch latest version, using fallback: app/v2.6.5"
        echo "app/v2.6.5"
    else
        echo "$latest_version"
    fi
}

# Download Hysteria2 Core (with version check from original)
download_hy2_core() {
    local version="$1"
    
    mkdir -p "$INSTALL_DIR"
    
    # Check existing version
    if [[ -x "$INSTALL_DIR/hy2" ]]; then
        local installed_version=$("$INSTALL_DIR/hy2" version 2>/dev/null | grep -i '^Version:' | awk '{print $2}')
        if [[ "app/$installed_version" == "$version" ]]; then
            log_success "✅ Hysteria2 ${version} is already installed. Skipping download."
            return 0
        else
            log_info "Installed version (app/$installed_version) differs from requested ($version). Updating..."
        fi
    fi
    
    local url="https://github.com/apernet/hysteria/releases/download/${version}/hysteria-linux-${arch}"
    
    log_info "Downloading from: $url"
    
    if ! curl -s -L -o "$INSTALL_DIR/hy2" "$url"; then
        log_error "Download failed"
        exit 1
    fi
    
    chmod +x "$INSTALL_DIR/hy2"
    log_success "✅ Hysteria2 core installed to $INSTALL_DIR"
}

# Get Server IP (from original)
get_server_ip() {
    local ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -4 | grep -oP '(?<=ip=).*')
    if [ -z "$ip" ]; then
        ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -6 | grep -oP '(?<=ip=).*')
    fi
    if echo "$ip" | grep -q ':'; then
        ip="[$ip]"
    fi
    
    if [ -z "$ip" ]; then
        log_warn "Unable to auto-detect IP. Please enter manually:"
        read -p "Server IP: " ip
    fi
    
    echo "$ip"
}

# Check Port Conflict
check_port_conflict() {
    local port="$1"
    
    if ss -tulnp 2>/dev/null | grep -q ":$port "; then
        log_error "Port $port is already in use:"
        ss -tulnp | grep ":$port "
        return 1
    fi
    
    if [[ -f "/etc/systemd/system/hy2-${port}.service" ]]; then
        log_warn "Service hy2-${port} already exists"
        return 1
    fi
    
    return 0
}

# Generate Certificate
generate_cert() {
    local port="$1"
    local cert_dir="$INSTALL_DIR/$port"
    
    mkdir -p "$cert_dir"
    
    log_info "Generating self-signed certificate (SNI: ${SNI_DOMAIN})..."
    
    cat > "$cert_dir/openssl.conf" <<EOF
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
        -keyout "$cert_dir/server.key" \
        -out "$cert_dir/server.crt" \
        -config "$cert_dir/openssl.conf" \
        > /dev/null 2>&1
    
    chmod 600 "$cert_dir/server.key"
    chmod 644 "$cert_dir/server.crt"
    
    local fingerprint=$(openssl x509 -noout -fingerprint -sha256 -in "$cert_dir/server.crt" | cut -d'=' -f2)
    
    log_success "✅ Certificate generated"
    log_info "SHA256 Fingerprint: $fingerprint"
}

# Create Configuration
create_config() {
    local port="$1"
    local password="$2"
    local config_dir="$INSTALL_DIR/$port"
    
    cat > "$config_dir/config.yaml" <<EOF
listen: :${port}

tls:
  cert: ${config_dir}/server.crt
  key: ${config_dir}/server.key

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
    
    log_success "✅ Configuration file created"
}

# Apply BBR Optimization (silent check from original)
apply_bbr() {
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    
    if [[ "$current_cc" == "bbr" ]]; then
        log_success "✅ BBR is already enabled"
        return 0
    fi
    
    log_info "Applying BBR + network optimizations..."
    
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

# Network Buffer Optimization (64MB)
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
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=15

# File Descriptors
fs.file-max=1048576
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=524288

EOF
    fi
    
    sysctl -p > /dev/null 2>&1
    
    # Set ulimit
    if ! grep -q "Hysteria2 Optimization" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf <<EOF

# Hysteria2 Optimization
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65536
* hard nproc 65536

EOF
    fi
    
    log_success "✅ Network optimization applied"
}

# Create Systemd Service
create_service() {
    local port="$1"
    local service_file="/etc/systemd/system/hy2-${port}.service"
    
    cat > "$service_file" <<EOF
[Unit]
Description=Hysteria2 Server (${HOSTNAME} - Port ${port})
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/${port}
Environment="HYSTERIA_LOG_LEVEL=warn"
ExecStart=${INSTALL_DIR}/hy2 server -c ${INSTALL_DIR}/${port}/config.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576
StandardOutput=append:/var/log/hy2-${port}.log
StandardError=append:/var/log/hy2-${port}.log

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable hy2-${port}.service > /dev/null 2>&1
    systemctl start hy2-${port}.service
    
    sleep 2
    
    if systemctl is-active --quiet hy2-${port}.service; then
        log_success "✅ Service hy2-${port} started successfully"
    else
        log_error "Service failed to start. Check logs: journalctl -u hy2-${port} -n 50"
        exit 1
    fi
}

# Generate Share Links
generate_links() {
    local ip="$1"
    local port="$2"
    local password="$3"
    
    # Hysteria2 URL (with proper encoding from original)
    local hy2_url="hy2://$(urlencode "$password")@${ip}:${port}/?insecure=1&sni=${SNI_DOMAIN}#$(urlencode "${HOSTNAME}-HY2-${port}")"
    
    # Sing-box Config
    local singbox_config=$(cat <<EOF
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
    
    # Clash Meta Config
    local clash_config=$(cat <<EOF
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
    
    # Save to file
    cat > "$INSTALL_DIR/$port/client-config.txt" <<EOF
========================================
Hysteria2 客户端配置
主机名: ${HOSTNAME}
服务器: ${ip}:${port}
密码: ${password}
SNI: ${SNI_DOMAIN}
带宽: 无限制 (自动协商)
========================================

【Hysteria2 分享链接】
${hy2_url}

【Sing-box 配置】
${singbox_config}

【Clash Meta 配置】
${clash_config}

========================================
管理命令:
- 启动: systemctl start hy2-${port}
- 停止: systemctl stop hy2-${port}
- 重启: systemctl restart hy2-${port}
- 状态: systemctl status hy2-${port}
- 日志: journalctl -u hy2-${port} -f

卸载命令:
systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf ${INSTALL_DIR}/${port}
========================================
EOF
    
    echo "$hy2_url"
    echo "$singbox_config"
    echo "$clash_config"
}

# Display Results
display_results() {
    local ip="$1"
    local port="$2"
    local password="$3"
    local hy2_url="$4"
    local singbox_config="$5"
    local clash_config="$6"
    
    clear
    echo ""
    echo -e "${BLUE_BG}========================================${NORMAL}"
    echo -e "${BLUE_BG}  🎉 Hysteria2 安装完成！${NORMAL}"
    echo -e "${BLUE_BG}========================================${NORMAL}"
    echo ""
    log_important "主机名: ${HOSTNAME}"
    log_important "服务器: ${ip}:${port}"
    log_important "密码: ${password}"
    log_important "SNI: ${SNI_DOMAIN}"
    log_important "带宽: 无限制 (自动协商)"
    echo ""
    log_success "【Hysteria2 分享链接】"
    echo "$hy2_url"
    echo ""
    log_success "【Sing-box 配置】"
    echo "$singbox_config"
    echo ""
    log_success "【Clash Meta 配置】"
    echo "$clash_config"
    echo ""
    log_important "管理命令:"
    echo "  启动: systemctl start hy2-${port}"
    echo "  停止: systemctl stop hy2-${port}"
    echo "  状态: systemctl status hy2-${port}"
    echo "  日志: journalctl -u hy2-${port} -f"
    echo ""
    log_important "卸载命令:"
    echo "  systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf ${INSTALL_DIR}/${port}"
    echo ""
}

# Push to Telegram
push_to_telegram() {
    local ip="$1"
    local port="$2"
    local password="$3"
    local hy2_url="$4"
    local singbox_config="$5"
    local clash_config="$6"
    
    local telegram_message=$(cat <<EOF
🚀 *Hysteria2 服务器部署成功*

📡 *服务器信息*
• 主机名: \`${HOSTNAME}\`
• IP: \`${ip}\`
• 端口: \`${port}\`
• 密码: \`${password}\`
• SNI: \`${SNI_DOMAIN}\`
• 带宽: 无限制 (自动协商)

🔗 *Hysteria2 分享链接*
\`${hy2_url}\`

📱 *客户端配置*
**Sing-box JSON:**
\`\`\`json
${singbox_config}
\`\`\`

**Clash Meta YAML:**
\`\`\`yaml
${clash_config}
\`\`\`

⚙️ *性能优化*
✅ BBR 拥塞控制已启用
✅ 64MB TCP/UDP 缓冲区
✅ 100 万连接跟踪
✅ 32MB QUIC 窗口
✅ 2048 并发流

📊 *预期性能*
• YouTube 8K: 流畅播放
• 延迟: 40-60ms (东京-香港)
• 并发设备: 20-50 台
• 峰值带宽: 1500-2500 Mbps

🛠 *管理命令*
• 启动: \`systemctl start hy2-${port}\`
• 停止: \`systemctl stop hy2-${port}\`
• 日志: \`journalctl -u hy2-${port} -f\`

⏰ 部署时间: $(date '+%Y-%m-%d %H:%M:%S')
EOF
)
    
    log_info "正在推送配置到 Telegram..."
    send_telegram "$telegram_message"
}

# Main Function
main() {
    # Accept arguments: port, version, ip
    local port="${1:-auto}"
    local version="${2:-auto}"
    local ip="${3:-auto}"
    
    clear
    echo -e "${BLUE_BG}========================================${NORMAL}"
    echo -e "${BLUE_BG}  Hysteria2 Ultimate Edition${NORMAL}"
    echo -e "${BLUE_BG}  Version: 7.0.0 - Production Ready${NORMAL}"
    echo -e "${BLUE_BG}  Hostname: ${HOSTNAME}${NORMAL}"
    echo -e "${BLUE_BG}========================================${NORMAL}"
    echo ""
    
    # Pre-checks
    check_root
    check_grep
    detect_arch
    install_packages
    
    # Get version
    if [[ "$version" == "auto" ]]; then
        version=$(get_latest_version)
    fi
    log_info "Target version: $version"
    
    # Download core
    download_hy2_core "$version"
    
    # Get IP
    if [[ "$ip" == "auto" ]]; then
        ip=$(get_server_ip)
    fi
    log_info "Server IP: $ip"
    
    # Get port
    if [[ "$port" == "auto" ]]; then
        port=$((RANDOM % 50000 + 10000))
        log_info "Generated random port: $port"
    else
        log_info "Using specified port: $port"
    fi
    
    # Check port conflict
    if ! check_port_conflict "$port"; then
        log_error "Port $port is not available. Please choose another port."
        exit 1
    fi
    
    # Generate password
    password=$(openssl rand -base64 16)
    log_info "Generated password: $password"
    
    # Generate certificate
    generate_cert "$port"
    
    # Create configuration
    create_config "$port" "$password"
    
    # Apply BBR optimization
    apply_bbr
    
    # Create and start service
    create_service "$port"
    
    # Generate share links
    local output=$(generate_links "$ip" "$port" "$password")
    local hy2_url=$(echo "$output" | sed -n '1p')
    local singbox_config=$(echo "$output" | sed -n '2p')
    local clash_config=$(echo "$output" | sed -n '3p')
    
    # Display results
    display_results "$ip" "$port" "$password" "$hy2_url" "$singbox_config" "$clash_config"
    
    # Push to Telegram
    push_to_telegram "$ip" "$port" "$password" "$hy2_url" "$singbox_config" "$clash_config"
    
    echo ""
    log_success "========================================${NORMAL}"
    log_success "✅ 部署完成！配置已保存到 ${INSTALL_DIR}/${port}/client-config.txt"
    log_success "========================================${NORMAL}"
    echo ""
}

# Execute
main "$@"
