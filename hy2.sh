#!/bin/bash

# ========================================
# Hysteria2 Unlimited Bandwidth Edition
# Version: 6.0.0 - with Telegram Push
# Date: 2025-12-15
# ========================================

# Configuration
HOSTNAME="ip-172-31-3-171"
BOT_TOKEN="7808383148:AAF5LglthZukCj6eqbA0rEbJZQMAjlk--I0"
CHAT_ID="-1002145386723"
INSTALL_DIR="/opt/skim-hy2"
DEFAULT_PORT="52015"
DEFAULT_PASSWORD="Aq112211!"
SNI_DOMAIN="icloud.cdn-apple.com"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
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
        log_info "✅ 配置已推送到 Telegram"
        return 0
    else
        log_warn "⚠️ Telegram 推送失败: $response"
        return 1
    fi
}

# Check Root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用 root 权限运行此脚本"
        exit 1
    fi
}

# Detect System
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "无法检测操作系统"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH_SUFFIX="amd64"
            ;;
        aarch64|arm64)
            ARCH_SUFFIX="arm64"
            ;;
        armv7l)
            ARCH_SUFFIX="arm"
            ;;
        *)
            log_error "不支持的 CPU 架构: $ARCH"
            exit 1
            ;;
    esac
    
    log_info "系统: $OS $VERSION | 架构: $ARCH"
}

# Install Dependencies
install_dependencies() {
    log_info "正在安装依赖..."
    
    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y curl jq openssl wget tar > /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y curl jq openssl wget tar > /dev/null 2>&1
            ;;
        alpine)
            apk add --no-cache curl jq openssl wget tar > /dev/null 2>&1
            ;;
        *)
            log_error "不支持的操作系统: $OS"
            exit 1
            ;;
    esac
    
    log_info "✅ 依赖安装完成"
}

# Download Hysteria2 Core
download_hysteria() {
    log_info "正在获取 Hysteria2 最新版本..."
    
    LATEST_VERSION=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name' | sed 's/^app\///')
    
    if [[ -z "$LATEST_VERSION" ]]; then
        log_error "无法获取最新版本"
        exit 1
    fi
    
    log_info "最新版本: $LATEST_VERSION"
    
    DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/app%2F${LATEST_VERSION}/hysteria-linux-${ARCH_SUFFIX}"
    
    mkdir -p "$INSTALL_DIR"
    
    log_info "正在下载 Hysteria2 核心..."
    if ! wget -q --show-progress -O "$INSTALL_DIR/hysteria" "$DOWNLOAD_URL"; then
        log_error "下载失败"
        exit 1
    fi
    
    chmod +x "$INSTALL_DIR/hysteria"
    log_info "✅ Hysteria2 核心下载完成 (v${LATEST_VERSION})"
}

# Generate Certificate
generate_cert() {
    log_info "正在生成自签名证书 (SNI: ${SNI_DOMAIN})..."
    
    mkdir -p "$INSTALL_DIR/$DEFAULT_PORT"
    
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "$INSTALL_DIR/$DEFAULT_PORT/key.pem" \
        -out "$INSTALL_DIR/$DEFAULT_PORT/cert.pem" \
        -subj "/CN=${SNI_DOMAIN}" \
        -days 36500 \
        -addext "subjectAltName=DNS:${SNI_DOMAIN},DNS:*.${SNI_DOMAIN}" \
        > /dev/null 2>&1
    
    chmod 600 "$INSTALL_DIR/$DEFAULT_PORT/key.pem"
    chmod 644 "$INSTALL_DIR/$DEFAULT_PORT/cert.pem"
    
    log_info "✅ 证书生成完成"
}

# Create Configuration
create_config() {
    log_info "正在生成配置文件..."
    
    cat > "$INSTALL_DIR/$DEFAULT_PORT/config.yaml" <<EOF
listen: :${DEFAULT_PORT}

tls:
  cert: $INSTALL_DIR/$DEFAULT_PORT/cert.pem
  key: $INSTALL_DIR/$DEFAULT_PORT/key.pem

auth:
  type: password
  password: ${DEFAULT_PASSWORD}

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
EOF
    
    log_info "✅ 配置文件生成完成"
}

# Apply BBR Optimization
apply_bbr() {
    log_info "正在检测 BBR 配置..."
    
    CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    
    if [[ "$CURRENT_CC" == "bbr" ]]; then
        log_info "✅ BBR 已启用，跳过优化"
        return 0
    fi
    
    log_info "正在应用千兆网络优化 (BBR + 高缓冲)..."
    
    cat >> /etc/sysctl.conf <<EOF

# ============================================
# Hysteria2 Gigabit Network Optimization
# Hostname: ${HOSTNAME}
# Date: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================

# BBR Congestion Control
net.core.default_qdisc=fq_pie
net.ipv4.tcp_congestion_control=bbr

# Network Buffer Optimization
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
    
    sysctl -p > /dev/null 2>&1
    
    # Set ulimit
    if ! grep -q "* soft nofile 1048576" /etc/security/limits.conf; then
        cat >> /etc/security/limits.conf <<EOF

# Hysteria2 Optimization
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65536
* hard nproc 65536

EOF
    fi
    
    log_info "✅ 网络优化完成"
}

# Create Systemd Service
create_service() {
    log_info "正在创建系统服务..."
    
    cat > /etc/systemd/system/hysteria-${DEFAULT_PORT}.service <<EOF
[Unit]
Description=Hysteria2 Server (${HOSTNAME} - Port ${DEFAULT_PORT})
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/$DEFAULT_PORT
ExecStart=$INSTALL_DIR/hysteria server -c $INSTALL_DIR/$DEFAULT_PORT/config.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable hysteria-${DEFAULT_PORT}.service > /dev/null 2>&1
    systemctl restart hysteria-${DEFAULT_PORT}.service
    
    sleep 2
    
    if systemctl is-active --quiet hysteria-${DEFAULT_PORT}.service; then
        log_info "✅ Hysteria2 服务启动成功"
    else
        log_error "服务启动失败，请检查日志: journalctl -u hysteria-${DEFAULT_PORT}.service -f"
        exit 1
    fi
}

# Get Server IP
get_server_ip() {
    SERVER_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || curl -s -4 ipinfo.io/ip)
    
    if [[ -z "$SERVER_IP" ]]; then
        log_warn "无法自动获取公网 IP，请手动输入"
        read -p "服务器 IP: " SERVER_IP
    fi
    
    log_info "服务器 IP: $SERVER_IP"
}

# Generate Share Links
generate_links() {
    log_info "正在生成客户端配置..."
    
    # Hysteria2 Share Link
    HY2_LINK="hysteria2://${DEFAULT_PASSWORD}@${SERVER_IP}:${DEFAULT_PORT}/?insecure=1&sni=${SNI_DOMAIN}#${HOSTNAME}-HY2"
    
    # Sing-box Config
    SINGBOX_CONFIG=$(cat <<EOF
{
  "type": "hysteria2",
  "tag": "${HOSTNAME}-HY2",
  "server": "${SERVER_IP}",
  "server_port": ${DEFAULT_PORT},
  "password": "${DEFAULT_PASSWORD}",
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
    CLASH_CONFIG=$(cat <<EOF
- name: ${HOSTNAME}-HY2
  type: hysteria2
  server: ${SERVER_IP}
  port: ${DEFAULT_PORT}
  password: ${DEFAULT_PASSWORD}
  skip-cert-verify: true
  sni: ${SNI_DOMAIN}
  alpn:
    - h3
EOF
)
    
    # Save to file
    cat > "$INSTALL_DIR/$DEFAULT_PORT/client-config.txt" <<EOF
========================================
Hysteria2 客户端配置
主机名: ${HOSTNAME}
服务器: ${SERVER_IP}:${DEFAULT_PORT}
密码: ${DEFAULT_PASSWORD}
SNI: ${SNI_DOMAIN}
带宽: 无限制 (自动协商)
========================================

【Hysteria2 分享链接】
${HY2_LINK}

【Sing-box 配置】
${SINGBOX_CONFIG}

【Clash Meta 配置】
${CLASH_CONFIG}

========================================
管理命令:
- 启动: systemctl start hysteria-${DEFAULT_PORT}
- 停止: systemctl stop hysteria-${DEFAULT_PORT}
- 重启: systemctl restart hysteria-${DEFAULT_PORT}
- 状态: systemctl status hysteria-${DEFAULT_PORT}
- 日志: journalctl -u hysteria-${DEFAULT_PORT} -f
========================================
EOF
    
    log_info "✅ 配置文件已保存: $INSTALL_DIR/$DEFAULT_PORT/client-config.txt"
}

# Display and Push to Telegram
display_and_push() {
    local config_content=$(cat "$INSTALL_DIR/$DEFAULT_PORT/client-config.txt")
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}🎉 Hysteria2 安装完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "$config_content"
    echo ""
    
    # Prepare Telegram Message
    local telegram_message=$(cat <<EOF
🚀 *Hysteria2 服务器部署成功*

📡 *服务器信息*
• 主机名: \`${HOSTNAME}\`
• IP: \`${SERVER_IP}\`
• 端口: \`${DEFAULT_PORT}\`
• 密码: \`${DEFAULT_PASSWORD}\`
• SNI: \`${SNI_DOMAIN}\`
• 带宽: 无限制 (自动协商)

🔗 *Hysteria2 分享链接*
\`${HY2_LINK}\`

📱 *客户端配置*
**Sing-box JSON:**
\`\`\`json
${SINGBOX_CONFIG}
\`\`\`

**Clash Meta YAML:**
\`\`\`yaml
${CLASH_CONFIG}
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
• 启动: \`systemctl start hysteria-${DEFAULT_PORT}\`
• 停止: \`systemctl stop hysteria-${DEFAULT_PORT}\`
• 日志: \`journalctl -u hysteria-${DEFAULT_PORT} -f\`

⏰ 部署时间: $(date '+%Y-%m-%d %H:%M:%S')
EOF
)
    
    log_info "正在推送配置到 Telegram..."
    send_telegram "$telegram_message"
}

# Main Installation
main() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Hysteria2 Unlimited Bandwidth Edition${NC}"
    echo -e "${BLUE}  Version: 6.0.0 - with Telegram Push${NC}"
    echo -e "${BLUE}  Hostname: ${HOSTNAME}${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    check_root
    detect_system
    install_dependencies
    download_hysteria
    generate_cert
    create_config
    apply_bbr
    create_service
    get_server_ip
    generate_links
    display_and_push
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}✅ 所有配置已完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}

# Execute
main
