#!/bin/bash

# ========================================
# Hysteria2 一键安装脚本
# 使用方法: 
#   bash script.sh              # 默认端口 52015
#   bash script.sh 15300        # 自定义端口 15300
#   bash script.sh 15300 auto   # 指定端口和自动检测IP
# ========================================

GREEN_BG='\033[42;30m'
RED_BG='\033[41;97m'
YELLOW_BG='\033[43;30m'
BLUE_BG='\033[44;97m'
NORMAL='\033[0m'

# 配置参数
DEFAULT_PORT=52015
DEFAULT_PASSWORD="Aq112211!"
DEFAULT_SNI="icloud.cdn-apple.com"

# 解析参数
PORT="${1:-$DEFAULT_PORT}"
PASSWORD="$DEFAULT_PASSWORD"
SNI="$DEFAULT_SNI"

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED_BG}需要 root 权限运行${NORMAL}"
  exit 1
fi

# 检测架构
cpu_arch=$(uname -m)
case "$cpu_arch" in
  x86_64) arch="amd64" ;;
  aarch64) arch="arm64" ;;
  armv7l) arch="arm" ;;
  *) echo -e "${RED_BG}不支持的架构: $cpu_arch${NORMAL}"; exit 1 ;;
esac

# 获取公网IP
get_public_ip() {
  ipv4=$(curl -s --max-time 5 -4 https://api.ipify.org 2>/dev/null)
  if [ -z "$ipv4" ]; then
    ipv4=$(curl -s --max-time 5 https://cloudflare.com/cdn-cgi/trace -4 | grep -oP '(?<=ip=).*' 2>/dev/null)
  fi
  echo "$ipv4"
}

PUBLIC_IP=$(get_public_ip)

echo -e "${BLUE_BG}========================================${NORMAL}"
echo -e "${BLUE_BG}  Hysteria2 安装脚本${NORMAL}"
echo -e "${BLUE_BG}========================================${NORMAL}"
echo ""
echo -e "${GREEN_BG}配置信息:${NORMAL}"
echo "  端口: $PORT"
echo "  密码: $PASSWORD"
echo "  SNI: $SNI"
echo "  公网IP: $PUBLIC_IP"
echo "  架构: $cpu_arch ($arch)"
echo ""

# 安装依赖
echo -e "${GREEN_BG}检查依赖...${NORMAL}"
for tool in curl wget openssl; do
  if ! command -v "$tool" &> /dev/null; then
    if command -v apt-get &> /dev/null; then
      apt-get update -qq && apt-get install -y $tool
    elif command -v apk &> /dev/null; then
      apk add --no-cache $tool
    fi
  fi
done

# 停止旧服务
echo -e "${YELLOW_BG}停止旧服务...${NORMAL}"
systemctl stop hy2-${PORT} 2>/dev/null
rc-service hy2-${PORT} stop 2>/dev/null

# 创建目录
mkdir -p /opt/skim-hy2/${PORT}

# 下载 Hysteria2 核心
if [ ! -f /opt/skim-hy2/hy2 ]; then
  echo -e "${GREEN_BG}下载 Hysteria2 核心...${NORMAL}"
  wget -q -O /opt/skim-hy2/hy2 \
    "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${arch}"
  
  if [ $? -ne 0 ]; then
    echo -e "${RED_BG}下载失败，尝试备用地址...${NORMAL}"
    wget -q -O /opt/skim-hy2/hy2 \
      "https://ghproxy.com/https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${arch}"
  fi
  
  chmod +x /opt/skim-hy2/hy2
fi

# 生成证书
echo -e "${GREEN_BG}生成自签证书...${NORMAL}"
cat > /opt/skim-hy2/${PORT}/openssl.conf <<EOF
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
CN                     = ${SNI}

[ v3_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${SNI}
DNS.2 = *.${SNI}
EOF

openssl req -x509 -new -nodes -days 36500 \
  -keyout /opt/skim-hy2/${PORT}/server.key \
  -out /opt/skim-hy2/${PORT}/server.crt \
  -config /opt/skim-hy2/${PORT}/openssl.conf \
  > /dev/null 2>&1

chmod 600 /opt/skim-hy2/${PORT}/server.key
chmod 644 /opt/skim-hy2/${PORT}/server.crt

# 创建配置文件
echo -e "${GREEN_BG}创建配置文件...${NORMAL}"
cat > /opt/skim-hy2/${PORT}/config.yaml <<EOF
listen: :${PORT}

tls:
  cert: /opt/skim-hy2/${PORT}/server.crt
  key: /opt/skim-hy2/${PORT}/server.key

auth:
  type: password
  password: ${PASSWORD}

quic:
  initStreamReceiveWindow: 33554432
  maxStreamReceiveWindow: 33554432
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 60s
  maxIncomingStreams: 2048

disableUDP: false
udpIdleTimeout: 60s

speedTest: false

masquerade:
  type: proxy
  proxy:
    url: https://www.apple.com
    rewriteHost: true
EOF

# 创建服务
echo -e "${GREEN_BG}创建系统服务...${NORMAL}"

if command -v systemctl >/dev/null 2>&1; then
  # Systemd
  cat > /etc/systemd/system/hy2-${PORT}.service <<EOF
[Unit]
Description=Hysteria 2 Server (Port ${PORT})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/skim-hy2/${PORT}
ExecStart=/opt/skim-hy2/hy2 server -c /opt/skim-hy2/${PORT}/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hy2-${PORT}
  systemctl restart hy2-${PORT}
  
  sleep 3
  
  if systemctl is-active --quiet hy2-${PORT}; then
    echo -e "${GREEN_BG}✅ 服务启动成功${NORMAL}"
  else
    echo -e "${RED_BG}❌ 服务启动失败${NORMAL}"
    systemctl status hy2-${PORT} --no-pager
    exit 1
  fi

elif command -v rc-service >/dev/null 2>&1; then
  # OpenRC
  cat > /etc/init.d/hy2-${PORT} <<EOF
#!/sbin/openrc-run

name="Hysteria 2 Server (Port ${PORT})"
description="Hysteria2 Proxy Server"
command="/opt/skim-hy2/hy2"
command_args="server -c /opt/skim-hy2/${PORT}/config.yaml"
command_background=true
pidfile="/run/hy2-${PORT}.pid"
output_log="/var/log/hy2-${PORT}.log"
error_log="/var/log/hy2-${PORT}.log"

depend() {
    need net
    after firewall
}
EOF

  chmod +x /etc/init.d/hy2-${PORT}
  rc-update add hy2-${PORT} default
  rc-service hy2-${PORT} restart
  
  sleep 3
  
  if rc-service hy2-${PORT} status | grep -q "started"; then
    echo -e "${GREEN_BG}✅ 服务启动成功${NORMAL}"
  else
    echo -e "${RED_BG}❌ 服务启动失败${NORMAL}"
    rc-service hy2-${PORT} status
    exit 1
  fi
fi

# URL编码函数
urlencode() {
  local string="${1}"
  local encoded=""
  local len=${#string}
  for (( i=0; i<len; i++ )); do
    local c="${string:$i:1}"
    case $c in
      [a-zA-Z0-9.~_-]) encoded+="$c" ;;
      *) printf -v hex '%%%02X' "'$c"; encoded+="$hex" ;;
    esac
  done
  echo "$encoded"
}

PASSWORD_ENC=$(urlencode "$PASSWORD")

# 显示配置
echo ""
echo -e "${BLUE_BG}========================================${NORMAL}"
echo -e "${BLUE_BG}  ✅ 安装完成${NORMAL}"
echo -e "${BLUE_BG}========================================${NORMAL}"
echo ""
echo -e "${GREEN_BG}服务器信息:${NORMAL}"
echo "  IP地址: $PUBLIC_IP"
echo "  端口: $PORT"
echo "  密码: $PASSWORD"
echo "  SNI: $SNI"
echo ""
echo -e "${GREEN_BG}v2rayN 链接:${NORMAL}"
echo "hy2://${PASSWORD_ENC}@${PUBLIC_IP}:${PORT}/?insecure=1&sni=${SNI}#Hysteria2-${PORT}"
echo ""
echo -e "${GREEN_BG}Sing-box 配置:${NORMAL}"
cat <<EOF
{
  "type": "hysteria2",
  "tag": "Hysteria2-${PORT}",
  "server": "${PUBLIC_IP}",
  "server_port": ${PORT},
  "password": "${PASSWORD}",
  "tls": {
    "enabled": true,
    "server_name": "${SNI}",
    "insecure": true,
    "alpn": ["h3"]
  }
}
EOF
echo ""
echo -e "${GREEN_BG}Clash Meta 配置:${NORMAL}"
cat <<EOF
- name: Hysteria2-${PORT}
  type: hysteria2
  server: ${PUBLIC_IP}
  port: ${PORT}
  password: ${PASSWORD}
  skip-cert-verify: true
  sni: ${SNI}
  alpn:
    - h3
EOF
echo ""
echo -e "${YELLOW_BG}管理命令:${NORMAL}"
if command -v systemctl >/dev/null 2>&1; then
  echo "  查看状态: systemctl status hy2-${PORT}"
  echo "  重启服务: systemctl restart hy2-${PORT}"
  echo "  停止服务: systemctl stop hy2-${PORT}"
  echo "  卸载: systemctl disable --now hy2-${PORT} && rm /etc/systemd/system/hy2-${PORT}.service && rm -rf /opt/skim-hy2/${PORT}"
else
  echo "  查看状态: rc-service hy2-${PORT} status"
  echo "  重启服务: rc-service hy2-${PORT} restart"
  echo "  停止服务: rc-service hy2-${PORT} stop"
  echo "  卸载: rc-update del hy2-${PORT} && rm /etc/init.d/hy2-${PORT} && rm -rf /opt/skim-hy2/${PORT}"
fi
echo -e "${BLUE_BG}========================================${NORMAL}"
