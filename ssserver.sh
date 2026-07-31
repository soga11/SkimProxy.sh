#!/bin/bash

# ============================================================
# Shadowsocks Rust 自动部署脚本 - 自定义版本
# 默认配置: 端口52016, 密码Aq112211!Aq112211!, 加密2022-blake3-aes-128-gcm
# GitHub: https://github.com/soga11/SkimProxy.sh/tree/patch-1
# ============================================================

GREEN_BG='\033[42;30m'   # 绿色背景，黑色文字
RED_BG='\033[41;97m'     # 红色背景，白色文字
WHITE_BG='\033[47;30m'   # 白色背景，黑色文字
NORMAL='\033[0m'         # 重置格式
BLUE='\033[0;34m'        # 蓝色文字
YELLOW='\033[1;33m'      # 黄色文字

# 版本信息
VERSION="1.0.0"
SCRIPT_NAME="SkimProxy.sh"
AUTHOR="soga11"

# ============================================================
# 初始化检查
# ============================================================
init_check() {
    echo -e "${BLUE}=== 初始化检查 ===${NORMAL}"
    
    # 检查是否以root权限运行
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED_BG}错误: 需要root权限运行此脚本${NORMAL}"
        echo "请使用sudo或以root用户运行"
        exit 1
    fi
    
    # 检查CPU架构
    cpu_arch=$(uname -m)
    case "$cpu_arch" in
        x86_64) arch="x86_64" ;;
        aarch64) arch="aarch64" ;;
        armv7*) arch="armv7" ;;
        *) echo -e "${RED_BG}不支持的CPU架构: $cpu_arch${NORMAL}"; exit 1 ;;
    esac
    echo -e "CPU架构: ${GREEN_BG} $arch ${NORMAL}"
}

# ============================================================
# 系统依赖检查
# ============================================================
check_dependencies() {
    echo -e "${BLUE}=== 检查系统依赖 ===${NORMAL}"
    
    # 安装GNU grep（如果需要）
    install_gnu_grep() {
        if command -v apk >/dev/null; then
            apk add grep
        elif command -v apt-get >/dev/null; then
            apt-get update && apt-get install -y grep
        elif command -v pacman >/dev/null; then
            pacman -Sy --noconfirm grep
        elif command -v dnf >/dev/null; then
            dnf install -y grep
        elif command -v yum >/dev/null; then
            yum install -y grep
        else
            echo -e "${RED_BG}无法自动安装GNU grep，请手动安装${NORMAL}"
            exit 1
        fi
    }
    
    # 检查grep是否为BusyBox版本
    if grep --version 2>&1 | grep -q BusyBox; then
        echo -e "${YELLOW}检测到BusyBox grep，正在安装GNU grep...${NORMAL}"
        install_gnu_grep
    fi
    
    # 安装必要工具
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
            echo -e "${RED_BG}不支持的包管理器${NORMAL}，请手动安装: curl, jq, tar, openssl, xz"
            exit 1
        fi
    }
    
    # 检查并安装必要工具
    for tool in curl jq tar openssl xz; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}缺少必要工具: $tool，正在安装...${NORMAL}"
            install_packages
            break
        fi
    done
    
    echo -e "${GREEN_BG}依赖检查完成${NORMAL}"
}

# ============================================================
# URL编码函数
# ============================================================
urlencode() {
    local LANG=C
    local input
    if [ -t 0 ]; then
        input="$1"  # if no pipe, use argument
    else
        input=$(cat)  # if piped, read from stdin
    fi
    local length="${#input}"
    for (( i = 0; i < length; i++ )); do
        c="${input:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "%s" "$c" ;;
            $'\n') printf "%%0A" ;;  # Handle newlines
            *) printf '%%%02X' "'$c" ;;
        esac
    done
    echo
}

# ============================================================
# 获取最新版本
# ============================================================
get_latest_version() {
    echo -e "${BLUE}获取Shadowsocks-Rust最新版本...${NORMAL}"
    
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r .tag_name 2>/dev/null)
    
    if [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
        echo -e "${YELLOW}无法从GitHub获取最新版本，使用默认版本${NORMAL}"
        echo "v1.22.0"
    else
        echo "$latest_version"
    fi
}

# ============================================================
# 下载并安装Shadowsocks-Rust
# ============================================================
install_ss_rust() {
    local version=$1
    echo -e "${BLUE}=== 安装Shadowsocks-Rust ${version} ===${NORMAL}"
    
    # 创建目标目录
    mkdir -p /opt/skim-ss/
    
    # 构建下载URL
    local url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${version}/shadowsocks-${version}.${arch}-unknown-linux-musl.tar.xz"
    
    echo -e "${YELLOW}下载Shadowsocks-Rust...${NORMAL}"
    echo -e "下载地址: $url"
    
    # 下载并解压
    curl -s -L -o shadowsocks.tar.xz "$url"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED_BG}下载失败${NORMAL}"
        rm -f shadowsocks.tar.xz
        exit 1
    fi
    
    tar -xvf shadowsocks.tar.xz -C /opt/skim-ss/ ssserver > /dev/null
    rm -rf shadowsocks.tar.xz
    
    # 设置执行权限
    chmod +x /opt/skim-ss/ssserver
    
    echo -e "${GREEN_BG}Shadowsocks-Rust 已安装到 /opt/skim-ss/ssserver${NORMAL}"
}

# ============================================================
# 检查现有版本
# ============================================================
check_existing_version() {
    local version=$1
    
    if [[ -x "/opt/skim-ss/ssserver" ]]; then
        local installed_version
        installed_version=$("/opt/skim-ss/ssserver" --version 2>/dev/null | awk '{print $2}')
        
        if [[ "v$installed_version" == "$version" ]]; then
            echo -e "${GREEN_BG}Shadowsocks-Rust ${version} 已安装，跳过下载${NORMAL}"
            return 0
        else
            echo -e "${YELLOW}已安装版本 ($installed_version) 与请求版本 ($version) 不同，正在更新...${NORMAL}"
            return 1
        fi
    else
        echo -e "${YELLOW}Shadowsocks-Rust 未安装，开始安装...${NORMAL}"
        return 1
    fi
}

# ============================================================
# 创建系统服务
# ============================================================
create_system_service() {
    local port=$1
    local cipher=$2
    local password=$3
    local ip=$4
    
    echo -e "${BLUE}=== 创建系统服务 ===${NORMAL}"
    
    # 检测init系统
    local init_system
    init_system=$(cat /proc/1/comm)
    
    if [[ "$init_system" == "systemd" ]]; then
        # 创建systemd服务文件
        cat <<EOF > /etc/systemd/system/ssserver-${port}.service
[Unit]
Description=Shadowsocks Rust Server on :${port}
After=network.target

[Service]
ExecStart=/opt/skim-ss/ssserver -U --server-addr [::]:${port} --encrypt-method ${cipher} --password ${password}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable ssserver-${port}
        systemctl start ssserver-${port}
        
        echo -e "${GREEN_BG}systemd 服务已创建并启动${NORMAL}"
        echo -e "服务名称: ssserver-${port}"
        echo -e "管理命令:"
        echo -e "  启动: systemctl start ssserver-${port}"
        echo -e "  停止: systemctl stop ssserver-${port}"
        echo -e "  状态: systemctl status ssserver-${port}"
        echo -e "  日志: journalctl -u ssserver-${port}"
        echo -e "  卸载: systemctl disable --now ssserver-${port} && rm /etc/systemd/system/ssserver-${port}.service"
        
    elif [[ "$init_system" == "init" || "$init_system" == "openrc" ]]; then
        # 创建openrc服务文件
        cat <<EOF > /etc/init.d/ssserver-${port}
#!/sbin/openrc-run

name="Shadowsocks Server on :${port}"
description="Shadowsocks Rust server on :${port}"
command="/opt/skim-ss/ssserver"
command_args=" -U --server-addr [::]:${port} --encrypt-method ${cipher} --password ${password}"
pidfile="/var/run/ssserver-${port}.pid"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting \$SERVICE_NAME"
    start-stop-daemon --start --background --make-pidfile --pidfile \$pidfile --exec \$command -- \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping \$SERVICE_NAME"
    start-stop-daemon --stop --pidfile \$pidfile
    eend \$?
}

restart() {
    stop
    start
}
EOF

        chmod +x /etc/init.d/ssserver-${port}
        rc-update add ssserver-${port} default
        rc-service ssserver-${port} start
        
        echo -e "${GREEN_BG}openrc 服务已创建并启动${NORMAL}"
        echo -e "服务名称: ssserver-${port}"
        echo -e "管理命令:"
        echo -e "  启动: rc-service ssserver-${port} start"
        echo -e "  停止: rc-service ssserver-${port} stop"
        echo -e "  状态: rc-service ssserver-${port} status"
        echo -e "  卸载: rc-update del ssserver-${port} default && rc-service ssserver-${port} stop && rm /etc/init.d/ssserver-${port}"
        
    else
        echo -e "${RED_BG}不支持的init系统: $init_system${NORMAL}"
        exit 1
    fi
}

# ============================================================
# 显示连接信息
# ============================================================
show_connection_info() {
    local port=$1
    local cipher=$2
    local password=$3
    local ip=$4
    
    echo -e "${BLUE}=== 连接信息 ===${NORMAL}"
    
    # 生成ss:// URL
    local ss_url
    ss_url="ss://$(echo -n "${cipher}:${password}" | base64 | urlencode)@${ip}:${port}#$(urlencode "${SCRIPT_NAME} ${cipher} ${ip}:${port}")"
    
    # 生成JSON配置
    local json_config
    json_config=$(cat <<EOF
{
    "type": "shadowsocks",
    "tag": "shadowsocks-server",
    "server": "${ip}",
    "server_port": ${port},
    "method": "${cipher}",
    "password": "${password}",
    "plugin": "",
    "plugin_opts": ""
}
EOF
)

    echo -e "${GREEN_BG}连接地址:${NORMAL} $ss_url"
    echo -e ""
    echo -e "${GREEN_BG}JSON配置:${NORMAL}"
    echo "$json_config"
    echo -e ""
    
    echo -e "${GREEN_BG}配置摘要:${NORMAL}"
    echo -e "  服务器地址: ${YELLOW}${ip}${NORMAL}"
    echo -e "  服务器端口: ${YELLOW}${port}${NORMAL}"
    echo -e "  加密方式:   ${YELLOW}${cipher}${NORMAL}"
    echo -e "  密码:       ${YELLOW}${password}${NORMAL}"
}

# ============================================================
# 主程序
# ============================================================
main() {
    echo -e "${GREEN_BG}========================================${NORMAL}"
    echo -e "${GREEN_BG}  ${SCRIPT_NAME} v${VERSION} - Shadowsocks部署工具  ${NORMAL}"
    echo -e "${GREEN_BG}  作者: ${AUTHOR}  ${NORMAL}"
    echo -e "${GREEN_BG}========================================${NORMAL}"
    echo ""
    
    # 初始化检查
    init_check
    
    # 检查依赖
    check_dependencies
    
    # 获取版本参数（默认: 最新版本）
    local version
    if [ -z "$3" ] || [ "$3" = "auto" ]; then
        version=$(get_latest_version)
    else
        version="$3"
    fi
    echo -e "Shadowsocks-Rust版本: ${GREEN_BG} ${version} ${NORMAL}"
    
    # 检查是否需要安装/更新
    if ! check_existing_version "$version"; then
        install_ss_rust "$version"
    fi
    
    # 获取端口参数（默认: 52016）
    local port
    if [ -z "$1" ] || [ "$1" = "auto" ]; then
        port=52016
    else
        port=$1
    fi
    echo -e "端口: ${GREEN_BG} ${port} ${NORMAL}"
    
    # 获取加密方式参数（默认: 2022-blake3-aes-128-gcm）
    local cipher
    if [ -z "$2" ] || [ "$2" = "auto" ]; then
        cipher="2022-blake3-aes-128-gcm"
    else
        cipher=$2
    fi
    echo -e "加密方式: ${GREEN_BG} ${cipher} ${NORMAL}"
    
    # 获取服务器IP参数（默认: 自动检测）
    local ip
    if [ -z "$4" ] || [ "$4" = "auto" ]; then
        echo -e "正在检测服务器IP..."
        ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -4 | grep -oP '(?<=ip=).*' 2>/dev/null)
        if [ -z "$ip" ]; then
            ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -6 | grep -oP '(?<=ip=).*' 2>/dev/null)
        fi
        if echo "$ip" | grep -q ':'; then
            ip="[$ip]"
        fi
    else 
        ip=$4
    fi
    echo -e "服务器IP: ${GREEN_BG} ${ip} ${NORMAL}"
    
    # 获取密码参数（默认: Aq112211!Aq112211!）
    local password
    if [ -z "$5" ] || [ "$5" = "auto" ]; then
        password="Aq112211!Aq112211!"
    else
        password=$5
    fi
    echo -e "密码: ${GREEN_BG} ${password} ${NORMAL}"
    
    echo ""
    
    # 创建系统服务
    create_system_service "$port" "$cipher" "$password" "$ip"
    
    echo ""
    
    # 显示连接信息
    show_connection_info "$port" "$cipher" "$password" "$ip"
    
    echo ""
    echo -e "${GREEN_BG}部署完成！${NORMAL}"
    echo -e "使用以下命令管理服务:"
    echo -e "  查看状态: systemctl status ssserver-${port}"
    echo -e "  查看日志: journalctl -u ssserver-${port} -f"
    echo -e "  重启服务: systemctl restart ssserver-${port}"
}

# ============================================================
# 命令行参数处理
# ============================================================
case "${1:-}" in
    -h|--help|help)
        echo -e "${GREEN_BG}${SCRIPT_NAME} v${VERSION}${NORMAL}"
        echo "用法: $0 [端口] [加密方式] [版本] [服务器IP] [密码]"
        echo ""
        echo "参数说明:"
        echo "  端口        服务器端口 (默认: 52016)"
        echo "  加密方式    加密算法 (默认: 2022-blake3-aes-128-gcm)"
        echo "  版本        Shadowsocks-Rust版本 (默认: 最新版)"
        echo "  服务器IP    服务器IP地址 (默认: 自动检测)"
        echo "  密码        连接密码 (默认: Aq112211!Aq112211!)"
        echo ""
        echo "示例:"
        echo "  $0                          # 使用默认配置"
        echo "  $0 8388                     # 使用端口8388"
        echo "  $0 8388 2022-blake3-aes-256-gcm auto auto MyPassword  # 自定义所有参数"
        echo ""
        echo "版本: ${VERSION}"
        echo "作者: ${AUTHOR}"
        exit 0
        ;;
    -v|--version|version)
        echo "${SCRIPT_NAME} v${VERSION}"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
