#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

show_help() {
    echo -e "${GREEN}Shadowsocks 节点管理脚本${NC}"
    echo -e "用法: $0 [命令]"
    echo -e ""
    echo -e "命令:"
    echo -e "  list        列出所有节点"
    echo -e "  status      查看所有节点状态"
    echo -e "  restart     重启所有节点"
    echo -e "  stop        停止所有节点"
    echo -e "  start       启动所有节点"
    echo -e "  logs        查看所有节点日志"
    echo -e "  add         添加新节点"
    echo -e "  remove      移除节点"
    echo -e "  backup      备份配置"
    echo -e "  restore     恢复配置"
}

list_nodes() {
    echo -e "${GREEN}当前节点列表:${NC}"
    echo -e "端口  服务名称          状态"
    echo -e "---  ----------------  ------"
    
    for service in /etc/systemd/system/skim-ss-*.service; do
        if [[ -f "$service" ]]; then
            port=$(basename "$service" | sed 's/skim-ss-\(.*\)\.service/\1/')
            service_name="skim-ss-$port"
            status=$(systemctl is-active "$service_name" 2>/dev/null)
            
            if [[ $status == "active" ]]; then
                echo -e "$port  $service_name  ${GREEN}运行中${NC}"
            else
                echo -e "$port  $service_name  ${RED}已停止${NC}"
            fi
        fi
    done
}

check_status() {
    echo -e "${GREEN}所有节点状态:${NC}"
    for service in /etc/systemd/system/skim-ss-*.service; do
        if [[ -f "$service" ]]; then
            port=$(basename "$service" | sed 's/skim-ss-\(.*\)\.service/\1/')
            systemctl status "skim-ss-$port" --no-pager
            echo -e ""
        fi
    done
}

restart_all() {
    echo -e "${YELLOW}正在重启所有节点...${NC}"
    for service in /etc/systemd/system/skim-ss-*.service; do
        if [[ -f "$service" ]]; then
            port=$(basename "$service" | sed 's/skim-ss-\(.*\)\.service/\1/')
            systemctl restart "skim-ss-$port"
            echo -e "已重启: skim-ss-$port"
        fi
    done
}

stop_all() {
    echo -e "${YELLOW}正在停止所有节点...${NC}"
    for service in /etc/systemd/system/skim-ss-*.service; do
        if [[ -f "$service" ]]; then
            port=$(basename "$service" | sed 's/skim-ss-\(.*\)\.service/\1/')
            systemctl stop "skim-ss-$port"
            echo -e "已停止: skim-ss-$port"
        fi
    done
}

start_all() {
    echo -e "${YELLOW}正在启动所有节点...${NC}"
    for service in /etc/systemd/system/skim-ss-*.service; do
        if [[ -f "$service" ]]; then
            port=$(basename "$service" | sed 's/skim-ss-\(.*\)\.service/\1/')
            systemctl start "skim-ss-$port"
            echo -e "已启动: skim-ss-$port"
        fi
    done
}

show_logs() {
    echo -e "${GREEN}所有节点日志:${NC}"
    for service in /etc/systemd/system/skim-ss-*.service; do
        if [[ -f "$service" ]]; then
            port=$(basename "$service" | sed 's/skim-ss-\(.*\)\.service/\1/')
            echo -e "${YELLOW}=== 日志: skim-ss-$port ===${NC}"
            journalctl -u "skim-ss-$port" --no-pager -n 10
            echo -e ""
        fi
    done
}

add_node() {
    read -p "请输入节点名称: " NODE_NAME
    read -p "请输入端口: " PORT
    read -p "请输入密码: " PASSWORD
    read -p "请输入加密方式 (默认 2022-blake3-aes-128-gcm): " CIPHER
    CIPHER=${CIPHER:-2022-blake3-aes-128-gcm}
    
    # 添加到配置文件
    echo "$NODE_NAME|$PORT|$PASSWORD|$CIPHER" >> ss_nodes.conf
    
    # 部署节点
    bash deploy_ssserver.sh
    
    echo -e "${GREEN}节点已添加并部署${NC}"
}

remove_node() {
    read -p "请输入要移除的节点端口: " PORT
    
    # 停止服务
    systemctl stop "skim-ss-$PORT" 2>/dev/null
    systemctl disable "skim-ss-$PORT" 2>/dev/null
    
    # 删除服务文件
    rm -f "/etc/systemd/system/skim-ss-$PORT.service"
    
    # 删除配置文件
    rm -f "/etc/skim-ss/config-$PORT.json"
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    # 从配置文件中移除
    sed -i "/|$PORT|/d" ss_nodes.conf
    
    echo -e "${GREEN}节点已移除${NC}"
}

backup_config() {
    echo -e "${GREEN}正在备份配置...${NC}"
    backup_dir="backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # 备份配置文件
    cp ss_nodes.conf "$backup_dir/"
    cp -r /etc/skim-ss/ "$backup_dir/"
    cp -r /etc/systemd/system/skim-ss-*.service "$backup_dir/"
    
    # 备份脚本
    cp deploy_ssserver.sh manage_ssserver.sh uninstall_ssserver.sh "$backup_dir/"
    
    # 创建压缩包
    tar -czf "${backup_dir}.tar.gz" "$backup_dir"
    rm -rf "$backup_dir"
    
    echo -e "${GREEN}备份完成: ${backup_dir}.tar.gz${NC}"
}

restore_config() {
    read -p "请输入备份文件路径: " backup_file
    
    if [[ -f "$backup_file" ]]; then
        echo -e "${GREEN}正在恢复配置...${NC}"
        tar -xzf "$backup_file"
        
        backup_dir=$(basename "$backup_file" .tar.gz)
        
        # 恢复配置文件
        cp "$backup_dir/ss_nodes.conf" .
        cp "$backup_dir/skim-ss"/* /etc/skim-ss/
        cp "$backup_dir"/skim-ss-*.service /etc/systemd/system/
        
        # 重新加载 systemd
        systemctl daemon-reload
        
        echo -e "${GREEN}配置恢复完成${NC}"
        echo -e "${YELLOW}请运行 'bash deploy_ssserver.sh' 重新部署节点${NC}"
    else
        echo -e "${RED}备份文件不存在${NC}"
    fi
}

# 主函数
case "$1" in
    list)
        list_nodes
        ;;
    status)
        check_status
        ;;
    restart)
        restart_all
        ;;
    stop)
        stop_all
        ;;
    start)
        start_all
        ;;
    logs)
        show_logs
        ;;
    add)
        add_node
        ;;
    remove)
        remove_node
        ;;
    backup)
        backup_config
        ;;
    restore)
        restore_config
        ;;
    *)
        show_help
        ;;
esac
