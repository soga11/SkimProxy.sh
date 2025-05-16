#!/bin/bash

GREEN_BG='\033[42;30m'   # Underlined, green background, black text
RED_BG='\033[41;97m'     # Red background (41), white text (97)
WHITE_BG='\033[47;30m'   # White background (47), black text (30)
NORMAL='\033[0m'         # Reset formatting

# Check if the script is being run as root
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

# Accept IP argument or fetch the IP from Cloudflare CDN trace
if [ -z "$3" ] || [ "$3" = "auto" ]; then
  ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -4 | grep -oP '(?<=ip=).*')
  if [ -z "$ip" ]; then
    ip=$(curl -s https://cloudflare.com/cdn-cgi/trace -6 | grep -oP '(?<=ip=).*')
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
    input="$1"
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

# Function to detect the package manager and install missing packages
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

# Install required tools if missing
for tool in curl jq tar openssl xz; do
  if ! command -v "$tool" &> /dev/null; then
    echo -e "${GREEN_BG}[Requirements] Installing missing dependencies...${NORMAL}"
    install_packages
    break
  fi
done

# Get the latest release version from GitHub API
get_latest_version() {
  latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r .tag_name)
  if [[ "$latest_version" == "null" ]]; then
    echo -e "${RED_BG}Unable to fetch latest version from GitHub.${NORMAL}"
    echo "app/v2.6.1"
  else
    echo "$latest_version"
  fi
}

# Set version argument or fallback to latest
if [ -z "$2" ] || [ "$2" = "auto" ]; then
  version=$(get_latest_version)
else
  version="$2"
fi

### Install hy2 core
# - Create target directory
mkdir -p /opt/hy2-unmanned
# - Construct the download URL
url="https://github.com/apernet/hysteria/releases/download/${version}/hysteria-linux-${arch}"
# - Download and extract
echo -e "${GREEN_BG}Downloading ${url}...${NORMAL}"
curl -s -L -o /opt/hy2-unmanned/hy2 "$url"
chmod +x /opt/hy2-unmanned/hy2
echo -e "${GREEN_BG}hy2 core installed to /opt/hy2-unmanned${NORMAL}"

### Generate config
# Accept port argument or generate a random port
if [ -z "$1" ] || [ "$1" = "auto" ]; then
  port=$((RANDOM % 50000 + 10000))
else
  port=$1
fi
# Make config folder for the spec port
mkdir -p /opt/hy2-unmanned/$port
# Generate password using openssl
password=$(openssl rand -base64 16)
# Self-sign cert
cat <<EOF > /opt/hy2-unmanned/$port/openssl.conf
[ req ]
default_bits           = 1024
prompt                 = no
default_md             = sha256
distinguished_name     = dn
x509_extensions        = v3_ext

[ dn ]
C                      = AQ
ST                     = unmanned
L                      = unmanned
O                      = unmanned
OU                     = unmanned
CN                     = www.gov.hk

[ v3_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = www.gov.hk
EOF
openssl req -x509 -new -nodes -days 3650 -keyout /opt/hy2-unmanned/$port/server.key -out /opt/hy2-unmanned/$port/server.crt -config /opt/hy2-unmanned/$port/openssl.conf

# Print the config
echo -e "${GREEN_BG}Using address${NORMAL}: $ip:$port"
echo -e "${GREEN_BG}Generated password${NORMAL}: $password"
echo -e "${GREEN_BG}Server CA SHA256${NORMAL}: $(openssl x509 -noout -fingerprint -sha256 -in /opt/hy2-unmanned/$port/server.crt)"

# Create hy2 config
  cat <<EOF > /opt/hy2-unmanned/$port/config.yaml
listen: :${port}
tls:
  cert: /opt/hy2-unmanned/${port}/server.crt
  key: /opt/hy2-unmanned/${port}/server.key
auth:
  type: password
  password: $password
EOF

# Create system service based on init system
init_system=$(cat /proc/1/comm)
if [[ "$init_system" == "systemd" ]]; then
  cat <<EOF > /etc/systemd/system/hy2-${port}.service
[Unit]
Description=Hysteria 2 Server on :${port}
After=network.target

[Service]
Environment="HYSTERIA_LOG_LEVEL=error"
ExecStart=/opt/hy2-unmanned/hy2 server -c /opt/hy2-unmanned/$port/config.yaml
Restart=on-failure
StandardOutput=append:/var/log/hy2-$port.log
StandardError=append:/var/log/hy2-$port.log

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hy2-${port}
  systemctl start hy2-${port}
  echo -e "${WHITE_BG}TO REMOVE THIS SERVICE:${NORMAL} systemctl disable --now hy2-${port} && rm /etc/systemd/system/hy2-${port}.service && rm -rf /opt/hy2-unmanned/$port"

elif [[ "$init_system" == "init" || "$init_system" == "openrc" ]]; then
  cat <<EOF > /etc/init.d/hy2-$port
#!/sbin/openrc-run

name="Hysteria 2 Server on :$port"
description="Hysteria 2 server on :$port"
command="/opt/hy2-unmanned/hy2"
command_args=" server -c /opt/hy2-unmanned/$port/config.yaml"
pidfile="/var/run/hy2-$port.pid"
logfile="/var/log/hy2-$port.log"

depend() {
    need net
    after firewall
}

log_to_file() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $message" >> "$logfile"
}

start() {
    ebegin "Starting $SERVICE_NAME"

    # Use respawn to start and monitor the service
    respawn -p "$pidfile" "$command" "$command_args" >> "$logfile" 2>&1 & # Redirect stdout and stderr to log

    if [ $? -eq 0 ]; then
        log_to_file "$SERVICE_NAME started successfully."
        eend 0  # Success
    else
        log_to_file "Failed to start $SERVICE_NAME."
        eend 1  # Failure
    fi
}

stop() {
    ebegin "Stopping $SERVICE_NAME"

    # Use kill to stop the process (more direct with respawn)
    if [ -f "$pidfile" ]; then
      PID=$(cat "$pidfile")
      kill "$PID"
      rm "$pidfile"
      log_to_file "$SERVICE_NAME stopped."
      eend 0
    else
      log_to_file "PID file not found for $SERVICE_NAME.  Assuming already stopped."
      eend 0 # Treat as success, as it seems to be already stopped
    fi

}

restart() {
    stop
    start
}
EOF

  chmod +x /etc/init.d/hy2-${port}
  rc-update add hy2-${port} default
  rc-service hy2-${port} start
  echo -e "${WHITE_BG}TO REMOVE THIS SERVICE:${NORMAL} rc-update del hy2-${port} default && rc-service hy2-${port} stop && rm /etc/init.d/hy2-${port} && rm -rf /opt/hy2-unmanned/$port"

else
  echo -e "${RED_BG}Unsupported init system: $init_system.${NORMAL}"
  exit 1
fi

# Generate hy2:// URL
hy2_url="hy2://$(urlencode $password)@$ip:$port/?insecure=1&sni=www.gov.hk#SkimProxy.sh+Hysteria2+$ip:$port"
# Generate JSON configuration
json_config=$(cat <<EOF
{
  "type": "hysteria2",
  "tag": "hysteria2-server",
  "server": "$ip",
  "server_port": $port,
  "password": "$password"
}
EOF
)
echo -e "${GREEN_BG}Hysteria 2 URL:${NORMAL} $hy2_url"
echo -e "${GREEN_BG}JSON configuration:${NORMAL} $json_config"

echo -e "${GREEN_BG}Hysteria 2 installed.${NORMAL}"
echo -e "${GREEN_BG}Service hy2-${port} has been started.${NORMAL}"

