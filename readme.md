# SkimProxy.sh

SkimProxy.sh is a minimalistic Bash-based toolchain to deploy proxy servers with as little code as possible. No bloat, just results.

## ⚠️ Warning

- Not yet tested on **Alpine Linux** — use at your own risk.
- Assumes a standard Linux environment with `bash`, `wget`, and basic utilities available.
- Assumes a functional human brain or at least an 8b LLM.

## 📦 Usage

Each argument is optional. Use `"auto"` to let the script decide, or leave all blank to use full defaults.

- **Port**: random between `10000–60000`
- **Version**: latest release
- **Password**: `openssl rand -base64 16`

### 🛡️ Shadowsocks-Rust

- **Cipher**: defaults to `2022-blake3-aes-128-gcm`

  when `Cipher` = `2022-blake3-aes-256-gcm`, `password` = `openssl rand -base64 32`

  see https://shadowsocks.org/doc/aead.html

  for ss2022 or SIP022 see https://shadowsocks.org/doc/sip022.html

```
wget -qO ssserver.sh https://skimproxy.pages.dev/ssserver.sh && bash ssserver.sh <port> <cipher> <version> <hostname>
```

Minimal:

```bash
wget -qO ssserver.sh https://skimproxy.pages.dev/ssserver.sh && bash ssserver.sh
```

### ⚡ Hysteria 2

```bash 
wget https://skimproxy.pages.dev/hy2.sh -q -O hy2.sh && bash hy2.sh <port> <version> <hostname>
```

Minimal:

```bash
wget https://skimproxy.pages.dev/hy2.sh -q -O hy2.sh && bash hy2.sh
```

### 🚀 Enable BBR + FQ_PIE

```bash
echo "net.core.default_qdisc=fq_pie" >> /etc/sysctl.conf && \
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf && \
sysctl -p
```