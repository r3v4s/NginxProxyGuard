#!/bin/sh
set -e

CERT_DIR="/etc/nginx/ssl"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"

# Create SSL directory if not exists
mkdir -p "$CERT_DIR"

# Generate 100-year self-signed certificate if not exists
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating 100-year self-signed SSL certificate for Nginx Proxy Guard UI..."

    openssl req -x509 -nodes -days 36500 \
        -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/C=KR/ST=Seoul/L=Seoul/O=Nginx Proxy Guard/OU=Security/CN=nginx-proxy-guard" \
        -addext "subjectAltName=DNS:localhost,DNS:nginx-proxy-guard,IP:127.0.0.1"

    chmod 644 "$CERT_FILE"
    chmod 600 "$KEY_FILE"

    echo "SSL certificate generated successfully!"
    echo "  - Certificate: $CERT_FILE"
    echo "  - Private Key: $KEY_FILE"
    echo "  - Validity: 100 years (36500 days)"
fi

# Where Docker cannot open ports below 1024 to non-root processes (kernels
# older than 4.11, e.g. Synology DSM 7), nginx binds 443 only through the
# capability on its binary, which no-new-privileges cancels. Say how to fix
# it before nginx fails with "bind() to 0.0.0.0:443 failed (13: Permission
# denied)".
floor=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)
if [ "$(id -u)" != 0 ] && [ "$floor" -gt 443 ] && grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status; then
    echo "[Entrypoint] ERROR: this host keeps port 443 privileged and no-new-privileges stops nginx from binding it." >&2
    echo "[Entrypoint] In docker-compose.yml, delete the 'security_opt' and '- \"no-new-privileges:true\"' lines of the ui service, then run: docker compose up -d" >&2
fi

# Start nginx
exec nginx -g 'daemon off;'
