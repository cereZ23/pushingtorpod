#!/usr/bin/env bash
# =============================================================================
# EASM Platform — Secure Production Deployment
# Target: easm.securekt.com (146.190.178.108)
# =============================================================================
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
SERVER_IP="146.190.178.108"
SERVER_USER="root"
SSH_KEY="$HOME/Downloads/id_rsa_inspectra"
REMOTE_DIR="/opt/easm"
DOMAIN="easm.securekt.com"

SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
SSH_CMD="ssh $SSH_OPTS ${SERVER_USER}@${SERVER_IP}"
SCP_CMD="scp $SSH_OPTS"
RSYNC_CMD="rsync -az --progress -e \"ssh $SSH_OPTS\""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# ── Pre-flight checks ───────────────────────────────────────────────
echo "=========================================="
echo "  EASM Secure Production Deploy"
echo "  Target: ${DOMAIN} (${SERVER_IP})"
echo "=========================================="
echo ""

# Check SSH key exists
[[ -f "$SSH_KEY" ]] || err "SSH key not found: $SSH_KEY"

# Check SSH key permissions
PERM=$(stat -f "%Lp" "$SSH_KEY" 2>/dev/null || stat -c "%a" "$SSH_KEY" 2>/dev/null)
if [[ "$PERM" != "600" && "$PERM" != "400" ]]; then
    warn "Fixing SSH key permissions (was $PERM)"
    chmod 600 "$SSH_KEY"
fi

# Test SSH connectivity
log "Testing SSH connection..."
$SSH_CMD "echo 'SSH OK'" || err "Cannot connect to ${SERVER_IP}. Check SSH key and network."

# ── Step 1: Server hardening ────────────────────────────────────────
log "Step 1/6: Server hardening..."
$SSH_CMD bash -s <<'HARDEN_EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[*] Updating packages..."
apt-get update -qq && apt-get upgrade -yqq

echo "[*] Installing essentials..."
apt-get install -yqq ufw fail2ban curl git unattended-upgrades

# ── Firewall (UFW) ──
echo "[*] Configuring firewall..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP (Caddy redirect)'
ufw allow 443/tcp comment 'HTTPS (Caddy)'
ufw allow 443/udp comment 'HTTP/3 (QUIC)'
echo "y" | ufw enable

# ── Fail2ban ──
echo "[*] Configuring fail2ban..."
cat > /etc/fail2ban/jail.local <<'F2B'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 7200
F2B
systemctl enable fail2ban
systemctl restart fail2ban

# ── SSH hardening ──
echo "[*] Hardening SSH..."
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

# ── Automatic security updates ──
echo "[*] Enabling automatic security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'AUTO'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTO

# ── Kernel hardening (sysctl) ──
echo "[*] Applying kernel hardening..."
cat > /etc/sysctl.d/99-easm-hardening.conf <<'SYSCTL'
# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1
# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
# Log martian packets
net.ipv4.conf.all.log_martians = 1
# Disable IP forwarding (not a router)
net.ipv4.ip_forward = 0
# Increase file descriptors for high-concurrency
fs.file-max = 65535
SYSCTL
sysctl -p /etc/sysctl.d/99-easm-hardening.conf >/dev/null 2>&1

echo "[*] Server hardening complete."
HARDEN_EOF
log "Server hardening done."

# ── Step 2: Install Docker ──────────────────────────────────────────
log "Step 2/6: Installing Docker..."
$SSH_CMD bash -s <<'DOCKER_EOF'
set -euo pipefail
if command -v docker &>/dev/null; then
    echo "[*] Docker already installed: $(docker --version)"
else
    echo "[*] Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    echo "[*] Docker installed: $(docker --version)"
fi

# Ensure compose plugin
if docker compose version &>/dev/null; then
    echo "[*] Docker Compose plugin: $(docker compose version)"
else
    echo "[*] Installing Docker Compose plugin..."
    apt-get install -yqq docker-compose-plugin
fi
DOCKER_EOF
log "Docker ready."

# ── Step 3: Transfer files ──────────────────────────────────────────
log "Step 3/6: Transferring project files..."
$SSH_CMD "mkdir -p ${REMOTE_DIR}"

# rsync project (exclude dev artifacts)
eval $RSYNC_CMD \
    --exclude='.git/' \
    --exclude='.claude/' \
    --exclude='node_modules/' \
    --exclude='frontend/node_modules/' \
    --exclude='frontend/dist/' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='.env' \
    --exclude='.env.*' \
    --exclude='*.jsonl' \
    --exclude='htmlcov/' \
    --exclude='.pytest_cache/' \
    --exclude='.mypy_cache/' \
    --exclude='*.mmdb' \
    --exclude='.specify/' \
    ./ "${SERVER_USER}@${SERVER_IP}:${REMOTE_DIR}/"

log "Files transferred."

# ── Step 4: Generate secrets & .env ─────────────────────────────────
log "Step 4/6: Generating production secrets..."
$SSH_CMD bash -s <<SECRETS_EOF
set -euo pipefail
cd ${REMOTE_DIR}

# Only generate .env if it doesn't exist (preserve existing secrets on redeploy)
if [[ -f .env ]]; then
    echo "[*] .env already exists — preserving existing secrets."
    echo "[*] To regenerate, delete .env and re-run deploy."
else
    echo "[*] Generating cryptographically strong secrets..."

    DB_PASS=\$(openssl rand -base64 32 | tr -d '=/+' | head -c 40)
    REDIS_PASS=\$(openssl rand -base64 32 | tr -d '=/+' | head -c 40)
    MINIO_USER="easm\$(openssl rand -hex 4)"
    MINIO_PASS=\$(openssl rand -base64 32 | tr -d '=/+' | head -c 40)
    SECRET=\$(openssl rand -base64 64 | tr -d '=/+' | head -c 86)
    JWT_SECRET=\$(openssl rand -base64 64 | tr -d '=/+' | head -c 86)
    MFA_KEY=\$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || openssl rand -base64 32)

    cat > .env <<ENV
# =============================================================================
# EASM Production Environment — AUTO-GENERATED $(date -u +%Y-%m-%dT%H:%M:%SZ)
# =============================================================================
# SECURITY: This file contains secrets. Never commit to git.

ENVIRONMENT=production

# Database
DB_PASSWORD=\${DB_PASS}

# Redis
REDIS_PASSWORD=\${REDIS_PASS}

# MinIO
MINIO_USER=\${MINIO_USER}
MINIO_PASSWORD=\${MINIO_PASS}

# Application secrets
SECRET_KEY=\${SECRET}
JWT_SECRET_KEY=\${JWT_SECRET}
MFA_ENCRYPTION_KEY=\${MFA_KEY}

# Performance
API_WORKERS=2
LOG_LEVEL=warning
ENV

    chmod 600 .env
    echo "[*] .env generated with strong secrets."
fi
SECRETS_EOF
log "Secrets configured."

# ── Step 5: Build & start ───────────────────────────────────────────
log "Step 5/6: Building and starting containers..."
$SSH_CMD bash -s <<START_EOF
set -euo pipefail
cd ${REMOTE_DIR}

echo "[*] Creating data directory for GeoIP databases..."
mkdir -p data/geoip

echo "[*] Pulling base images..."
docker compose -f docker-compose.prod.yml pull --ignore-buildable 2>/dev/null || true

echo "[*] Building images..."
docker compose -f docker-compose.prod.yml build --no-cache

echo "[*] Starting services..."
docker compose -f docker-compose.prod.yml up -d

echo "[*] Waiting for services to initialize (30s)..."
sleep 30

echo "[*] Container status:"
docker compose -f docker-compose.prod.yml ps
START_EOF
log "Services started."

# ── Step 6: Verify deployment ───────────────────────────────────────
log "Step 6/6: Verifying deployment..."

echo ""
echo "Waiting 15s for Caddy to obtain SSL certificate..."
sleep 15

# Check health endpoint
echo -n "  Health check: "
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${DOMAIN}/health" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    echo -e "${GREEN}OK (200)${NC}"
elif [[ "$HTTP_CODE" == "503" ]]; then
    warn "Service degraded (503) — some backends may still be starting"
else
    warn "Got HTTP ${HTTP_CODE} — Caddy may still be provisioning SSL"
fi

# Check frontend
echo -n "  Frontend:     "
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${DOMAIN}/" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    echo -e "${GREEN}OK (200)${NC}"
else
    warn "Got HTTP ${HTTP_CODE}"
fi

# Check that internal ports are NOT exposed
echo -n "  Port 5432:    "
$SSH_CMD "ss -tlnp | grep -q ':5432.*0.0.0.0' && echo 'EXPOSED (BAD)' || echo 'internal only (good)'"
echo -n "  Port 6379:    "
$SSH_CMD "ss -tlnp | grep -q ':6379.*0.0.0.0' && echo 'EXPOSED (BAD)' || echo 'internal only (good)'"
echo -n "  Port 9000:    "
$SSH_CMD "ss -tlnp | grep -q ':9000.*0.0.0.0' && echo 'EXPOSED (BAD)' || echo 'internal only (good)'"
echo -n "  Port 8000:    "
$SSH_CMD "ss -tlnp | grep -q ':8000.*0.0.0.0' && echo 'EXPOSED (BAD)' || echo 'internal only (good)'"

# Firewall status
echo ""
echo "  Firewall:"
$SSH_CMD "ufw status | head -10"

echo ""
echo "=========================================="
echo -e "  ${GREEN}Deployment complete!${NC}"
echo "  https://${DOMAIN}"
echo "=========================================="
echo ""
echo "Useful commands:"
echo "  ssh $SSH_OPTS ${SERVER_USER}@${SERVER_IP}"
echo "  cd ${REMOTE_DIR}"
echo "  docker compose -f docker-compose.prod.yml logs -f"
echo "  docker compose -f docker-compose.prod.yml ps"
echo "  docker compose -f docker-compose.prod.yml restart api"
