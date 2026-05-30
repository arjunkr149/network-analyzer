#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Network Traffic Monitor — Ubuntu Server Setup Script
#  Run as root: sudo bash setup-server.sh
#  Tested on: Ubuntu 22.04 LTS
# ═══════════════════════════════════════════════════════════════════════════════

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }
err()  { echo -e "${RED}[✗] $1${NC}"; exit 1; }

echo -e "${BLUE}"
echo "  ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗"
echo "  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝"
echo "  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ "
echo "  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ "
echo "  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗"
echo "  Network Traffic Monitor — Auto Setup"
echo -e "${NC}"

# ── 1. System update ──────────────────────────────────────────────────────────
log "Step 1/9: Updating system..."
apt-get update -qq && apt-get upgrade -y -qq

# ── 2. Install dependencies ───────────────────────────────────────────────────
log "Step 2/9: Installing system packages..."
apt-get install -y -qq \
  git curl wget ufw nginx certbot python3-certbot-nginx \
  tshark wireshark-common net-tools \
  zeek suricata \
  docker.io docker-compose \
  fail2ban

# ── 3. Configure Docker ───────────────────────────────────────────────────────
log "Step 3/9: Configuring Docker..."
systemctl enable docker && systemctl start docker
usermod -aG docker $SUDO_USER 2>/dev/null || true

# ── 4. Configure UFW firewall ─────────────────────────────────────────────────
log "Step 4/9: Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 3000/tcp  # Grafana (restrict to your IP in prod!)
ufw allow 5601/tcp  # Kibana  (restrict to your IP in prod!)
ufw --force enable
log "Firewall configured"

# ── 5. Setup project directory ────────────────────────────────────────────────
log "Step 5/9: Setting up project directory..."
mkdir -p /opt/network-monitor
cd /opt/network-monitor

# Clone from GitHub (replace with your repo URL)
if [ ! -d ".git" ]; then
  warn "No git repo found. Creating from scratch..."
  log "Copy your project files to /opt/network-monitor/"
else
  git pull origin main
fi

# ── 6. Configure tshark permissions ──────────────────────────────────────────
log "Step 6/9: Configuring tshark permissions..."
dpkg-reconfigure wireshark-common <<< "yes" || true
groupadd -f wireshark
usermod -aG wireshark $SUDO_USER 2>/dev/null || true
chmod +x /usr/bin/dumpcap

# ── 7. Configure Zeek ─────────────────────────────────────────────────────────
log "Step 7/9: Configuring Zeek..."
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
sed -i "s/interface=eth0/interface=$IFACE/" /etc/zeek/zeekctl.cfg 2>/dev/null || true
zeekctl deploy 2>/dev/null || warn "Zeek deploy skipped — run 'zeekctl deploy' manually"

# ── 8. Configure Suricata ─────────────────────────────────────────────────────
log "Step 8/9: Configuring Suricata..."
suricata-update 2>/dev/null || true
systemctl enable suricata && systemctl start suricata || true

# ── 9. Start all services via Docker Compose ──────────────────────────────────
log "Step 9/9: Starting Docker Compose stack..."
cd /opt/network-monitor

# Create .env file
cat > .env << EOF
NODE_ENV=production
REACT_APP_API_URL=http://$(hostname -I | awk '{print $1}')/api
REACT_APP_WS_URL=ws://$(hostname -I | awk '{print $1}')/ws
EOF

docker-compose pull
docker-compose up -d

# Wait for services
log "Waiting for services to start (30 seconds)..."
sleep 30

# Health check
if curl -sf http://localhost:4000/api/health > /dev/null; then
  log "Backend API: ✅ Running"
else
  warn "Backend API: ⚠️  Check with: docker-compose logs backend"
fi

SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Network Monitor Deployed Successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  🌐 Dashboard:    ${BLUE}http://$SERVER_IP${NC}"
echo -e "  📊 Grafana:      ${BLUE}http://$SERVER_IP:3001${NC}  (admin/admin123)"
echo -e "  🔍 Kibana:       ${BLUE}http://$SERVER_IP:5601${NC}"
echo -e "  🔌 API Health:   ${BLUE}http://$SERVER_IP:4000/api/health${NC}"
echo ""
echo -e "  📝 Logs:  docker-compose logs -f"
echo -e "  🔄 Restart: docker-compose restart"
echo -e "  🛑 Stop:  docker-compose down"
echo ""
echo -e "${YELLOW}  Next steps:${NC}"
echo -e "  1. Add SSL: sudo certbot --nginx -d yourdomain.com"
echo -e "  2. Add GitHub Secrets: SERVER_HOST, SERVER_USER, SERVER_SSH_KEY"
echo -e "  3. Push to GitHub → auto-deploys via GitHub Actions"
echo ""
