# 🛡️ Network Traffic Monitor — Wireshark + ELK Stack

> **Access Control & Identity Management Project**
> Real-time network packet monitoring with threat detection, protocol analysis, and hosted dashboard.

---

## 🚀 Quick Start (3 commands)

```bash
git clone https://github.com/YOUR_USERNAME/network-monitor.git
cd network-monitor
docker-compose up -d
```

Open **http://localhost** → Dashboard ready!

---

## 📁 Project Structure

```
network-monitor/
├── backend/              ← Node.js + WebSocket API
│   ├── server.js         ← Main server (tshark + simulation)
│   ├── Dockerfile
│   └── package.json
├── frontend/             ← React dashboard
│   ├── src/
│   │   ├── App.js        ← Main dashboard component
│   │   └── App.css       ← Styles
│   ├── Dockerfile
│   └── package.json
├── nginx/
│   └── nginx.conf        ← Reverse proxy + WebSocket
├── docker/
│   ├── logstash.conf     ← Log pipeline
│   └── grafana-datasource.yml
├── .github/
│   └── workflows/
│       └── deploy.yml    ← Auto CI/CD pipeline
├── docker-compose.yml    ← Full stack orchestration
├── setup-server.sh       ← One-command Ubuntu setup
└── README.md
```

---

## 🖥️ Local Development

### Prerequisites
- Node.js 18+
- Docker + Docker Compose

### Run Backend
```bash
cd backend
npm install
npm start          # starts on http://localhost:4000
```

### Run Frontend
```bash
cd frontend
npm install
npm start          # starts on http://localhost:3000
```

### Run Full Stack
```bash
docker-compose up -d
```

---

## ☁️ Deploy to Ubuntu Server (Hosting Level)

### Option A: One-Command Setup
```bash
# On your Ubuntu 22.04 server:
git clone https://github.com/YOUR_USERNAME/network-monitor.git /opt/network-monitor
cd /opt/network-monitor
sudo bash setup-server.sh
```

### Option B: Manual Step-by-Step

**Step 1 — Provision server** (AWS/DigitalOcean/Azure):
```
OS: Ubuntu 22.04 LTS
RAM: 4GB minimum
CPU: 2 vCPU
Storage: 20GB SSD
Ports open: 22, 80, 443
```

**Step 2 — SSH into server and install**:
```bash
ssh ubuntu@YOUR_SERVER_IP

# Install Docker
sudo apt update
sudo apt install -y docker.io docker-compose git tshark

# Clone project
git clone https://github.com/YOUR_USERNAME/network-monitor.git /opt/network-monitor
cd /opt/network-monitor
```

**Step 3 — Set environment**:
```bash
cat > .env << EOF
REACT_APP_API_URL=http://YOUR_SERVER_IP/api
REACT_APP_WS_URL=ws://YOUR_SERVER_IP/ws
EOF
```

**Step 4 — Start all services**:
```bash
docker-compose up -d
```

**Step 5 — Add SSL (free)**:
```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

### URLs after deployment:

| Service      | URL                          |
|--------------|------------------------------|
| Dashboard    | http://YOUR_IP               |
| Grafana      | http://YOUR_IP:3001          |
| Kibana       | http://YOUR_IP:5601          |
| API Health   | http://YOUR_IP/api/health    |
| WebSocket    | ws://YOUR_IP/ws              |

---

## 🤖 GitHub Actions Auto-Deploy

### Setup (one time):
1. Fork/clone this repo to GitHub
2. Go to **Settings → Secrets → Actions**, add:

| Secret Name       | Value                          |
|-------------------|--------------------------------|
| `SERVER_HOST`     | Your server IP or domain       |
| `SERVER_USER`     | `ubuntu` or `root`             |
| `SERVER_SSH_KEY`  | Your private SSH key content   |
| `DOCKER_USERNAME` | Your Docker Hub username       |
| `DOCKER_PASSWORD` | Your Docker Hub password/token |

3. Push to `main` branch → auto deploys! 🚀

---

## 🔧 API Reference

| Endpoint                  | Method | Description                        |
|---------------------------|--------|------------------------------------|
| `/api/health`             | GET    | Server health check                |
| `/api/packets`            | GET    | Get captured packets (filterable)  |
| `/api/alerts`             | GET    | Get IDS alerts                     |
| `/api/stats`              | GET    | Traffic statistics + proto counts  |
| `/api/capture/start`      | POST   | Start packet capture               |
| `/api/capture/stop`       | POST   | Stop capture                       |
| `/api/data`               | DELETE | Clear all data                     |

### WebSocket Events (ws://host/ws):
```json
{ "type": "batch",   "data": [...packets] }
{ "type": "alert",   "data": { alert } }
{ "type": "stats",   "data": { stats } }
{ "type": "status",  "data": { "capturing": true } }
{ "type": "cleared"  }
```

---

## 🔍 Real tshark Capture

By default the backend runs in **simulation mode**. To enable real capture:

```bash
# On the capture server — start via API with mode=real
curl -X POST http://localhost:4000/api/capture/start \
  -H "Content-Type: application/json" \
  -d '{"mode": "real", "interface": "eth0"}'

# Or run tshark manually and pipe to Elasticsearch:
tshark -i eth0 -T ek | curl -s -XPOST "http://localhost:9200/packets/_bulk" \
  -H "Content-Type: application/json" --data-binary @-
```

---

## 🛡️ Security Protocols Monitored

| Protocol  | Port | What We Detect                           |
|-----------|------|------------------------------------------|
| Kerberos  | 88   | AS-REQ/TGS-REQ, Kerberoasting patterns  |
| LDAP      | 389  | bindRequest credentials, enumeration     |
| RADIUS    | 1812 | Access-Request/Reject, replay attacks    |
| SSH       | 22   | Brute force, unauthorized logins         |
| HTTP      | 80   | Plaintext POST credentials               |
| NTLM      | var  | Challenge-response, Pass-the-Hash        |

---

## 🐳 Docker Services

| Container         | Purpose                | Port |
|-------------------|------------------------|------|
| `nm_backend`      | Node.js API + WebSocket | 4000 |
| `nm_frontend`     | React dashboard         | 3000 |
| `nm_nginx`        | Reverse proxy + SSL     | 80/443|
| `nm_elasticsearch`| Search + indexing       | 9200 |
| `nm_logstash`     | Log pipeline            | 5044 |
| `nm_kibana`       | Log visualization       | 5601 |
| `nm_grafana`      | Metrics dashboard       | 3001 |

---

## 📊 Tech Stack

```
Frontend:  React 18 + Recharts + WebSocket
Backend:   Node.js + Express + ws
Capture:   tshark (Wireshark CLI) + Zeek + Suricata
Storage:   Elasticsearch 8
Pipeline:  Logstash + Filebeat
Dashboard: Grafana + Kibana
Proxy:     Nginx + SSL (Let's Encrypt)
CI/CD:     GitHub Actions
Container: Docker + Docker Compose
```

---

## 📝 Academic Context

This project was built for the **Access Control & Identity Management** course to demonstrate:
- Real-time network traffic analysis
- Identity protocol monitoring (Kerberos, LDAP, RADIUS)
- Threat detection and alerting
- Hosted, production-grade monitoring infrastructure

---

## ⚠️ Ethical Notice

Only capture traffic on networks you **own or have explicit permission** to monitor.
Unauthorized packet capture is illegal under computer crime laws in most jurisdictions.
