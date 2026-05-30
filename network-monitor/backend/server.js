const express = require("express");
const http    = require("http");
const { WebSocketServer } = require("ws");
const cors   = require("cors");
const { exec, spawn } = require("child_process");
const os     = require("os");

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

app.use(cors());
app.use(express.json());

// ── State ─────────────────────────────────────────────────────────────────────
let packets = [], alerts = [], connections = [];
let stats = { total:0, bytes:0, threats:0, dropped:0, startTime: Date.now() };
let capturing = false, simInterval = null, alertInterval = null;
let packetId = 1;

// ── Data generators ───────────────────────────────────────────────────────────
const R    = (a,b) => Math.floor(Math.random()*(b-a+1))+a;
const pick = arr   => arr[R(0,arr.length-1)];

const PROTOCOLS = ["HTTP","HTTPS","DNS","TCP","UDP","LDAP","Kerberos","RADIUS","ICMP","SSH","ARP","TLS","SMTP"];
const SRCS      = ["192.168.1.10","192.168.1.22","10.0.0.5","172.16.0.3","192.168.1.45","10.0.0.99","192.168.2.8","10.1.0.15"];
const DSTS      = ["8.8.8.8","10.0.0.1","192.168.1.1","104.21.44.1","1.1.1.1","52.96.148.18","172.217.160.78","185.199.108.153"];
const INFOS = {
  HTTP: ["GET /api/v1/auth HTTP/1.1","POST /login [user=admin&pass=***]","GET /admin/panel HTTP/1.1"],
  HTTPS:["TLSv1.3 Application Data","Client Hello SNI=corp.local","Change Cipher Spec"],
  DNS:  ["Std query A ldap.corp.local","Std query resp A 10.0.0.50","PTR query"],
  TCP:  ["SYN Seq=0 Win=64240 Len=0","SYN,ACK Seq=0 Ack=1","ACK Seq=1 Ack=1","RST,ACK"],
  UDP:  ["Src Port: 56123 Dst Port: 514 Len=68","Len=31"],
  LDAP: ["bindRequest cn=admin,dc=corp,dc=local","searchRequest dc=corp,dc=local","bindResponse success"],
  Kerberos:["AS-REQ cname:john.doe@CORP","TGS-REQ sname:HTTP/web.corp.local","AS-REP TGT issued"],
  RADIUS:  ["Access-Request id=12 User=john.doe","Access-Accept id=12","Access-Reject id=13"],
  ICMP:    ["Echo request id=0x1a2b seq=1","Echo reply id=0x1a2b seq=1","Dest Unreachable"],
  SSH:     ["Client: SSH-2.0-OpenSSH_8.9p1","Server: SSH-2.0-OpenSSH_8.4p1","Encrypted packet"],
  ARP:     ["Who has 192.168.1.1? Tell 192.168.1.10","192.168.1.1 is at aa:bb:cc:dd:ee:ff"],
  TLS:     ["Client Hello (TLSv1.3)","Server Hello + Certificate","Encrypted Alert"],
  SMTP:    ["EHLO mail.corp.local","AUTH LOGIN","MAIL FROM:<svc@corp.local>"],
};
const THREATS = [
  {name:"Kerberoasting Attack",    severity:"critical",cvss:9.1,category:"Credential Access",   rule:"ET EXPLOIT Kerberoasting TGS-REQ",    sig:"2027861",cve:"CVE-2022-33679"},
  {name:"SSH Brute Force",         severity:"critical",cvss:8.6,category:"Brute Force",          rule:"ET SCAN SSH Brute Force Attempt",      sig:"2001219",cve:"CVE-2023-38408"},
  {name:"LDAP Plaintext Auth",     severity:"high",    cvss:7.5,category:"Credential Exposure",  rule:"ET POLICY LDAP Cleartext Credentials", sig:"2003324",cve:null},
  {name:"SYN Port Scan",           severity:"high",    cvss:6.8,category:"Reconnaissance",       rule:"ET SCAN Nmap SYN Scan Detected",       sig:"2000537",cve:null},
  {name:"HTTP Plaintext Creds",    severity:"high",    cvss:7.2,category:"Credential Access",    rule:"ET CREDS HTTP Form Login Cleartext",   sig:"2013028",cve:null},
  {name:"DNS Tunneling",           severity:"medium",  cvss:5.5,category:"Command & Control",    rule:"ET DNS Long Domain Query",             sig:"2027868",cve:null},
  {name:"ARP Spoofing",            severity:"medium",  cvss:5.9,category:"Man-in-the-Middle",    rule:"ET ARP Spoofing Detected",             sig:"2008582",cve:null},
];

function genPacket() {
  const proto = pick(PROTOCOLS);
  const portMap = {HTTP:80,HTTPS:443,DNS:53,TCP:R(1024,9999),UDP:R(1024,9999),LDAP:389,Kerberos:88,RADIUS:1812,ICMP:0,SSH:22,ARP:0,TLS:443,SMTP:25};
  return {
    id: packetId++, timestamp: new Date().toISOString(),
    timeStr: new Date().toLocaleTimeString("en-GB",{hour12:false})+"."+String(R(0,999)).padStart(3,"0"),
    src: pick(SRCS), dst: pick(DSTS), proto,
    srcPort: R(1024,65535), dstPort: portMap[proto],
    size: R(40,1500), ttl: R(48,128),
    flags: proto==="TCP"?pick(["SYN","ACK","SYN-ACK","PSH-ACK","FIN-ACK","RST"]):"—",
    info: pick(INFOS[proto]||["Data"]),
  };
}

function broadcast(msg) {
  const data = JSON.stringify(msg);
  wss.clients.forEach(c => { if(c.readyState===1) c.send(data); });
}

// ── Simulation ────────────────────────────────────────────────────────────────
function startSim() {
  if(simInterval) return;
  simInterval = setInterval(()=>{
    if(!capturing) return;
    const batch = Array.from({length:R(3,8)}, genPacket);
    packets = [...batch, ...packets].slice(0,500);
    stats.total  += batch.length;
    stats.bytes  += batch.reduce((s,p)=>s+p.size,0);
    broadcast({type:"batch", data:batch});
    broadcast({type:"stats", data:{...stats, uptime:Date.now()-stats.startTime}});
  }, 700);

  alertInterval = setInterval(()=>{
    if(!capturing) return;
    if(Math.random()<0.2){
      const alert = {...pick(THREATS), id:Date.now(), time:new Date().toISOString(), src:pick(SRCS), dst:pick(DSTS), count:R(1,50)};
      alerts = [alert,...alerts].slice(0,100);
      stats.threats++;
      broadcast({type:"alert", data:alert});
    }
  }, 2500);
}
function stopSim() {
  clearInterval(simInterval); simInterval=null;
  clearInterval(alertInterval); alertInterval=null;
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
wss.on("connection", ws => {
  console.log("WS client connected");
  ws.send(JSON.stringify({type:"init", data:{packets:packets.slice(0,60), alerts:alerts.slice(0,20), stats, capturing}}));
  ws.on("close", ()=>console.log("WS client disconnected"));
});

// ── REST API ──────────────────────────────────────────────────────────────────
app.get("/api/health", (req,res) => res.json({status:"ok", uptime:process.uptime(), capturing, simMode:true, version:"2.0.0"}));

app.get("/api/packets", (req,res) => {
  let result = packets;
  const {limit=100, proto, src, dst, search} = req.query;
  if(proto&&proto!=="All") result=result.filter(p=>p.proto===proto);
  if(src)    result=result.filter(p=>p.src.includes(src));
  if(dst)    result=result.filter(p=>p.dst.includes(dst));
  if(search) result=result.filter(p=>JSON.stringify(p).toLowerCase().includes(search.toLowerCase()));
  res.json({count:result.length, packets:result.slice(0,parseInt(limit))});
});

app.get("/api/alerts",  (req,res) => res.json({count:alerts.length, alerts:alerts.slice(0,50)}));

app.get("/api/stats",   (req,res) => {
  const protoCount={};
  packets.forEach(p=>{protoCount[p.proto]=(protoCount[p.proto]||0)+1});
  const topSrc={}, topDst={};
  packets.slice(0,200).forEach(p=>{topSrc[p.src]=(topSrc[p.src]||0)+1;topDst[p.dst]=(topDst[p.dst]||0)+1});
  res.json({
    ...stats, uptime:Date.now()-stats.startTime,
    protoCount, packetCount:packets.length, alertCount:alerts.length,
    topSources:Object.entries(topSrc).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([ip,c])=>({ip,count:c})),
    topDests:Object.entries(topDst).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([ip,c])=>({ip,count:c})),
    sevCount:{critical:alerts.filter(a=>a.severity==="critical").length,high:alerts.filter(a=>a.severity==="high").length,medium:alerts.filter(a=>a.severity==="medium").length,low:0},
  });
});

app.get("/api/protocols", (req,res) => {
  const protoCount={};
  packets.forEach(p=>{protoCount[p.proto]=(protoCount[p.proto]||0)+1});
  const total=packets.length||1;
  res.json(Object.entries(protoCount).sort((a,b)=>b[1]-a[1]).map(([proto,count])=>({proto,count,pct:((count/total)*100).toFixed(2),bytes:count*R(60,200)})));
});

app.get("/api/connections", (req,res) => res.json([
  {proto:"TCP",local:"192.168.1.10:52341",remote:"10.0.0.1:80",state:"ESTABLISHED",pid:1234,process:"chrome",bytes:"1.2 MB",duration:"5m 12s"},
  {proto:"TCP",local:"192.168.1.22:22",remote:"10.0.0.5:54123",state:"ESTABLISHED",pid:5678,process:"sshd",bytes:"89 KB",duration:"12m 44s"},
  {proto:"TCP",local:"192.168.1.10:52350",remote:"10.0.0.50:389",state:"ESTABLISHED",pid:2345,process:"ldap",bytes:"12 KB",duration:"0m 45s"},
  {proto:"TCP",local:"10.0.0.99:54321",remote:"192.168.1.22:22",state:"SYN_SENT",pid:9999,process:"scanner",bytes:"4.2 KB",duration:"0m 01s"},
  {proto:"UDP",local:"192.168.1.10:60234",remote:"8.8.8.8:53",state:"—",pid:1234,process:"systemd",bytes:"2.1 KB",duration:"—"},
]));

app.get("/api/dns",  (req,res) => res.json(packets.filter(p=>p.proto==="DNS").slice(0,50).map(p=>({...p,query:p.info,type:"A",status:"NOERROR",ttl:R(60,900)}))));
app.get("/api/http", (req,res) => res.json(packets.filter(p=>p.proto==="HTTP"||p.proto==="HTTPS").slice(0,50)));

app.post("/api/capture/start", (req,res) => {
  if(capturing) return res.json({status:"already_running"});
  capturing=true; stats.startTime=Date.now();
  startSim();
  broadcast({type:"status",data:{capturing:true}});
  res.json({status:"started",mode:"simulation"});
});

app.post("/api/capture/stop", (req,res) => {
  capturing=false; stopSim();
  broadcast({type:"status",data:{capturing:false}});
  res.json({status:"stopped"});
});

app.delete("/api/data", (req,res) => {
  packets=[]; alerts=[];
  stats={total:0,bytes:0,threats:0,dropped:0,startTime:Date.now()};
  packetId=1;
  broadcast({type:"cleared"});
  res.json({status:"cleared"});
});

app.get("/api/interfaces", (req,res) => {
  exec("ip link show 2>/dev/null | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | cut -d@ -f1", (err,out)=>{
    const ifaces = out ? out.split("\n").filter(Boolean) : Object.keys(os.networkInterfaces());
    res.json({interfaces:ifaces});
  });
});

app.get("/api/geo", (req,res) => res.json([
  {country:"China",code:"CN",lat:35.86,lng:104.19,count:R(150,300),severity:"critical"},
  {country:"Russia",code:"RU",lat:61.52,lng:105.31,count:R(100,250),severity:"high"},
  {country:"United States",code:"US",lat:37.09,lng:-95.71,count:R(80,180),severity:"medium"},
  {country:"Germany",code:"DE",lat:51.16,lng:10.45,count:R(50,120),severity:"medium"},
  {country:"Brazil",code:"BR",lat:-14.23,lng:-51.92,count:R(30,90),severity:"low"},
]));

const PORT = process.env.PORT||4000;
server.listen(PORT, ()=>console.log(`\n🛡  NetWatch Backend v2.0\n   API:       http://localhost:${PORT}/api\n   WebSocket: ws://localhost:${PORT}\n   Health:    http://localhost:${PORT}/api/health\n`));
