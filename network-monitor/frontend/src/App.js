import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line
} from "recharts";
import "./App.css";

// ── Palette ───────────────────────────────────────────────────────────────────
const C = {
  cyan:"#00e5ff", green:"#00ff9f", red:"#ff2d55",
  yellow:"#ffd60a", purple:"#c084fc", orange:"#fb923c",
  text:"#cce4ff", dim:"#5a8aaa", muted:"#2a4a62",
  bg2:"#071525", border:"#0d2540",
};
const PC = {
  HTTP:"#fb923c",HTTPS:"#4ade80",DNS:"#60a5fa",TCP:"#94a3b8",
  UDP:"#a8b5c5",LDAP:"#facc15",Kerberos:"#e879f9",RADIUS:"#22d3ee",
  ICMP:"#f87171",SSH:"#86efac",ARP:"#d4a574",TLS:"#2dd4bf",
  SMTP:"#ff8c69",FTP:"#ffe082",SNMP:"#b39ddb",
};
const SC = {
  critical:{bg:"#1a0512",border:"#ff2d55",text:"#ff2d55"},
  high:    {bg:"#1a1000",border:"#ffd60a",text:"#ffd60a"},
  medium:  {bg:"#001828",border:"#00e5ff",text:"#00e5ff"},
  low:     {bg:"#001a10",border:"#00ff9f",text:"#00ff9f"},
};

// ── Helpers ───────────────────────────────────────────────────────────────────
const R = (a,b) => Math.floor(Math.random()*(b-a+1))+a;
const pick = a => a[R(0,a.length-1)];

const PROTOS = ["HTTP","HTTPS","DNS","TCP","UDP","LDAP","Kerberos","RADIUS","ICMP","SSH","ARP","TLS","SMTP"];
const SRCS   = ["192.168.1.10","192.168.1.22","10.0.0.5","172.16.0.3","192.168.1.45","10.0.0.99","192.168.2.8","10.1.0.15","192.168.0.254","10.10.0.22"];
const DSTS   = ["8.8.8.8","10.0.0.1","192.168.1.1","104.21.44.1","1.1.1.1","52.96.148.18","172.217.160.78","185.199.108.153","142.250.80.46","140.82.114.3"];
const INFOS  = {
  HTTP: ["GET /api/v1/auth HTTP/1.1","POST /login  [user=admin&pass=***]","GET /admin/panel HTTP/1.1 [200 OK]","OPTIONS /api/users HTTP/1.1"],
  HTTPS:["TLSv1.3 Application Data len=1342","Client Hello (SNI=corp.local)","Server Hello + Certificate","Change Cipher Spec"],
  DNS:  ["Std query A ldap.corp.local","Std query resp A 10.0.0.50 (TTL 300)","Std query AAAA github.com","PTR 10.0.168.192.in-addr.arpa"],
  TCP:  ["SYN Seq=0 Win=64240 Len=0 MSS=1460","SYN,ACK Seq=0 Ack=1 Win=65535","ACK Seq=1 Ack=1 Len=0","RST,ACK Seq=1 Ack=1"],
  UDP:  ["Src Port: 56123  Dst Port: 514  Len=68","Src Port: 60234  Dst Port: 53  Len=31"],
  LDAP: ["bindRequest(1) cn=admin,dc=corp,dc=local  simple","searchRequest(2) dc=corp,dc=local [objectClass=*]","searchResEntry  cn=users,dc=corp,dc=local","bindResponse(1) success"],
  Kerberos:["AS-REQ  cname: john.doe@CORP  realm: CORP.LOCAL","AS-REP  cname: john.doe@CORP (TGT issued)","TGS-REQ sname: HTTP/web.corp.local","TGS-REP (Service Ticket issued)"],
  RADIUS:  ["Access-Request id=12 User=john.doe NAS-IP=10.0.0.1","Access-Accept id=12 (auth OK)","Access-Reject id=13 (auth FAIL)","Accounting-Request Acct-Status=Start"],
  ICMP:    ["Echo (ping) request  id=0x1a2b seq=1 ttl=64","Echo (ping) reply    id=0x1a2b seq=1 ttl=128","Dest Unreachable (Port unreachable)","Time-to-live exceeded in transit"],
  SSH:     ["Client: SSH-2.0-OpenSSH_8.9p1 Ubuntu","Server: SSH-2.0-OpenSSH_8.4p1 Debian","Encrypted packet  len=92","Newkeys / Algorithm Negotiation"],
  ARP:     ["Who has 192.168.1.1? Tell 192.168.1.10","192.168.1.1 is at aa:bb:cc:dd:ee:ff","ARP Reply (Gratuitous)","Duplicate IP detected: 192.168.1.50"],
  TLS:     ["Client Hello  (TLSv1.3)","Server Hello + Certificate (RSA-2048)","Certificate Verify + Finished","Encrypted Alert (close_notify)"],
  SMTP:    ["EHLO mail.corp.local","AUTH LOGIN (base64 credentials)","MAIL FROM:<svc@corp.local>","DATA (email body)"],
};
const THREATS_DATA = [
  {name:"Kerberoasting Attack",    severity:"critical",cvss:9.1,cat:"Credential Access",  rule:"ET EXPLOIT Kerberoasting TGS-REQ",    sig:"2027861",cve:"CVE-2022-33679"},
  {name:"SSH Brute Force",         severity:"critical",cvss:8.6,cat:"Brute Force",         rule:"ET SCAN SSH Brute Force Attempt",      sig:"2001219",cve:"CVE-2023-38408"},
  {name:"LDAP Plaintext Auth",     severity:"high",    cvss:7.5,cat:"Credential Exposure", rule:"ET POLICY LDAP Cleartext Credentials", sig:"2003324",cve:null},
  {name:"SYN Port Scan",           severity:"high",    cvss:6.8,cat:"Reconnaissance",      rule:"ET SCAN Nmap SYN Scan Detected",       sig:"2000537",cve:null},
  {name:"HTTP Plaintext Creds",    severity:"high",    cvss:7.2,cat:"Credential Access",   rule:"ET CREDS HTTP Form Login Cleartext",   sig:"2013028",cve:null},
  {name:"DNS Tunneling",           severity:"medium",  cvss:5.5,cat:"Command & Control",   rule:"ET DNS Long Domain Query (Tunneling)", sig:"2027868",cve:null},
  {name:"ARP Spoofing / MitM",     severity:"medium",  cvss:5.9,cat:"Man-in-the-Middle",   rule:"ET ARP Spoofing Detected",             sig:"2008582",cve:null},
  {name:"RADIUS Replay Attack",    severity:"medium",  cvss:5.3,cat:"Auth Bypass",         rule:"ET RADIUS Replay Attack Pattern",      sig:"2019244",cve:null},
  {name:"SMTP Auth Harvesting",    severity:"medium",  cvss:5.7,cat:"Credential Access",   rule:"ET CREDS SMTP AUTH LOGIN Cleartext",   sig:"2011716",cve:null},
  {name:"Kerberos AS-REP Roast",   severity:"critical",cvss:8.8,cat:"Credential Access",   rule:"ET EXPLOIT AS-REP Roasting Detected",  sig:"2027862",cve:"CVE-2021-42278"},
];
const GEO = [
  {country:"China",      code:"CN",x:745,y:195,count:234,color:"#ff2d55"},
  {country:"Russia",     code:"RU",x:630,y:138,count:189,color:"#ffd60a"},
  {country:"United States",code:"US",x:200,y:200,count:156,color:"#00e5ff"},
  {country:"Germany",    code:"DE",x:495,y:160,count:89, color:"#c084fc"},
  {country:"Brazil",     code:"BR",x:285,y:310,count:67, color:"#00ff9f"},
  {country:"India",      code:"IN",x:670,y:235,count:54, color:"#fb923c"},
  {country:"Ukraine",    code:"UA",x:555,y:152,count:43, color:"#ffd60a"},
  {country:"Netherlands",code:"NL",x:483,y:152,count:38, color:"#60a5fa"},
];
const CONNS = [
  {proto:"TCP",local:"192.168.1.10:52341",remote:"10.0.0.1:80",    state:"ESTABLISHED",pid:1234,proc:"chrome",   bytes:"1.2 MB",dur:"5m 12s"},
  {proto:"TCP",local:"192.168.1.10:52342",remote:"8.8.8.8:443",    state:"ESTABLISHED",pid:1235,proc:"firefox",  bytes:"345 KB",dur:"2m 08s"},
  {proto:"TCP",local:"192.168.1.22:22",   remote:"10.0.0.5:54123", state:"ESTABLISHED",pid:5678,proc:"sshd",     bytes:"89 KB", dur:"12m 44s"},
  {proto:"TCP",local:"192.168.1.10:52350",remote:"10.0.0.50:389",  state:"ESTABLISHED",pid:2345,proc:"ldap",     bytes:"12 KB", dur:"0m 45s"},
  {proto:"TCP",local:"10.0.0.99:54321",   remote:"192.168.1.22:22",state:"SYN_SENT",   pid:9999,proc:"scanner",  bytes:"4.2 KB",dur:"0m 01s"},
  {proto:"UDP",local:"192.168.1.10:60234",remote:"8.8.8.8:53",     state:"—",          pid:1234,proc:"systemd",  bytes:"2.1 KB",dur:"—"},
  {proto:"TCP",local:"192.168.1.10:52360",remote:"10.0.0.10:88",   state:"TIME_WAIT",  pid:3456,proc:"kinit",    bytes:"8.9 KB",dur:"—"},
  {proto:"TCP",local:"192.168.2.8:45678", remote:"185.199.108.153:443",state:"ESTABLISHED",pid:7890,proc:"git",  bytes:"567 KB",dur:"1m 33s"},
  {proto:"TCP",local:"10.1.0.15:49201",   remote:"172.16.0.3:1812",state:"ESTABLISHED",pid:4321,proc:"radius",   bytes:"3.4 KB",dur:"0m 22s"},
  {proto:"TCP",local:"192.168.1.45:50001",remote:"192.168.1.22:22",state:"SYN_SENT",   pid:8888,proc:"nmap",     bytes:"640 B", dur:"0m 00s"},
];
const DNS_LOG = [
  {time:"14:32:01.123",client:"192.168.1.10",query:"ldap.corp.local",    type:"A",   resp:"10.0.0.50",         ttl:300,status:"NOERROR"},
  {time:"14:32:01.456",client:"192.168.1.22",query:"dc01.corp.local",    type:"A",   resp:"10.0.0.10",         ttl:300,status:"NOERROR"},
  {time:"14:32:02.001",client:"10.0.0.5",    query:"github.com",         type:"AAAA",resp:"2607:f8b0::200e",   ttl:299,status:"NOERROR"},
  {time:"14:32:02.789",client:"192.168.1.45",query:"aAbBcCdDeEfF4a5b6c7d8e9f.corp.evil.com",type:"TXT",resp:"NXDOMAIN",ttl:0,status:"SUSPICIOUS"},
  {time:"14:32:03.100",client:"172.16.0.3",  query:"kerberos.corp.local",type:"SRV", resp:"dc01.corp.local:88",ttl:600,status:"NOERROR"},
  {time:"14:32:03.450",client:"192.168.2.8", query:"github.com",         type:"A",   resp:"140.82.114.3",      ttl:60, status:"NOERROR"},
  {time:"14:32:04.010",client:"10.0.0.99",   query:"corp.local",         type:"ANY", resp:"[zone transfer?]",  ttl:0,  status:"SUSPICIOUS"},
  {time:"14:32:04.220",client:"192.168.1.10",query:"smtp.corp.local",    type:"MX",  resp:"mail.corp.local",   ttl:900,status:"NOERROR"},
];
const HTTP_LOG = [
  {time:"14:32:01.200",method:"POST",url:"http://corp.local/auth/login",           status:200,type:"application/json",size:"2.1 KB",dur:"45ms",client:"192.168.1.10",note:"⚠ Plaintext creds"},
  {time:"14:32:01.800",method:"GET", url:"https://10.0.0.1/admin/users",           status:200,type:"text/html",       size:"15.3 KB",dur:"120ms",client:"192.168.1.22",note:""},
  {time:"14:32:02.100",method:"GET", url:"http://corp.local/ldap/query?base=dc%3D",status:200,type:"application/json",size:"8.7 KB",dur:"33ms",client:"10.0.0.99",note:"⚠ LDAP injection attempt"},
  {time:"14:32:02.500",method:"POST",url:"http://192.168.1.1/cgi-bin/auth",        status:401,type:"text/plain",      size:"128 B", dur:"12ms",client:"10.0.0.5",note:"❌ Auth failed"},
  {time:"14:32:03.000",method:"GET", url:"https://api.corp.local/v1/tokens",       status:200,type:"application/json",size:"512 B", dur:"88ms",client:"192.168.1.10",note:""},
  {time:"14:32:03.800",method:"DELETE",url:"https://10.0.0.1/api/users/44",        status:403,type:"text/plain",      size:"64 B",  dur:"22ms",client:"10.0.0.99",note:"❌ Unauthorized"},
  {time:"14:32:04.100",method:"PUT", url:"http://corp.local/api/config",            status:200,type:"application/json",size:"1.2 KB",dur:"67ms",client:"192.168.1.22",note:"⚠ Config change"},
];
const PROTO_TREE = {
  name:"Frame",pct:100,
  children:[{name:"Ethernet II",pct:100,
    children:[
      {name:"Internet Protocol v4",pct:94.8,
        children:[
          {name:"Transmission Control Protocol",pct:72.3,
            children:[
              {name:"Transport Layer Security (TLS 1.3)",pct:38.2,
                children:[{name:"HTTP/2 (HTTPS)",pct:38.2,children:[]}]},
              {name:"HyperText Transfer Protocol (HTTP)",pct:18.5,children:[]},
              {name:"Secure Shell Protocol (SSH)",pct:9.8,children:[]},
              {name:"Lightweight Dir. Access Protocol",pct:4.1,children:[]},
              {name:"SMTP / Email Protocol",pct:1.7,children:[]},
            ]},
          {name:"User Datagram Protocol",pct:18.2,
            children:[
              {name:"Domain Name System (DNS)",pct:12.4,children:[]},
              {name:"RADIUS Authentication",pct:4.1,children:[]},
              {name:"Kerberos (UDP)",pct:1.7,children:[]},
            ]},
          {name:"Internet Control Msg Protocol",pct:4.3,children:[]},
        ]},
      {name:"Address Resolution Protocol",pct:5.2,children:[]},
    ]}]
};

// ── Packet generator ──────────────────────────────────────────────────────────
let pkId = 1;
function genPkt() {
  const proto = pick(PROTOS);
  const src   = pick(SRCS);
  const dst   = pick(DSTS);
  const pm = {HTTP:80,HTTPS:443,DNS:53,TCP:R(1024,9999),UDP:R(1024,9999),LDAP:389,Kerberos:88,RADIUS:1812,ICMP:0,SSH:22,ARP:0,TLS:443,SMTP:25};
  return {
    id:pkId++, ts:new Date().toISOString(),
    tstr:new Date().toLocaleTimeString("en-GB",{hour12:false})+"."+String(R(0,999)).padStart(3,"0"),
    src, dst, proto,
    sp:R(1024,65535), dp:pm[proto]||0,
    size:R(40,1500),
    info:pick(INFOS[proto]||["Data"]),
    ttl:R(48,128),
    flags:proto==="TCP"?pick(["SYN","ACK","SYN-ACK","PSH-ACK","FIN-ACK","RST"]):"—",
    hex:genHex(R(40,100)),
  };
}
function genHex(n) {
  const b = Array.from({length:n},()=>R(0,255).toString(16).padStart(2,"0"));
  const rows=[];
  for(let i=0;i<b.length;i+=16){
    const ch=b.slice(i,i+16);
    const hex=ch.map((x,j)=>(j===8?" ":"")+x).join(" ");
    const asc=ch.map(x=>{const c=parseInt(x,16);return c>=32&&c<127?String.fromCharCode(c):"."}).join("");
    rows.push({off:i.toString(16).padStart(4,"0"),hex,asc});
  }
  return rows;
}
function buildTree(p) {
  if(!p) return [];
  return [
    {name:`Frame ${p.id}: ${p.size} bytes on wire (${p.size*8} bits)`,color:"#94a3b8",fields:[
      {k:"Interface id",v:"0 (eth0)"},{k:"Encapsulation type",v:"Ethernet (1)"},
      {k:"Arrival Time",v:p.tstr},{k:"Frame Length",v:`${p.size} bytes (${p.size*8} bits)`},
      {k:"Capture Length",v:`${p.size} bytes`},{k:"Marked",v:"False"},{k:"Ignored",v:"False"},
    ]},
    {name:`Ethernet II  Src: aa:bb:cc:${R(10,99)}:${R(10,99)}:ff  Dst: ff:ff:ff:ff:ff:ff`,color:"#fb923c",fields:[
      {k:"Destination",v:"ff:ff:ff:ff:ff:ff (Broadcast)"},
      {k:"Source",v:`aa:bb:cc:${R(10,99)}:${R(10,99)}:ff`},
      {k:"Type",v:"IPv4 (0x0800)"},{k:"FCS",v:`0x${R(1000,9999).toString(16)}`,n:"[correct]"},
    ]},
    {name:`Internet Protocol v4  Src: ${p.src}  Dst: ${p.dst}`,color:"#60a5fa",fields:[
      {k:"Version",v:"4"},{k:"Header Length",v:"20 bytes (5)"},
      {k:"Diff Services",v:"0x00 (DSCP:CS0, ECN:Not-ECT)"},
      {k:"Total Length",v:String(p.size-14)},
      {k:"Identification",v:`0x${R(1000,9999).toString(16)} (${R(1000,9999)})`},
      {k:"Flags",v:"0x02 (Don't Fragment)"},
      {k:"TTL",v:String(p.ttl)},
      {k:"Protocol",v:p.proto==="UDP"?"UDP (17)":"TCP (6)"},
      {k:"Checksum",v:`0x${R(1000,9999).toString(16)}`,n:"[correct]"},
      {k:"Source Address",v:p.src},{k:"Destination",v:p.dst},
    ]},
    p.proto!=="UDP"
      ?{name:`TCP  Src Port: ${p.sp}  Dst Port: ${p.dp}  Flags: ${p.flags}`,color:"#c084fc",fields:[
          {k:"Source Port",v:String(p.sp)},{k:"Destination Port",v:String(p.dp)},
          {k:"Stream index",v:String(R(1,99))},
          {k:"Sequence Number",v:String(R(1000000,9999999))},
          {k:"Ack Number",v:String(R(1000000,9999999))},
          {k:"Header Length",v:"32 bytes (8)"},{k:"Flags",v:`0x018 (PSH, ACK)`},
          {k:"Window Size",v:"65535"},{k:"Checksum",v:`0x${R(1000,9999).toString(16)}`,n:"[correct]"},
          {k:"Options",v:"MSS=1460, WS=256, SACK_PERM, TS val"},
        ]}
      :{name:`UDP  Src Port: ${p.sp}  Dst Port: ${p.dp}`,color:"#94a3b8",fields:[
          {k:"Source Port",v:String(p.sp)},{k:"Destination Port",v:String(p.dp)},
          {k:"Length",v:String(p.size-28)},{k:"Checksum",v:`0x${R(1000,9999).toString(16)}`},
        ]},
    {name:`Application Layer: ${p.proto}`,color:PC[p.proto]||"#888",fields:[
      {k:"Protocol",v:p.proto},{k:"Info",v:p.info},
      {k:"Payload",v:`${p.size-54} bytes`},{k:"Decoded as",v:p.proto},
    ]},
  ];
}
function fmtTime(s) {
  if(!s) return "00:00";
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),ss=Math.floor(s%60);
  return h>0?`${h}:${String(m).padStart(2,"0")}:${String(ss).padStart(2,"0")}`:`${String(m).padStart(2,"0")}:${String(ss).padStart(2,"0")}`;
}
function fmtBytes(b) {
  if(b>1073741824) return `${(b/1073741824).toFixed(2)} GB`;
  if(b>1048576)    return `${(b/1048576).toFixed(1)} MB`;
  if(b>1024)       return `${(b/1024).toFixed(1)} KB`;
  return `${b} B`;
}
function getFlag(c) {
  return {CN:"🇨🇳",RU:"🇷🇺",US:"🇺🇸",DE:"🇩🇪",BR:"🇧🇷",IN:"🇮🇳",UA:"🇺🇦",NL:"🇳🇱"}[c]||"🏴";
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Metric({icon,label,value,sub,color}) {
  return (
    <div className="metric" style={{"--c":color}}>
      <div className="m-icon" style={{color,textShadow:`0 0 10px ${color}80`}}>{icon}</div>
      <div>
        <div className="m-label">{label}</div>
        <div className="m-val">{value}</div>
        <div className="m-sub">{sub}</div>
      </div>
    </div>
  );
}

function TreeNode({node,depth,total,open,setOpen}) {
  const id   = node.name;
  const isO  = open.has(id);
  const hasC = node.children?.length>0;
  const pkts = Math.round((node.pct/100)*total)||0;
  const bytes= pkts*R(60,200);
  return (
    <>
      <div className="tnode" style={{paddingLeft:12+depth*20}}
        onClick={()=>hasC&&setOpen(prev=>{const n=new Set(prev);isO?n.delete(id):n.add(id);return n})}>
        <span className="tn-tog">{hasC?(isO?"▼":"▶"):" "}</span>
        <span className="tn-name">{node.name}</span>
        <span className="tn-pct">{node.pct.toFixed(1)}%</span>
        <span className="tn-pk">{pkts.toLocaleString()}</span>
        <span className="tn-by">{bytes>1024?`${(bytes/1024).toFixed(1)}k`:bytes}</span>
        <span className="tn-bps">{Math.round(bytes*.08).toLocaleString()}</span>
        <span className="tn-end">{!hasC?pkts.toLocaleString():"—"}</span>
      </div>
      {isO&&node.children?.map(c=><TreeNode key={c.name} node={c} depth={depth+1} total={total} open={open} setOpen={setOpen}/>)}
    </>
  );
}

function DecodeLayer({layer}) {
  const [o,setO]=useState(true);
  return (
    <div className="dlayer">
      <div className="dl-hd" onClick={()=>setO(x=>!x)}>
        <span className="dl-tog">{o?"▼":"▶"}</span>
        <span className="dl-name" style={{color:layer.color}}>{layer.name}</span>
      </div>
      {o&&<div className="dl-flds">
        {layer.fields.map((f,i)=>(
          <div key={i} className="dfield">
            <span className="df-k">{f.k}:</span>
            <span className="df-v">{f.v}</span>
            {f.n&&<span className="df-n">{f.n}</span>}
          </div>
        ))}
      </div>}
    </div>
  );
}

function WorldMap({sources}) {
  return (
    <svg viewBox="0 0 920 480" className="map-svg" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <filter id="glow"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        <radialGradient id="mapbg" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#071525"/><stop offset="100%" stopColor="#020912"/>
        </radialGradient>
      </defs>
      <rect width="920" height="480" fill="url(#mapbg)"/>
      {/* Grid */}
      {[...Array(10)].map((_,i)=><line key={`h${i}`} x1="0" y1={i*48} x2="920" y2={i*48} stroke="#0d2540" strokeWidth="0.5"/>)}
      {[...Array(19)].map((_,i)=><line key={`v${i}`} x1={i*50} y1="0" x2={i*50} y2="480" stroke="#0d2540" strokeWidth="0.5"/>)}
      {/* Simplified continents */}
      <path d="M55 195 Q110 168 165 178 Q205 172 248 183 Q265 210 255 248 Q235 278 200 288 Q165 298 135 290 Q100 275 72 248 Q48 222 55 195Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
      <path d="M268 155 Q328 132 408 142 Q468 148 530 160 Q560 172 568 195 Q562 220 535 228 Q492 232 450 226 Q400 218 358 208 Q318 198 290 188 Q268 178 268 155Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
      <path d="M270 225 Q295 215 325 218 Q335 240 325 270 Q310 295 285 302 Q265 298 258 278 Q250 255 270 225Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
      <path d="M582 138 Q655 125 748 136 Q808 148 848 172 Q868 198 856 228 Q834 258 792 268 Q740 272 688 260 Q636 244 608 218 Q578 192 574 168 Q572 150 582 138Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
      <path d="M490 255 Q518 238 548 245 Q562 262 550 292 Q532 318 506 326 Q484 320 474 298 Q465 275 490 255Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
      <path d="M700 248 Q735 236 768 248 Q782 268 770 300 Q752 328 720 336 Q698 330 686 308 Q675 282 700 248Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
      <path d="M294 288 Q328 275 368 292 Q388 318 376 372 Q354 412 322 420 Q298 414 282 388 Q265 358 272 322 Q278 300 294 288Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
      {/* Attack lines */}
      {sources.map(s=>(
        <g key={s.country}>
          <line x1={s.x} y1={s.y} x2={460} y2={240} stroke={s.color} strokeWidth="0.9" strokeDasharray="5,4" opacity="0.45">
            <animate attributeName="stroke-dashoffset" from="0" to="-27" dur={`${R(15,25)/10}s`} repeatCount="indefinite"/>
          </line>
          <circle cx={s.x} cy={s.y} r={Math.sqrt(s.count)/2+4} fill={s.color} opacity="0.12" filter="url(#glow)"/>
          <circle cx={s.x} cy={s.y} r="4" fill={s.color} filter="url(#glow)">
            <animate attributeName="r" values="3;7;3" dur={`${R(15,25)/10}s`} repeatCount="indefinite"/>
            <animate attributeName="opacity" values="1;0.3;1" dur={`${R(15,25)/10}s`} repeatCount="indefinite"/>
          </circle>
          <text x={s.x+9} y={s.y+4} fill={s.color} fontSize="9" fontFamily="JetBrains Mono,monospace" opacity="0.7">{s.code}</text>
        </g>
      ))}
      {/* Target */}
      <circle cx={460} cy={240} r="18" fill="#00e5ff" opacity="0.06" filter="url(#glow)"/>
      <circle cx={460} cy={240} r="8"  fill="#00e5ff" opacity="0.15"/>
      <circle cx={460} cy={240} r="4"  fill="#00e5ff" filter="url(#glow)">
        <animate attributeName="r" values="4;8;4" dur="2s" repeatCount="indefinite"/>
        <animate attributeName="opacity" values="1;0.4;1" dur="2s" repeatCount="indefinite"/>
      </circle>
      <text x={468} y={260} fill="#00e5ff" fontSize="9" fontFamily="JetBrains Mono,monospace" opacity="0.8">TARGET</text>
    </svg>
  );
}

// ── MAIN APP ──────────────────────────────────────────────────────────────────
export default function App() {
  const [cap,  setCap]   = useState(false);
  const [paused,setPaused]= useState(false);
  const [pkts, setPkts]  = useState([]);
  const [alerts,setAlerts]= useState([]);
  const [traffic,setTraf] = useState(Array.from({length:20},(_,i)=>({t:i,pkts:R(5,25),bps:R(5000,300000)})));
  const [protoC,setProtoC]= useState({});
  const [sel,  setSel]   = useState(null);
  const [tab,  setTab]   = useState("live");
  const [filter,setFilt] = useState("");
  const [stats, setStats] = useState({total:0,bytes:0,threats:0,pps:0,elapsed:0});
  const [hexTab,setHexTab]= useState("decode");
  const [cSearch,setCSearch]=useState("");
  const [treeOpen,setTreeOpen]=useState(new Set(["Frame","Ethernet II","Internet Protocol v4","Transmission Control Protocol"]));
  const ivRef = useRef(null);
  const atRef = useRef(null);
  const t0Ref = useRef(null);

  // Capture loop
  useEffect(()=>{
    if(cap&&!paused){
      t0Ref.current = t0Ref.current||Date.now();
      ivRef.current = setInterval(()=>{
        const batch=Array.from({length:R(3,7)},genPkt);
        setPkts(p=>[...batch,...p].slice(0,300));
        setProtoC(p=>{const n={...p};batch.forEach(pk=>{n[pk.proto]=(n[pk.proto]||0)+1});return n});
        setStats(p=>({
          total:p.total+batch.length,
          bytes:p.bytes+batch.reduce((s,pk)=>s+pk.size,0),
          threats:p.threats, pps:batch.length*(1000/750),
          elapsed:(Date.now()-t0Ref.current)/1000,
        }));
        setTraf(p=>[...p,{t:p.length,pkts:batch.length,bps:batch.reduce((s,pk)=>s+pk.size*8,0)}].slice(-40));
      },750);
      atRef.current = setInterval(()=>{
        if(Math.random()<0.28){
          const t={...pick(THREATS_DATA),id:Date.now(),time:new Date().toISOString(),src:pick(SRCS),dst:pick(DSTS),count:R(1,60)};
          setAlerts(p=>[t,...p].slice(0,40));
          setStats(p=>({...p,threats:p.threats+1}));
        }
      },2800);
    } else {
      clearInterval(ivRef.current);
      clearInterval(atRef.current);
    }
    return()=>{clearInterval(ivRef.current);clearInterval(atRef.current)};
  },[cap,paused]);

  const filtered = useMemo(()=>{
    if(!filter.trim()) return pkts;
    const f=filter.toLowerCase();
    return pkts.filter(p=>p.proto.toLowerCase().includes(f)||p.src.includes(f)||p.dst.includes(f)||p.info.toLowerCase().includes(f)||String(p.dp).includes(f));
  },[pkts,filter]);

  const pieData = useMemo(()=>Object.entries(protoC).map(([name,value])=>({name,value})),[protoC]);
  const pktTree = useMemo(()=>buildTree(sel),[sel]);
  const totalPkts = Object.values(protoC).reduce((a,b)=>a+b,0)||1;

  const startCap=()=>{setCap(true);t0Ref.current=Date.now()};
  const stopCap =()=>{setCap(false);t0Ref.current=null};
  const clear   =()=>{setPkts([]);setAlerts([]);setProtoC({});setStats({total:0,bytes:0,threats:0,pps:0,elapsed:0});pkId=1};

  const TABS=[
    {id:"live",       ico:"◈",lbl:"Live Capture",   badge:filtered.length},
    {id:"protocols",  ico:"◫",lbl:"Protocol Hierarchy"},
    {id:"inspector",  ico:"⊕",lbl:"Packet Inspector", badge:sel?`#${sel.id}`:null,clr:sel?"grn":null},
    {id:"threats",    ico:"⚠",lbl:"Threat Intel",   badge:alerts.length,clr:alerts.filter(a=>a.severity==="critical").length?"red":null},
    {id:"connections",ico:"◉",lbl:"Connections",    badge:CONNS.length},
    {id:"statistics", ico:"◷",lbl:"Statistics"},
    {id:"dns",        ico:"◎",lbl:"DNS",             badge:DNS_LOG.length},
    {id:"http",       ico:"⬡",lbl:"HTTP",            badge:HTTP_LOG.length},
    {id:"geomap",     ico:"◬",lbl:"Geo Map",         badge:GEO.length},
  ];

  return (
    <div className="app">
      {/* ── TOP BAR ── */}
      <div className="topbar">
        <div className="logo">
          <div className="logo-mark">◈</div>
          <div>
            <div className="logo-text">NETWATCH</div>
            <div className="logo-ver">NETWORK ANALYZER v2.0</div>
          </div>
        </div>
        <div className="topbar-center">
          <select className="iface-sel">
            <option>eth0  ▸  192.168.1.10/24</option>
            <option>wlan0 ▸  10.0.0.5/24</option>
            <option>lo    ▸  127.0.0.1/8</option>
            <option>any   ▸  (all interfaces)</option>
          </select>
          <div className="fbar">
            <span className="fbar-icon">⌕</span>
            <input placeholder="Apply display filter ... (e.g. tcp && ip.src==192.168.1.10 || http.method==POST)" value={filter} onChange={e=>setFilt(e.target.value)}/>
            {filter&&<button className="fbar-clear" onClick={()=>setFilt("")}>✕</button>}
          </div>
        </div>
        <div className="topbar-right">
          {cap&&!paused&&<span className="badge-live"><span className="badge-live-dot"/>LIVE</span>}
          {cap&&paused&&<span className="badge-pause">⏸ PAUSED</span>}
          {!cap&&<button className="btn btn-start" onClick={startCap}>▶ Start Capture</button>}
          {cap&&<button className="btn btn-pause" onClick={()=>setPaused(p=>!p)}>{paused?"▶ Resume":"⏸ Pause"}</button>}
          {cap&&<button className="btn btn-stop" onClick={stopCap}>⏹ Stop</button>}
          <button className="btn btn-clear" onClick={clear}>⌫ Clear</button>
          <button className="btn btn-export">⬇ Export .pcap</button>
        </div>
      </div>

      {/* ── METRICS ── */}
      <div className="metrics">
        <Metric icon="◫" label="Packets Captured" value={stats.total.toLocaleString()} sub={`${Math.round(stats.pps)} pkt/s`} color={C.cyan}/>
        <Metric icon="◈" label="Data Volume" value={fmtBytes(stats.bytes)} sub={`${fmtBytes(Math.round(stats.pps*800))}/s`} color={C.green}/>
        <Metric icon="⚠" label="IDS Alerts" value={stats.threats} sub={`${alerts.filter(a=>a.severity==="critical").length} critical`} color={C.red}/>
        <Metric icon="◉" label="Protocols" value={Object.keys(protoC).length||0} sub={`of ${PROTOS.length} monitored`} color={C.purple}/>
        <Metric icon="◷" label="Capture Time" value={fmtTime(stats.elapsed)} sub={cap?(paused?"paused":"capturing"):"idle"} color={C.yellow}/>
        <Metric icon="◎" label="Dropped Pkts" value="0" sub="0.000% loss" color={C.orange}/>
      </div>

      {/* ── TABBAR ── */}
      <div className="tabbar">
        {TABS.map(t=>(
          <button key={t.id} className={`tab${tab===t.id?" on":""}`} onClick={()=>setTab(t.id)}>
            <span className="tab-ico">{t.ico}</span>
            {t.lbl}
            {t.badge!=null&&t.badge!==false&&
              <span className={`tbadge${t.clr?" "+t.clr:""}`}>{t.badge}</span>}
          </button>
        ))}
      </div>

      {/* ── CONTENT ── */}
      <div className="content">

        {/* ──────────────────────────────── LIVE CAPTURE ── */}
        {tab==="live"&&(
          <div className="live-wrap">
            <div className="pkt-wrap">
              <table className="pkt-t">
                <thead><tr>
                  <th>No.</th><th>Timestamp</th><th>Source</th><th>Src Port</th>
                  <th>Destination</th><th>Dst Port</th><th>Protocol</th><th>Length</th><th>TTL</th><th>Flags</th><th>Info</th>
                </tr></thead>
                <tbody>
                  {filtered.slice(0,80).map(p=>(
                    <tr key={p.id} className={`pk${sel?.id===p.id?" sel":""}`}
                      style={{
                        "--pc":PC[p.proto]||"#888",
                        background:sel?.id===p.id?"#001c2e":undefined
                      }}
                      onClick={()=>{setSel(p);setTab("inspector")}}>
                      <td className="mono muted sm">{p.id}</td>
                      <td className="mono dim sm">{p.tstr}</td>
                      <td className="mono sm">{p.src}</td>
                      <td className="mono muted sm">{p.sp}</td>
                      <td className="mono sm">{p.dst}</td>
                      <td className="mono muted sm">{p.dp||"—"}</td>
                      <td><span className="ptag" style={{"--pc":PC[p.proto]||"#888"}}>{p.proto}</span></td>
                      <td className="mono muted sm">{p.size}</td>
                      <td className="mono muted sm">{p.ttl}</td>
                      <td className="mono sm" style={{color:p.flags==="RST"||p.flags==="SYN"?C.red:C.dim,fontSize:10}}>{p.flags}</td>
                      <td className="icell mono sm">{p.info}</td>
                    </tr>
                  ))}
                  {filtered.length===0&&<tr><td colSpan={11} className="empty-pk">{cap?"— No packets match current filter —":"◈  Press Start Capture to begin monitoring"}</td></tr>}
                </tbody>
              </table>
            </div>
            {/* Live sidebar */}
            <div className="lsb">
              <div className="sb-sec">
                <div className="sb-ttl">Protocol Breakdown</div>
                {Object.entries(protoC).sort((a,b)=>b[1]-a[1]).slice(0,9).map(([p,c])=>{
                  const pct=((c/totalPkts)*100).toFixed(1);
                  return(
                    <div key={p} className="pbar-row">
                      <span className="pbar-lbl" style={{color:PC[p]||"#888"}}>{p}</span>
                      <div className="pbar-bg"><div className="pbar-fill" style={{width:`${pct}%`,background:PC[p]||"#888"}}/></div>
                      <span className="pbar-pct">{pct}%</span>
                    </div>
                  );
                })}
                {Object.keys(protoC).length===0&&<div className="muted sm">Waiting for traffic…</div>}
              </div>
              <div className="sb-sec">
                <div className="sb-ttl">Traffic Rate</div>
                <ResponsiveContainer width="100%" height={90}>
                  <AreaChart data={traffic.slice(-20)}>
                    <defs>
                      <linearGradient id="tg" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={C.cyan} stopOpacity={0.35}/>
                        <stop offset="100%" stopColor={C.cyan} stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <Area type="monotone" dataKey="pkts" stroke={C.cyan} fill="url(#tg)" strokeWidth={1.5} dot={false}/>
                    <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:10,color:C.text}}/>
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <div className="sb-sec">
                <div className="sb-ttl">Latest Alerts</div>
                {alerts.slice(0,5).map(a=>(
                  <div key={a.id} className="malert" style={{"--c":SC[a.severity].text}}>
                    <span className="malert-s">{a.severity[0].toUpperCase()}</span>
                    <span className="malert-n">{a.name}</span>
                  </div>
                ))}
                {alerts.length===0&&<div className="muted sm">No alerts yet</div>}
              </div>
              <div className="sb-sec">
                <div className="sb-ttl">Top Sources</div>
                {Object.entries(pkts.slice(0,100).reduce((acc,p)=>{acc[p.src]=(acc[p.src]||0)+1;return acc},{}))
                  .sort((a,b)=>b[1]-a[1]).slice(0,5).map(([ip,c])=>(
                  <div key={ip} style={{display:"flex",gap:6,padding:"3px 0",borderBottom:"1px solid #0a1620"}}>
                    <span className="mono sm" style={{flex:1,color:C.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{ip}</span>
                    <span className="mono sm muted">{c}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ──────────────────────────────── PROTOCOL HIERARCHY ── */}
        {tab==="protocols"&&(
          <div className="ph-wrap">
            <div className="ph-head">
              <div style={{flex:3}}>Protocol</div>
              <div style={{flex:1,textAlign:"right"}}>% Packets</div>
              <div style={{flex:1,textAlign:"right"}}>Packets</div>
              <div style={{flex:1,textAlign:"right"}}>Bytes</div>
              <div style={{flex:1,textAlign:"right"}}>Bits/s</div>
              <div style={{flex:1,textAlign:"right"}}>End Pkts</div>
            </div>
            <div className="ph-body">
              <TreeNode node={PROTO_TREE} depth={0} total={stats.total} open={treeOpen} setOpen={setTreeOpen}/>
            </div>
            <div className="ph-foot">
              <span>{stats.total.toLocaleString()} packets total</span>
              <span>{fmtBytes(stats.bytes)} captured</span>
              <span>{Object.keys(protoC).length} protocols active</span>
              <span>Interface: eth0</span>
            </div>
          </div>
        )}

        {/* ──────────────────────────────── PACKET INSPECTOR ── */}
        {tab==="inspector"&&(
          <div className="insp-wrap">
            <div className="insp-main">
              {!sel?(
                <div className="es">
                  <div className="es-ico">⊕</div>
                  <div style={{fontSize:13}}>Select a packet to inspect</div>
                  <div className="muted sm">Full protocol decode + hex dump view</div>
                </div>
              ):(
                <>
                  <div className="ins-tabs">
                    <button className={`ins-tab${hexTab==="decode"?" on":""}`} onClick={()=>setHexTab("decode")}>⊕ Protocol Decode</button>
                    <button className={`ins-tab${hexTab==="hex"?" on":""}`} onClick={()=>setHexTab("hex")}>◫ Hex / ASCII Dump</button>
                  </div>
                  {hexTab==="decode"&&(
                    <div className="decode">
                      {pktTree?.map((layer,i)=><DecodeLayer key={i} layer={layer}/>)}
                    </div>
                  )}
                  {hexTab==="hex"&&(
                    <div className="hexd">
                      <div className="hex-hd">
                        <span>Offset</span>
                        <span>00 01 02 03 04 05 06 07 &nbsp; 08 09 0a 0b 0c 0d 0e 0f</span>
                        <span>ASCII</span>
                      </div>
                      {sel.hex.map((r,i)=>(
                        <div key={i} className="hex-row">
                          <span className="hex-off">{r.off}</span>
                          <span className="hex-by">{r.hex}</span>
                          <span className="hex-asc">{r.asc}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
            <div className="insp-aside">
              <div className="sb-ttl">Packet Summary</div>
              {sel?[
                ["Frame #",sel.id],["Timestamp",sel.tstr],["Source IP",sel.src],
                ["Src Port",sel.sp],["Destination",sel.dst],["Dst Port",sel.dp||"—"],
                ["Protocol",sel.proto],["Frame Len",`${sel.size} bytes`],
                ["TTL",sel.ttl],["TCP Flags",sel.flags],
              ].map(([k,v])=>(
                <div key={k} className="sum-row">
                  <span className="sum-k">{k}</span>
                  <span className="sum-v">{v}</span>
                </div>
              )):<div className="muted sm">No packet selected</div>}
              <div className="nav-pair">
                <button className="nav-btn" onClick={()=>{const i=pkts.findIndex(p=>p.id===sel?.id);if(i<pkts.length-1)setSel(pkts[i+1])}}>← Prev</button>
                <button className="nav-btn" onClick={()=>{const i=pkts.findIndex(p=>p.id===sel?.id);if(i>0)setSel(pkts[i-1])}}>Next →</button>
              </div>
              <div className="sb-ttl" style={{marginTop:14}}>Actions</div>
              {["Follow TCP Stream","Mark Packet","Export Selected","Apply as Filter","Colorize Rule"].map(a=>(
                <button key={a} className="nav-btn" style={{width:"100%",marginBottom:4,textAlign:"left",padding:"5px 8px"}}>{a}</button>
              ))}
            </div>
          </div>
        )}

        {/* ──────────────────────────────── THREAT INTEL ── */}
        {tab==="threats"&&(
          <div className="thr-wrap">
            <div className="thr-main">
              <div className="sev-bar">
                {["critical","high","medium","low"].map(s=>{
                  const sc=SC[s]; const ct=alerts.filter(a=>a.severity===s).length;
                  return(
                    <div key={s} className="sev-c" style={{"--sc":sc.text,"--sbg":sc.bg,"--sb":sc.border}}>
                      <div className="sev-lbl">{s.toUpperCase()}</div>
                      <div className="sev-num">{ct}</div>
                    </div>
                  );
                })}
              </div>
              <div className="alerts">
                {alerts.length===0?(
                  <div className="es"><div className="es-ico" style={{color:C.green}}>✓</div>
                    <div>No threats detected</div><div className="muted sm">Start capture to monitor</div>
                  </div>
                ):alerts.map(a=>{
                  const sc=SC[a.severity];
                  return(
                    <div key={a.id} className="acard" style={{"--ac":sc.text,"--abg":sc.bg,"--ab":sc.border}}>
                      <div className="ac-l">
                        <div className="ac-sev">{a.severity.toUpperCase()}</div>
                        <div className="ac-cvss">{a.cvss.toFixed(1)}</div>
                        <div style={{fontSize:9,color:sc.text,opacity:.7}}>CVSS</div>
                      </div>
                      <div className="ac-bd">
                        <div className="ac-nm">{a.name}</div>
                        <div className="ac-mt">
                          <span>SIG: {a.sig}</span><span>{a.cat}</span>
                          {a.cve&&<span className="cve">{a.cve}</span>}
                        </div>
                        <div className="ac-rl">{a.rule}</div>
                        <div className="ac-fl">
                          <span className="mono sm">{a.src}</span>
                          <span className="flarr">→</span>
                          <span className="mono sm">{a.dst}</span>
                          <span className="ac-pt">{a.proto}</span>
                        </div>
                      </div>
                      <div className="ac-r">
                        <div className="ac-tm">{new Date(a.time).toLocaleTimeString()}</div>
                        <div className="ac-ct">×{a.count}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
            <div className="thr-sb">
              <div className="sb-ttl">MITRE ATT&CK</div>
              {[
                {t:"Reconnaissance",      n:alerts.filter(a=>a.cat?.includes("Recon")).length,c:"#ffd60a"},
                {t:"Credential Access",   n:alerts.filter(a=>a.cat?.includes("Cred")).length, c:"#ff2d55"},
                {t:"Brute Force",         n:alerts.filter(a=>a.cat?.includes("Brute")).length,c:"#fb923c"},
                {t:"Command & Control",   n:alerts.filter(a=>a.cat?.includes("Command")).length,c:"#c084fc"},
                {t:"Lateral Movement",    n:0,c:"#60a5fa"},
                {t:"Exfiltration",        n:0,c:"#00e5ff"},
                {t:"Man-in-the-Middle",   n:alerts.filter(a=>a.cat?.includes("MitM")).length,c:"#22d3ee"},
                {t:"Auth Bypass",         n:alerts.filter(a=>a.cat?.includes("Auth")).length,c:"#4ade80"},
              ].map(m=>(
                <div key={m.t} className="mitre-r">
                  <div className="mit-bg"><div className="mit-fill" style={{width:`${Math.min(100,(m.n/Math.max(1,alerts.length))*300)}%`,background:m.c}}/></div>
                  <span className="mit-lbl">{m.t}</span>
                  <span className="mit-n" style={{color:m.c}}>{m.n}</span>
                </div>
              ))}
              <div className="sb-ttl" style={{marginTop:16}}>Alert Timeline</div>
              <ResponsiveContainer width="100%" height={110}>
                <BarChart data={traffic.slice(-15).map((t,i)=>({...t,al:Math.random()<.3?R(1,3):0}))}>
                  <Bar dataKey="al" fill={C.red} radius={[2,2,0,0]}/>
                  <XAxis hide/><YAxis hide/>
                  <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:10}}/>
                </BarChart>
              </ResponsiveContainer>
              <div className="sb-ttl" style={{marginTop:16}}>Top Attack Sources</div>
              {alerts.slice(0,5).map(a=>(
                <div key={a.id} style={{display:"flex",gap:6,padding:"3px 0",borderBottom:"1px solid #0a1620",fontSize:10.5}}>
                  <span className="mono" style={{flex:1,color:C.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{a.src}</span>
                  <span style={{color:SC[a.severity].text,fontWeight:600}}>{a.severity[0].toUpperCase()}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ──────────────────────────────── CONNECTIONS ── */}
        {tab==="connections"&&(
          <div className="conn-wrap">
            <div className="conn-tb">
              <input className="fbar" style={{width:280,background:"#071525",border:"1px solid #0d2540",color:C.text,padding:"6px 10px",borderRadius:4,fontFamily:"JetBrains Mono,monospace",fontSize:11,outline:"none"}}
                placeholder="Filter connections…" value={cSearch} onChange={e=>setCSearch(e.target.value)}/>
              <div className="conn-st">
                <span><span style={{color:C.green}}>●</span> {CONNS.filter(c=>c.state==="ESTABLISHED").length} ESTABLISHED</span>
                <span><span style={{color:C.yellow}}>●</span> {CONNS.filter(c=>c.state==="TIME_WAIT").length} TIME_WAIT</span>
                <span><span style={{color:C.red}}>●</span> {CONNS.filter(c=>c.state==="SYN_SENT").length} SYN_SENT</span>
                <span><span style={{color:C.dim}}>●</span> {CONNS.filter(c=>c.proto==="UDP").length} UDP</span>
              </div>
            </div>
            <table className="ctable">
              <thead><tr><th>Proto</th><th>Local Address</th><th>Foreign Address</th><th>State</th><th>PID</th><th>Process</th><th>Bytes</th><th>Duration</th></tr></thead>
              <tbody>
                {CONNS.filter(c=>!cSearch||c.local.includes(cSearch)||c.remote.includes(cSearch)||c.proc.includes(cSearch)).map((c,i)=>{
                  const sc={ESTABLISHED:C.green,TIME_WAIT:C.yellow,SYN_SENT:C.red}[c.state]||C.dim;
                  return(
                    <tr key={i} className="crow">
                      <td><span className="ptag" style={{"--pc":c.proto==="TCP"?C.cyan:C.purple}}>{c.proto}</span></td>
                      <td className="mono sm">{c.local}</td>
                      <td className="mono sm">{c.remote}</td>
                      <td><span style={{color:sc,fontWeight:600,fontSize:10.5,fontFamily:"JetBrains Mono,monospace"}}>{c.state}</span></td>
                      <td className="mono muted sm">{c.pid}</td>
                      <td className="mono sm" style={{color:C.green}}>{c.proc}</td>
                      <td className="mono dim sm">{c.bytes}</td>
                      <td className="mono muted sm">{c.dur}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* ──────────────────────────────── STATISTICS ── */}
        {tab==="statistics"&&(
          <div className="stat-grid">
            <div className="spanel">
              <div className="sp-ttl">Traffic Volume Over Time</div>
              <ResponsiveContainer width="100%" height={170}>
                <AreaChart data={traffic}>
                  <defs>
                    <linearGradient id="tg2" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={C.cyan} stopOpacity={0.4}/>
                      <stop offset="100%" stopColor={C.cyan} stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
                  <XAxis dataKey="t" hide/>
                  <YAxis tick={{fontSize:9,fill:C.dim}}/>
                  <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:10,color:C.text}}/>
                  <Area type="monotone" dataKey="pkts" name="Packets/s" stroke={C.cyan} fill="url(#tg2)" strokeWidth={2} dot={false}/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="spanel">
              <div className="sp-ttl">Protocol Distribution</div>
              <ResponsiveContainer width="100%" height={170}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={48} outerRadius={72} dataKey="value" nameKey="name" fontSize={10}>
                    {pieData.map((e,i)=><Cell key={e.name} fill={PC[e.name]||"#888"}/>)}
                  </Pie>
                  <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:10}}/>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="spanel" style={{gridColumn:"1/-1"}}>
              <div className="sp-ttl">Top Talkers — Source IP Packet Count</div>
              <ResponsiveContainer width="100%" height={130}>
                <BarChart data={Object.entries(pkts.slice(0,200).reduce((acc,p)=>{acc[p.src]=(acc[p.src]||0)+1;return acc},{})).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([ip,count])=>({ip,count}))}>
                  <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
                  <XAxis dataKey="ip" tick={{fontSize:9,fill:C.dim}}/>
                  <YAxis tick={{fontSize:9,fill:C.dim}}/>
                  <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:10}}/>
                  <Bar dataKey="count" name="Packets" fill={C.cyan} radius={[3,3,0,0]}/>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="spanel">
              <div className="sp-ttl">Packets per Protocol</div>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={Object.entries(protoC).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([p,c])=>({p,c}))} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
                  <XAxis type="number" tick={{fontSize:9,fill:C.dim}}/>
                  <YAxis dataKey="p" type="category" tick={{fontSize:9,fill:C.dim}} width={68}/>
                  <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:10}}/>
                  <Bar dataKey="c" name="Packets" radius={[0,3,3,0]}>
                    {Object.entries(protoC).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([p])=><Cell key={p} fill={PC[p]||"#888"}/>)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="spanel">
              <div className="sp-ttl">Top Destination IPs</div>
              {Object.entries(pkts.slice(0,200).reduce((acc,p)=>{acc[p.dst]=(acc[p.dst]||0)+1;return acc},{})).sort((a,b)=>b[1]-a[1]).slice(0,7).map(([ip,c])=>(
                <div key={ip} className="tdest-r">
                  <span className="mono sm" style={{minWidth:130,color:C.text}}>{ip}</span>
                  <div className="tdest-b"><div className="tdest-f" style={{width:`${(c/Math.max(1,pkts.length))*100*8}%`}}/></div>
                  <span className="mono muted sm">{c}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ──────────────────────────────── DNS ── */}
        {tab==="dns"&&(
          <div className="dns-wrap">
            <div className="dns-sum">
              {[
                {l:"Total Queries",v:DNS_LOG.length,c:C.cyan},
                {l:"Resolved (NOERROR)",v:DNS_LOG.filter(d=>d.status==="NOERROR").length,c:C.green},
                {l:"Suspicious",v:DNS_LOG.filter(d=>d.status==="SUSPICIOUS").length,c:C.red},
                {l:"Unique Domains",v:new Set(DNS_LOG.map(d=>d.query)).size,c:C.purple},
              ].map(s=>(
                <div key={s.l} className="ds">
                  <span className="ds-v" style={{color:s.c}}>{s.v}</span>
                  <div className="ds-l">{s.l}</div>
                </div>
              ))}
            </div>
            <table className="dtable">
              <thead><tr><th>Time</th><th>Client</th><th>Query Name</th><th>Type</th><th>Response</th><th>TTL</th><th>Status</th></tr></thead>
              <tbody>
                {DNS_LOG.map((d,i)=>(
                  <tr key={i} className="drow">
                    <td className="mono muted sm">{d.time}</td>
                    <td className="mono sm">{d.client}</td>
                    <td className="mono sm" style={{color:d.status==="SUSPICIOUS"?C.red:C.text,maxWidth:320,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.query}</td>
                    <td><span className="ttag">{d.type}</span></td>
                    <td className="mono sm" style={{color:C.green,maxWidth:200,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.resp}</td>
                    <td className="mono muted sm">{d.ttl}s</td>
                    <td><span style={{color:d.status==="NOERROR"?C.green:d.status==="SUSPICIOUS"?C.red:C.yellow,fontWeight:700,fontSize:10.5}}>{d.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ──────────────────────────────── HTTP ── */}
        {tab==="http"&&(
          <div className="http-wrap">
            <div className="http-sum">
              {[
                {l:"GET",v:HTTP_LOG.filter(h=>h.method==="GET").length,c:C.cyan},
                {l:"POST",v:HTTP_LOG.filter(h=>h.method==="POST").length,c:C.green},
                {l:"200 OK",v:HTTP_LOG.filter(h=>h.status===200).length,c:C.green},
                {l:"4xx Errors",v:HTTP_LOG.filter(h=>h.status>=400).length,c:C.red},
                {l:"Suspicious",v:HTTP_LOG.filter(h=>h.note.includes("⚠")||h.note.includes("❌")).length,c:C.yellow},
              ].map(s=>(
                <div key={s.l} className="hs" style={{"--hc":s.c}}>
                  <span className="hs-v">{s.v}</span>
                  <div className="hs-l">{s.l}</div>
                </div>
              ))}
            </div>
            <table className="httable">
              <thead><tr><th>Time</th><th>Method</th><th>URL</th><th>Status</th><th>Content-Type</th><th>Size</th><th>Duration</th><th>Client</th><th>Note</th></tr></thead>
              <tbody>
                {HTTP_LOG.map((h,i)=>(
                  <tr key={i} className="hrow">
                    <td className="mono muted sm">{h.time}</td>
                    <td><span className={`mtag m-${h.method.toLowerCase()}`}>{h.method}</span></td>
                    <td className="mono sm" style={{color:h.url.startsWith("http:")?"#fb923c":C.text,maxWidth:260,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{h.url}</td>
                    <td className="mono" style={{color:h.status===200?C.green:h.status>=400?C.red:C.yellow,fontWeight:700,fontSize:11.5}}>{h.status}</td>
                    <td className="mono muted sm">{h.type}</td>
                    <td className="mono muted sm">{h.size}</td>
                    <td className="mono muted sm">{h.dur}</td>
                    <td className="mono sm">{h.client}</td>
                    <td className="sm" style={{color:h.note.includes("⚠")?C.yellow:h.note.includes("❌")?C.red:C.dim}}>{h.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ──────────────────────────────── GEO MAP ── */}
        {tab==="geomap"&&(
          <div className="geo-wrap">
            <div className="geo-main">
              <div className="geo-ttl">◬ ATTACK ORIGIN MAP — Geographic Threat Intelligence</div>
              <div className="map-area"><WorldMap sources={GEO}/></div>
            </div>
            <div className="geo-sb">
              <div className="sb-ttl">Top Attack Sources</div>
              {[...GEO].sort((a,b)=>b.count-a.count).map(s=>(
                <div key={s.country} className="geo-r">
                  <span className="geo-fl">{getFlag(s.code)}</span>
                  <span className="geo-cn">{s.country}</span>
                  <div className="geo-bg"><div className="geo-fill" style={{width:`${(s.count/GEO[0].count)*100}%`,background:s.color}}/></div>
                  <span className="geo-ct" style={{color:s.color}}>{s.count}</span>
                </div>
              ))}
              <div className="sb-ttl" style={{marginTop:16}}>Attack Categories</div>
              {[
                {l:"Brute Force",c:C.red,pct:38},{l:"Reconnaissance",c:C.yellow,pct:27},
                {l:"Cred Harvesting",c:C.purple,pct:19},{l:"C2 / Tunneling",c:C.orange,pct:11},{l:"Other",c:C.dim,pct:5},
              ].map(x=>(
                <div key={x.l} className="mitre-r">
                  <span className="mit-lbl" style={{minWidth:110}}>{x.l}</span>
                  <div className="mit-bg"><div className="mit-fill" style={{width:`${x.pct}%`,background:x.c}}/></div>
                  <span className="mit-n" style={{color:x.c}}>{x.pct}%</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── STATUS BAR ── */}
      <div className="sbar">
        <span>◈ eth0</span><div className="sbar-sep"/>
        <span>Packets: <b style={{color:C.cyan}}>{stats.total.toLocaleString()}</b></span><div className="sbar-sep"/>
        <span>Shown: <b style={{color:C.text}}>{filtered.length}</b></span><div className="sbar-sep"/>
        <span>Bytes: <b style={{color:C.text}}>{fmtBytes(stats.bytes)}</b></span><div className="sbar-sep"/>
        <span>Filter: <span style={{color:filter?C.yellow:C.muted}}>{filter||"none"}</span></span><div className="sbar-sep"/>
        <span>Profile: Default</span><div className="sbar-sep"/>
        <span>Mode: {cap&&!paused?"Real-time capture":cap&&paused?"Paused":"Idle"}</span>
        <span className="sbar-r" style={{color:cap?C.green:C.muted}}>
          {cap&&!paused?`● CAPTURING  ${Math.round(stats.pps)} pkt/s`:cap&&paused?"⏸ PAUSED":"● READY"}
        </span>
      </div>
    </div>
  );
}
