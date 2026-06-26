import { useState, useEffect, useRef, useMemo } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from "recharts";

const C  = { cyan:"#00e5ff",green:"#00ff9f",red:"#ff2d55",yellow:"#ffd60a",purple:"#c084fc",orange:"#fb923c",text:"#cce4ff",dim:"#5a8aaa",muted:"#2a4a62",bg2:"#071525",border:"#0d2540" };
const PC = { HTTP:"#fb923c",HTTPS:"#4ade80",DNS:"#60a5fa",TCP:"#94a3b8",UDP:"#a8b5c5",LDAP:"#facc15",Kerberos:"#e879f9",RADIUS:"#22d3ee",ICMP:"#f87171",SSH:"#86efac",ARP:"#d4a574",TLS:"#2dd4bf",SMTP:"#ff8c69" };
const SC = { critical:{bg:"#1a0512",border:"#ff2d55",text:"#ff2d55"}, high:{bg:"#1a1000",border:"#ffd60a",text:"#ffd60a"}, medium:{bg:"#001828",border:"#00e5ff",text:"#00e5ff"}, low:{bg:"#001a10",border:"#00ff9f",text:"#00ff9f"} };

const R    = (a,b) => Math.floor(Math.random()*(b-a+1))+a;
const pick = a    => a[R(0,a.length-1)];
const PROTOS = ["HTTP","HTTPS","DNS","TCP","UDP","LDAP","Kerberos","RADIUS","ICMP","SSH","ARP","TLS"];

// University campus IP ranges
const SRCS = ["10.10.1.42","10.10.2.88","10.10.3.15","172.16.5.201","10.10.4.77","192.168.10.9","10.10.6.130","172.16.8.44"];
const DSTS = ["10.10.0.1","10.10.0.10","10.10.0.50","8.8.8.8","10.10.0.25","10.10.0.100","1.1.1.1","203.0.113.5"];

const INFOS = {
  HTTP:"GET /student-portal/login HTTP/1.1",
  HTTPS:"TLSv1.3 Application Data",
  DNS:"Std query A ldap.university.edu",
  TCP:"SYN Seq=0 Win=64240 Len=0",
  UDP:"Src Port: 56123 Dst Port: 514",
  LDAP:"bindRequest cn=student,dc=university,dc=edu",
  Kerberos:"AS-REQ cname: s21btech045@UNIV",
  RADIUS:"Access-Request id=22 (WiFi auth)",
  ICMP:"Echo ping request id=0x1a2b",
  SSH:"Client: SSH-2.0-OpenSSH_8.9p1",
  ARP:"Who has 10.10.0.1? Tell 10.10.1.42",
  TLS:"Client Hello (TLSv1.3)",
};

const THREATS_DATA = [
  {name:"Exam Portal Credential Stuffing",severity:"critical",cvss:9.2,cat:"Credential Access",rule:"ET EXPLOIT HTTP Auth Bruteforce on /exam-portal",sig:"2027901",cve:"CVE-2023-44487"},
  {name:"Unauthorized Library DB Scraping",severity:"critical",cvss:8.8,cat:"Data Exfiltration",rule:"ET POLICY Automated Scraping Detected",sig:"2031002",cve:null},
  {name:"Rogue Access Point (Evil Twin)",severity:"critical",cvss:9.0,cat:"Man-in-the-Middle",rule:"ET WIFI Rogue AP SSID clash UnivWiFi",sig:"2029845",cve:"CVE-2022-47522"},
  {name:"LDAP Plaintext Student Auth",severity:"high",cvss:7.5,cat:"Credential Exposure",rule:"ET POLICY LDAP Cleartext Credentials",sig:"2003324",cve:null},
  {name:"SSH Brute Force (Admin Server)",severity:"high",cvss:8.6,cat:"Brute Force",rule:"ET SCAN SSH Brute Force Attempt",sig:"2001219",cve:"CVE-2023-38408"},
  {name:"DNS Tunneling (C2 Beaconing)",severity:"high",cvss:7.2,cat:"Command & Control",rule:"ET DNS Long TXT Record Query",sig:"2027868",cve:null},
  {name:"ARP Spoofing on Lab Subnet",severity:"medium",cvss:6.5,cat:"Network Recon",rule:"ET POLICY ARP Spoof Detected",sig:"2000537",cve:null},
  {name:"VPN Policy Bypass Attempt",severity:"medium",cvss:5.8,cat:"Defense Evasion",rule:"ET POLICY Unauthorized VPN Protocol",sig:"2019284",cve:null},
];

const GEO = [
  {country:"China",          code:"CN",x:745,y:195,count:212,color:"#ff2d55"},
  {country:"Russia",         code:"RU",x:630,y:138,count:178,color:"#ffd60a"},
  {country:"United States",  code:"US",x:200,y:200,count:134,color:"#00e5ff"},
  {country:"Germany",        code:"DE",x:495,y:160,count:76, color:"#c084fc"},
  {country:"Brazil",         code:"BR",x:285,y:310,count:58, color:"#00ff9f"},
  {country:"India",          code:"IN",x:670,y:235,count:49, color:"#fb923c"},
];

const CONNS = [
  {proto:"TCP",local:"10.10.1.42:52341",  remote:"10.10.0.50:389",   state:"ESTABLISHED",pid:2211,proc:"ldap-auth",  bytes:"12 KB",  dur:"0m 45s"},
  {proto:"TCP",local:"10.10.2.88:54123",  remote:"10.10.0.10:22",    state:"ESTABLISHED",pid:5678,proc:"sshd",       bytes:"89 KB",  dur:"12m 44s"},
  {proto:"TCP",local:"172.16.5.201:49200",remote:"10.10.0.25:443",   state:"ESTABLISHED",pid:4321,proc:"exam-portal",bytes:"2.3 MB", dur:"8m 02s"},
  {proto:"TCP",local:"10.10.3.15:60000",  remote:"10.10.0.100:1812", state:"ESTABLISHED",pid:9001,proc:"radius",     bytes:"4 KB",   dur:"0m 12s"},
  {proto:"TCP",local:"192.168.10.9:54321",remote:"10.10.2.88:22",    state:"SYN_SENT",   pid:9999,proc:"scanner",    bytes:"4.2 KB", dur:"0m 01s"},
  {proto:"UDP",local:"10.10.4.77:60234",  remote:"8.8.8.8:53",       state:"—",           pid:1234,proc:"systemd",   bytes:"2.1 KB", dur:"—"},
  {proto:"TCP",local:"10.10.6.130:52360", remote:"10.10.0.10:88",    state:"TIME_WAIT",   pid:3456,proc:"kinit",     bytes:"8.9 KB", dur:"—"},
  {proto:"TCP",local:"172.16.8.44:45678", remote:"203.0.113.5:443",  state:"ESTABLISHED",pid:7890,proc:"curl",       bytes:"567 KB", dur:"1m 33s"},
];

const DNS_LOG = [
  {time:"14:32:01.123",client:"10.10.1.42",  query:"ldap.university.edu",         type:"A",   resp:"10.10.0.50",         ttl:300,status:"NOERROR"},
  {time:"14:32:01.456",client:"10.10.2.88",  query:"exam.university.edu",          type:"A",   resp:"10.10.0.25",         ttl:300,status:"NOERROR"},
  {time:"14:32:02.789",client:"172.16.5.201",query:"aAbBcC4a5b6c7d8e.evil.com",   type:"TXT", resp:"NXDOMAIN",           ttl:0,  status:"SUSPICIOUS"},
  {time:"14:32:03.100",client:"10.10.3.15",  query:"kerberos.university.edu",      type:"SRV", resp:"dc01.university.edu",ttl:600,status:"NOERROR"},
  {time:"14:32:04.010",client:"192.168.10.9",query:"university.edu",               type:"ANY", resp:"[zone transfer?]",   ttl:0,  status:"SUSPICIOUS"},
  {time:"14:32:04.220",client:"10.10.4.77",  query:"library.university.edu",       type:"A",   resp:"10.10.0.100",        ttl:900,status:"NOERROR"},
  {time:"14:32:05.330",client:"172.16.8.44", query:"wifi.university.edu",          type:"A",   resp:"10.10.0.5",          ttl:300,status:"NOERROR"},
];

const HTTP_LOG = [
  {time:"14:32:01.200",method:"POST",url:"http://student.university.edu/login",           status:200,type:"application/json",size:"2.1 KB",dur:"45ms", client:"10.10.1.42",  note:"⚠ Plaintext credentials"},
  {time:"14:32:01.800",method:"GET", url:"https://exam.university.edu/paper/cs301",        status:200,type:"text/html",       size:"15.3 KB",dur:"120ms",client:"172.16.5.201",note:""},
  {time:"14:32:02.100",method:"GET", url:"https://library.university.edu/api/search?q=*",  status:200,type:"application/json",size:"98.7 KB",dur:"33ms", client:"192.168.10.9",note:"⚠ Automated scraping"},
  {time:"14:32:02.500",method:"POST",url:"http://exam.university.edu/submit",              status:401,type:"text/plain",      size:"128 B", dur:"12ms", client:"10.10.3.15",  note:"❌ Auth failed"},
  {time:"14:32:03.800",method:"DELETE",url:"https://student.university.edu/api/grade/88",  status:403,type:"text/plain",      size:"64 B",  dur:"22ms", client:"192.168.10.9",note:"❌ Unauthorized grade delete"},
  {time:"14:32:04.100",method:"PUT", url:"http://admin.university.edu/api/config",          status:200,type:"application/json",size:"1.2 KB",dur:"67ms", client:"10.10.2.88",  note:"⚠ Admin config change"},
];

let pkId=1;
function genPkt(){
  const proto=pick(PROTOS),src=pick(SRCS),dst=pick(DSTS);
  const pm={HTTP:80,HTTPS:443,DNS:53,TCP:R(1024,9999),UDP:R(1024,9999),LDAP:389,Kerberos:88,RADIUS:1812,ICMP:0,SSH:22,ARP:0,TLS:443};
  return {id:pkId++,tstr:new Date().toLocaleTimeString("en-GB",{hour12:false})+"."+String(R(0,999)).padStart(3,"0"),src,dst,proto,sp:R(1024,65535),dp:pm[proto]||0,size:R(40,1500),ttl:R(48,128),flags:proto==="TCP"?pick(["SYN","ACK","SYN-ACK","PSH-ACK","FIN-ACK","RST"]):"—",info:INFOS[proto]||"Data"};
}
function fmtTime(s){if(!s)return"00:00";const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),ss=Math.floor(s%60);return h>0?`${h}:${String(m).padStart(2,"0")}:${String(ss).padStart(2,"0")}`:`${String(m).padStart(2,"0")}:${String(ss).padStart(2,"0")}`}
function fmtBytes(b){if(b>1073741824)return`${(b/1073741824).toFixed(2)} GB`;if(b>1048576)return`${(b/1048576).toFixed(1)} MB`;if(b>1024)return`${(b/1024).toFixed(1)} KB`;return`${b} B`}
function getFlag(c){return{CN:"🇨🇳",RU:"🇷🇺",US:"🇺🇸",DE:"🇩🇪",BR:"🇧🇷",IN:"🇮🇳"}[c]||"🏴"}

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=JetBrains+Mono:wght@300;400;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg0:#020912;--bg1:#040e1c;--bg2:#071525;--bg3:#0b1d30;--border:#0d2540;--border2:#163555;scrollbar-width:thin;scrollbar-color:#163555 #020912}
body{background:#020912;color:#cce4ff;font-family:'IBM Plex Sans',sans-serif}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:#020912}::-webkit-scrollbar-thumb{background:#163555;border-radius:3px}
.app{display:flex;flex-direction:column;height:100vh;overflow:hidden;position:relative}
.app::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,0.01) 2px,rgba(0,229,255,0.01) 4px);pointer-events:none;z-index:1000}
.topbar{display:flex;align-items:center;gap:10px;padding:0 14px;height:50px;flex-shrink:0;background:linear-gradient(180deg,#0a1e35 0%,#050e1c 100%);border-bottom:1px solid #163555;box-shadow:0 1px 0 #00e5ff25,0 4px 20px rgba(0,0,0,.5)}
.logo{display:flex;align-items:center;gap:9px;flex-shrink:0}
.lmark{width:32px;height:32px;border:1.5px solid #00e5ff;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:15px;color:#00e5ff;animation:lp 3s ease-in-out infinite;box-shadow:0 0 12px #00e5ff30,inset 0 0 12px #00e5ff12}
@keyframes lp{0%,100%{box-shadow:0 0 8px #00e5ff30,inset 0 0 8px #00e5ff12}50%{box-shadow:0 0 20px #00e5ff50,inset 0 0 16px #00e5ff20}}
.ltxt{font-family:'Orbitron',sans-serif;font-weight:900;font-size:14px;color:#00e5ff;letter-spacing:3px}
.lver{font-family:'Orbitron',sans-serif;font-size:8px;color:#2a4a62;letter-spacing:2px}
.tc{display:flex;align-items:center;gap:8px;flex:1;min-width:0}
.isel{background:#0b1d30;border:1px solid #163555;color:#00e5ff;padding:5px 9px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;cursor:pointer;flex-shrink:0;outline:none}
.fb{position:relative;flex:1;display:flex;align-items:center}
.fb input{width:100%;background:#040e1c;border:1px solid #0d2540;color:#cce4ff;padding:7px 28px 7px 28px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:11px;outline:none;transition:border-color .2s}
.fb input:focus{border-color:#00e5ff40;box-shadow:0 0 0 2px #00e5ff10}
.fb input::placeholder{color:#2a4a62}
.fbi{position:absolute;left:9px;color:#2a4a62;font-size:14px}
.fbc{position:absolute;right:7px;background:none;border:none;color:#5a8aaa;cursor:pointer;font-size:11px}
.tr{display:flex;align-items:center;gap:5px;flex-shrink:0}
.blv{display:flex;align-items:center;gap:5px;background:#001f0d;border:1px solid #00ff9f50;color:#00ff9f;padding:4px 10px;border-radius:20px;font-size:9.5px;font-family:'Orbitron',sans-serif;letter-spacing:2px}
.bld{width:6px;height:6px;border-radius:50%;background:#00ff9f;animation:ld 1s infinite}
@keyframes ld{0%,100%{opacity:1;box-shadow:0 0 6px #00ff9f}50%{opacity:.4;box-shadow:none}}
.bp{background:#1c1400;border:1px solid #ffd60a40;color:#ffd60a;padding:4px 10px;border-radius:20px;font-size:9.5px}
.btn{padding:5px 13px;border-radius:4px;border:1px solid;cursor:pointer;font-size:11px;transition:all .15s;white-space:nowrap}
.bs{background:#001f0d;border-color:#00ff9f40;color:#00ff9f}.bs:hover{background:#002f18;border-color:#00ff9f}
.bpa{background:#1c1400;border-color:#ffd60a40;color:#ffd60a}
.bst{background:#1a0510;border-color:#ff2d5540;color:#ff2d55}
.bcl{background:#0b1d30;border-color:#0d2540;color:#5a8aaa}.bcl:hover{color:#cce4ff}
.bex{background:#0f001a;border-color:#c084fc40;color:#c084fc}
.mrow{display:flex;gap:1px;background:#0d2540;border-bottom:1px solid #0d2540;flex-shrink:0}
.mc{flex:1;background:#040e1c;padding:8px 13px;display:flex;align-items:center;gap:9px;border-right:1px solid #0d2540;cursor:default}
.mc:hover{background:#071525}
.mi{font-size:17px;flex-shrink:0}
.ml{font-family:'Orbitron',sans-serif;font-size:8px;color:#2a4a62;letter-spacing:2px;text-transform:uppercase;margin-bottom:1px}
.mv{font-family:'Orbitron',sans-serif;font-size:15px;font-weight:700;line-height:1}
.ms{font-size:9.5px;color:#5a8aaa;margin-top:2px}
.tabbar{display:flex;background:#040e1c;border-bottom:1px solid #0d2540;overflow-x:auto;flex-shrink:0}
.tabbar::-webkit-scrollbar{height:3px}
.tb{display:flex;align-items:center;gap:5px;padding:8px 13px;white-space:nowrap;background:transparent;border:none;border-bottom:2px solid transparent;color:#2a4a62;cursor:pointer;font-size:11px;font-family:'IBM Plex Sans',sans-serif;transition:all .15s;border-right:1px solid #0d2540}
.tb:hover{color:#cce4ff;background:#071525}
.tb.on{color:#00e5ff;border-bottom-color:#00e5ff}
.tbdg{background:#0b1d30;border:1px solid #163555;color:#5a8aaa;padding:0 5px;border-radius:8px;font-size:9px;font-family:'JetBrains Mono',monospace}
.tbdg.r{background:#1a0512;border-color:#ff2d5540;color:#ff2d55}
.tbdg.g{background:#001a10;border-color:#00ff9f40;color:#00ff9f}
.content{flex:1;overflow:hidden;background:#020912}
.lw{display:flex;height:100%;overflow:hidden}
.pw{flex:1;overflow:auto}
.pt{width:100%;border-collapse:collapse;font-size:11px}
.pt th{position:sticky;top:0;z-index:2;background:#081728;padding:6px 9px;text-align:left;font-size:9px;color:#2a4a62;font-weight:600;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #163555;white-space:nowrap}
.pk{border-bottom:1px solid #081520;cursor:pointer;transition:background .07s}
.pk:hover{background:#0d1f35!important}
.pk:nth-child(even){background:#040d18}
.pk.sel{background:#001c2e!important;outline:2px solid #00e5ff20;outline-offset:-2px}
.pt td{padding:4px 9px;white-space:nowrap}
.ptag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700;font-family:'JetBrains Mono',monospace}
.ic{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#5a8aaa}
.mono{font-family:'JetBrains Mono',monospace}.sm{font-size:10px}.dim{color:#5a8aaa}.muted{color:#2a4a62}
.epk{text-align:center;padding:45px;color:#2a4a62;font-family:'Orbitron',sans-serif;letter-spacing:3px;font-size:11px}
.lsb{width:240px;background:#050d1a;border-left:1px solid #0d2540;overflow-y:auto;flex-shrink:0}
.ss{padding:11px;border-bottom:1px solid #0d2540}
.sst{font-family:'Orbitron',sans-serif;font-size:8px;color:#2a4a62;letter-spacing:3px;text-transform:uppercase;margin-bottom:9px;display:flex;align-items:center;gap:5px}
.sst::after{content:'';flex:1;height:1px;background:#0d2540}
.pbr{display:flex;align-items:center;gap:5px;margin-bottom:4px}
.pbl{font-family:'JetBrains Mono',monospace;font-size:9.5px;font-weight:700;width:62px;flex-shrink:0}
.pbb{flex:1;height:3px;background:#0d2540;border-radius:2px}
.pbf{height:3px;border-radius:2px;transition:width .5s}
.pbp{font-family:'JetBrains Mono',monospace;font-size:9px;color:#2a4a62;width:32px;text-align:right}
.malt{display:flex;align-items:center;gap:5px;padding:4px 0;border-bottom:1px solid #081520}
.mals{width:16px;height:16px;border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;flex-shrink:0}
.maln{font-size:10px;color:#cce4ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ph{display:flex;flex-direction:column;height:100%}
.phh{display:flex;padding:7px 11px;background:#0b1d30;border-bottom:1px solid #163555;font-size:9px;color:#2a4a62;font-weight:600;text-transform:uppercase;letter-spacing:1px;flex-shrink:0}
.phb{flex:1;overflow:auto}
.tn{display:flex;align-items:center;padding:5px 11px;cursor:pointer;gap:5px;border-bottom:1px solid #060f1a;transition:background .1s}
.tn:hover{background:#071525}
.tni{width:12px;color:#2a4a62;font-size:10px;font-family:monospace;flex-shrink:0}
.tnn{flex:3;font-size:11px;color:#cce4ff}
.tnp,.tnk,.tnb,.tnbps,.tne{flex:1;font-family:'JetBrains Mono',monospace;font-size:10px;color:#5a8aaa;text-align:right}
.phf{display:flex;gap:16px;padding:7px 11px;background:#050d1a;border-top:1px solid #0d2540;font-size:10px;color:#2a4a62;flex-shrink:0}
.inw{display:flex;height:100%}
.inm{flex:1;overflow:auto;display:flex;flex-direction:column}
.ina{width:205px;background:#050d1a;border-left:1px solid #0d2540;overflow-y:auto;padding:11px;flex-shrink:0}
.ints{display:flex;border-bottom:1px solid #0d2540;flex-shrink:0}
.intt{padding:7px 14px;background:transparent;border:none;color:#5a8aaa;cursor:pointer;font-size:11px;border-bottom:2px solid transparent;transition:all .15s}
.intt.on{color:#00e5ff;border-bottom-color:#00e5ff}
.dc{overflow:auto;flex:1;padding:7px}
.dl{margin-bottom:3px}
.dlh{display:flex;align-items:center;gap:5px;padding:5px 9px;cursor:pointer;background:#071525;border:1px solid #0d2540;border-radius:4px;transition:background .1s}
.dlh:hover{background:#0b1d30}
.dlt{color:#2a4a62;font-size:10px;width:12px}
.dln{font-size:11px;font-weight:600}
.dlf{padding:3px 0 7px 26px;background:#040e1c;border:1px solid #0d2540;border-top:none;border-radius:0 0 4px 4px}
.dfi{display:flex;gap:7px;padding:2px 7px}.dfi:hover{background:#071525}
.dfk{color:#5a8aaa;font-family:'JetBrains Mono',monospace;font-size:10px;min-width:158px;flex-shrink:0}
.dfv{color:#cce4ff;font-family:'JetBrains Mono',monospace;font-size:10px}
.dfn{color:#00ff9f;font-size:9px;margin-left:4px}
.hxd{font-family:'JetBrains Mono',monospace;font-size:10.5px;overflow:auto;flex:1;padding:11px 14px;background:#020912}
.hxhd{display:flex;gap:14px;color:#2a4a62;margin-bottom:7px;font-size:9px;border-bottom:1px solid #0d2540;padding-bottom:5px}
.hxr{display:flex;gap:14px;padding:2px 0}.hxr:hover{background:#071525}
.hxo{color:#2a4a62;width:36px}.hxb{color:#4fc3f7;flex:1;letter-spacing:.7px}.hxa{color:#00ff9f;width:105px}
.sr{display:flex;gap:5px;padding:3px 0;border-bottom:1px solid #0a1620}
.sk{font-size:9.5px;color:#2a4a62;min-width:76px;flex-shrink:0}
.sv{font-size:10.5px;color:#cce4ff;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nb{display:flex;gap:5px;margin-top:5px}
.nbb{flex:1;background:#0b1d30;border:1px solid #0d2540;color:#5a8aaa;padding:5px;border-radius:3px;cursor:pointer;font-size:10px;transition:all .15s}
.nbb:hover{color:#00e5ff;border-color:#00e5ff30}
.es{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:#2a4a62;gap:8px;text-align:center}
.esic{font-size:34px;margin-bottom:4px}
.tw{display:flex;height:100%}
.tmn{flex:1;overflow:auto;display:flex;flex-direction:column}
.tsb{width:210px;background:#050d1a;border-left:1px solid #0d2540;overflow-y:auto;padding:11px;flex-shrink:0}
.svbar{display:flex;gap:1px;background:#0d2540;flex-shrink:0}
.svc{flex:1;padding:10px;text-align:center}
.svl{font-family:'Orbitron',sans-serif;font-size:8px;letter-spacing:2px}
.svn{font-family:'Orbitron',sans-serif;font-size:20px;font-weight:700}
.als{flex:1;overflow:auto;padding:7px;display:flex;flex-direction:column;gap:5px}
.ac{display:flex;gap:9px;padding:9px 11px;border:1px solid;border-left:3px solid;border-radius:4px;transition:filter .15s}
.ac:hover{filter:brightness(1.08)}
.acl{display:flex;flex-direction:column;align-items:center;gap:3px;flex-shrink:0;min-width:52px}
.acsv{font-family:'Orbitron',sans-serif;font-size:8px;font-weight:700;border:1px solid;padding:2px 4px;border-radius:2px;letter-spacing:1px;text-align:center}
.accv{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:700}
.acbd{flex:1;min-width:0}
.acnm{font-size:12px;font-weight:600;color:#cce4ff;margin-bottom:3px}
.acmt{display:flex;gap:8px;font-size:9.5px;color:#5a8aaa;flex-wrap:wrap;margin-bottom:2px}
.cve{color:#c084fc}
.acrl{font-family:'JetBrains Mono',monospace;font-size:9.5px;color:#2a4a62;margin-bottom:3px}
.acfl{display:flex;align-items:center;gap:5px;font-size:10px}
.fla{color:#2a4a62}
.acpt{background:#0b1d30;border:1px solid #0d2540;color:#5a8aaa;padding:0 5px;border-radius:8px;font-size:9px}
.acr{flex-shrink:0;text-align:right}
.actm{font-size:9px;color:#2a4a62;font-family:'JetBrains Mono',monospace}
.acct{font-family:'Orbitron',sans-serif;font-size:13px;font-weight:700}
.mtr{display:flex;align-items:center;gap:5px;margin-bottom:6px}
.mtb{flex:1;height:3px;background:#0d2540;border-radius:2px}
.mtf{height:3px;border-radius:2px;transition:width .4s}
.mtl{font-size:9px;color:#5a8aaa;min-width:96px}
.mtn{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;min-width:18px;text-align:right}
.cw{height:100%;overflow:auto;display:flex;flex-direction:column}
.ctb{display:flex;align-items:center;gap:12px;padding:8px 13px;background:#050d1a;border-bottom:1px solid #0d2540;flex-shrink:0}
.cst{display:flex;gap:12px;font-size:10.5px;color:#5a8aaa}
.ctt{width:100%;border-collapse:collapse;font-size:11px}
.ctt th{position:sticky;top:0;z-index:2;background:#081728;padding:6px 11px;text-align:left;font-size:9px;color:#2a4a62;font-weight:600;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #163555}
.cr{border-bottom:1px solid #060f1a;transition:background .1s}.cr:hover{background:#071525}
.ctt td{padding:6px 11px}
.sg{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:#0d2540;height:100%;overflow:auto}
.sp{background:#050d1a;padding:13px;overflow:auto}
.spt{font-family:'Orbitron',sans-serif;font-size:8px;color:#2a4a62;letter-spacing:3px;text-transform:uppercase;margin-bottom:11px}
.tdr{display:flex;align-items:center;gap:7px;margin-bottom:5px}
.tdb{flex:1;height:3px;background:#0d2540;border-radius:2px}
.tdf{height:3px;border-radius:2px;background:#00e5ff;transition:width .4s}
.dnw{height:100%;overflow:auto;display:flex;flex-direction:column}
.dns{display:flex;gap:1px;background:#0d2540;flex-shrink:0}
.dsc{flex:1;padding:11px;background:#050d1a;text-align:center}
.dsv{display:block;font-family:'Orbitron',sans-serif;font-size:18px;font-weight:700;color:#00e5ff}
.dsl{font-size:9px;color:#2a4a62;margin-top:2px}
.dnt{width:100%;border-collapse:collapse;font-size:11px}
.dnt th{position:sticky;top:0;z-index:2;background:#081728;padding:6px 9px;text-align:left;font-size:9px;color:#2a4a62;font-weight:600;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #163555}
.dr{border-bottom:1px solid #060f1a;transition:background .1s}.dr:hover{background:#071525}
.dnt td{padding:5px 9px}
.ttg{background:#0b1d30;border:1px solid #163555;color:#00e5ff;padding:1px 5px;border-radius:3px;font-size:9.5px;font-family:'JetBrains Mono',monospace}
.htw{height:100%;overflow:auto;display:flex;flex-direction:column}
.hts{display:flex;gap:1px;background:#0d2540;flex-shrink:0}
.hsc{flex:1;padding:10px;background:#050d1a;text-align:center;border-left:3px solid}
.hsv{display:block;font-family:'Orbitron',sans-serif;font-size:18px;font-weight:700}
.hsl{font-size:9px;color:#2a4a62}
.htt{width:100%;border-collapse:collapse;font-size:10.5px}
.htt th{position:sticky;top:0;z-index:2;background:#081728;padding:6px 9px;text-align:left;font-size:9px;color:#2a4a62;font-weight:600;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #163555}
.hr{border-bottom:1px solid #060f1a;transition:background .1s}.hr:hover{background:#071525}
.htt td{padding:5px 9px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mt{padding:1px 6px;border-radius:3px;font-size:9.5px;font-weight:700;font-family:'JetBrains Mono',monospace}
.mget{background:#001824;border:1px solid #00e5ff40;color:#00e5ff}
.mpost{background:#001a10;border:1px solid #00ff9f40;color:#00ff9f}
.mdel{background:#1a0510;border:1px solid #ff2d5540;color:#ff2d55}
.mput{background:#1c1400;border:1px solid #ffd60a40;color:#ffd60a}
.gw{display:flex;height:100%}
.gm{flex:1;display:flex;flex-direction:column;overflow:hidden}
.gttl{padding:8px 14px;font-family:'Orbitron',sans-serif;font-size:9px;color:#2a4a62;letter-spacing:2px;border-bottom:1px solid #0d2540}
.ma{flex:1;display:flex;align-items:center;justify-content:center;padding:11px;overflow:hidden}
.msv{width:100%;height:100%;max-height:400px}
.gsb{width:225px;background:#050d1a;border-left:1px solid #0d2540;overflow-y:auto;padding:11px;flex-shrink:0}
.gr{display:flex;align-items:center;gap:5px;margin-bottom:7px}
.gfl{font-size:14px}.gcn{font-size:10.5px;color:#cce4ff;min-width:86px;flex-shrink:0}
.gbg{flex:1;height:3px;background:#0d2540;border-radius:2px}.gfil{height:3px;border-radius:2px}
.gct{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;min-width:26px;text-align:right}
.sb{display:flex;align-items:center;gap:12px;padding:4px 13px;background:#040e1c;border-top:1px solid #0d2540;font-size:10px;color:#2a4a62;font-family:'JetBrains Mono',monospace;flex-shrink:0}
.sbsep{width:1px;height:11px;background:#0d2540}.sbr{margin-left:auto}
.recharts-default-tooltip{background:#071525!important;border:1px solid #163555!important;border-radius:4px!important;font-size:10px!important;color:#cce4ff!important}
`;

function Metric({icon,label,value,sub,color}){
  return <div className="mc"><div className="mi" style={{color,textShadow:`0 0 10px ${color}80`}}>{icon}</div><div><div className="ml">{label}</div><div className="mv" style={{color}}>{value}</div><div className="ms">{sub}</div></div></div>;
}

function TreeNode({node,depth,total,open,setOpen}){
  const id=node.name,isO=open.has(id),hasC=node.children?.length>0;
  const pkts=Math.round((node.pct/100)*total)||0,bytes=pkts*R(60,200);
  return <>
    <div className="tn" style={{paddingLeft:11+depth*18}} onClick={()=>hasC&&setOpen(p=>{const n=new Set(p);isO?n.delete(id):n.add(id);return n})}>
      <span className="tni">{hasC?(isO?"▼":"▶"):" "}</span>
      <span className="tnn">{node.name}</span>
      <span className="tnp">{node.pct.toFixed(1)}%</span>
      <span className="tnk">{pkts.toLocaleString()}</span>
      <span className="tnb">{bytes>1024?`${(bytes/1024).toFixed(1)}k`:bytes}</span>
      <span className="tnbps">{Math.round(bytes*.08).toLocaleString()}</span>
      <span className="tne">{!hasC?pkts.toLocaleString():"—"}</span>
    </div>
    {isO&&node.children?.map(c=><TreeNode key={c.name} node={c} depth={depth+1} total={total} open={open} setOpen={setOpen}/>)}
  </>;
}

function DecodeLayer({layer}){
  const [o,setO]=useState(true);
  return <div className="dl">
    <div className="dlh" onClick={()=>setO(x=>!x)}>
      <span className="dlt">{o?"▼":"▶"}</span>
      <span className="dln" style={{color:layer.color}}>{layer.name}</span>
    </div>
    {o&&<div className="dlf">{layer.fields.map((f,i)=><div key={i} className="dfi"><span className="dfk">{f.k}:</span><span className="dfv">{f.v}</span>{f.n&&<span className="dfn">{f.n}</span>}</div>)}</div>}
  </div>;
}

const PROTO_TREE={name:"Frame",pct:100,children:[{name:"Ethernet II",pct:100,children:[{name:"Internet Protocol v4",pct:94.8,children:[{name:"Transmission Control Protocol",pct:72.3,children:[{name:"Transport Layer Security (TLS 1.3)",pct:38.2,children:[{name:"HTTPS (Student Portal / Exam)",pct:38.2,children:[]}]},{name:"HyperText Transfer Protocol",pct:18.5,children:[]},{name:"Secure Shell Protocol (SSH)",pct:9.8,children:[]},{name:"LDAP / Kerberos (Campus Auth)",pct:5.8,children:[]}]},{name:"User Datagram Protocol",pct:18.2,children:[{name:"Domain Name System",pct:12.4,children:[]},{name:"RADIUS (Wi-Fi Auth)",pct:5.8,children:[]}]},{name:"ICMP",pct:4.3,children:[]}]},{name:"Address Resolution Protocol",pct:5.2,children:[]}]}]};

function buildTree(p){
  if(!p) return [];
  return [
    {name:`Frame ${p.id}: ${p.size} bytes on wire`,color:"#94a3b8",fields:[{k:"Interface",v:"eth0 (Campus Core Switch)"},{k:"Arrival Time",v:p.tstr},{k:"Frame Length",v:`${p.size} bytes`},{k:"Capture Length",v:`${p.size} bytes`}]},
    {name:`Ethernet II  Src: aa:bb:cc:dd:ee:ff`,color:"#fb923c",fields:[{k:"Destination",v:"ff:ff:ff:ff:ff:ff (Broadcast)"},{k:"Source",v:`aa:bb:cc:${R(10,99)}:${R(10,99)}:ff`},{k:"Type",v:"IPv4 (0x0800)"},{k:"FCS",v:`0x${R(1000,9999).toString(16)}`,n:"[correct]"}]},
    {name:`Internet Protocol v4  Src: ${p.src}  Dst: ${p.dst}`,color:"#60a5fa",fields:[{k:"Version",v:"4"},{k:"Header Length",v:"20 bytes"},{k:"Total Length",v:String(p.size-14)},{k:"TTL",v:String(p.ttl)},{k:"Protocol",v:p.proto==="UDP"?"UDP (17)":"TCP (6)"},{k:"Checksum",v:`0x${R(1000,9999).toString(16)}`,n:"[correct]"},{k:"Source",v:p.src},{k:"Destination",v:p.dst}]},
    {name:`TCP  Src Port: ${p.sp}  Dst Port: ${p.dp}  Flags: ${p.flags}`,color:"#c084fc",fields:[{k:"Source Port",v:String(p.sp)},{k:"Destination Port",v:String(p.dp)},{k:"Sequence Number",v:String(R(1000000,9999999))},{k:"Ack Number",v:String(R(1000000,9999999))},{k:"Flags",v:`0x018 (${p.flags})`},{k:"Window Size",v:"65535"},{k:"Options",v:"MSS=1460, WS=256, SACK_PERM"}]},
    {name:`Application: ${p.proto}`,color:PC[p.proto]||"#888",fields:[{k:"Protocol",v:p.proto},{k:"Info",v:p.info},{k:"Payload",v:`${p.size-54} bytes`}]},
  ];
}

function genHex(n){const b=Array.from({length:n},()=>R(0,255).toString(16).padStart(2,"0"));const rows=[];for(let i=0;i<b.length;i+=16){const ch=b.slice(i,i+16);rows.push({off:i.toString(16).padStart(4,"0"),hex:ch.map((x,j)=>(j===8?" ":"")+x).join(" "),asc:ch.map(x=>{const c=parseInt(x,16);return c>=32&&c<127?String.fromCharCode(c):"."}).join("")})}return rows;}

export default function App(){
  useEffect(()=>{
    const style=document.createElement("style");style.textContent=CSS;document.head.appendChild(style);
    const link=document.createElement("link");link.rel="stylesheet";link.href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=JetBrains+Mono:wght@300;400;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap";document.head.appendChild(link);
    return()=>{document.head.removeChild(style);document.head.removeChild(link)};
  },[]);

  const [cap,setCap]=useState(false);
  const [paused,setPaused]=useState(false);
  const [pkts,setPkts]=useState([]);
  const [alerts,setAlerts]=useState([]);
  const [traffic,setTraf]=useState(Array.from({length:20},(_,i)=>({t:i,pkts:R(5,25),bps:R(5000,300000)})));
  const [protoC,setProtoC]=useState({});
  const [sel,setSel]=useState(null);
  const [tab,setTab]=useState("live");
  const [filter,setFilt]=useState("");
  const [stats,setStats]=useState({total:0,bytes:0,threats:0,pps:0,elapsed:0});
  const [hexTab,setHexTab]=useState("decode");
  const [cSearch,setCSearch]=useState("");
  const [treeOpen,setTreeOpen]=useState(new Set(["Frame","Ethernet II","Internet Protocol v4","Transmission Control Protocol"]));
  const [pktTree,setPktTree]=useState(null);
  const [pktHex,setPktHex]=useState([]);
  const ivRef=useRef(null),atRef=useRef(null),t0Ref=useRef(null);

  useEffect(()=>{
    if(cap&&!paused){
      t0Ref.current=t0Ref.current||Date.now();
      ivRef.current=setInterval(()=>{
        const batch=Array.from({length:R(3,7)},genPkt);
        setPkts(p=>[...batch,...p].slice(0,250));
        setProtoC(p=>{const n={...p};batch.forEach(pk=>{n[pk.proto]=(n[pk.proto]||0)+1});return n});
        setStats(p=>({total:p.total+batch.length,bytes:p.bytes+batch.reduce((s,pk)=>s+pk.size,0),threats:p.threats,pps:batch.length*(1000/750),elapsed:(Date.now()-t0Ref.current)/1000}));
        setTraf(p=>[...p,{t:p.length,pkts:batch.length,bps:batch.reduce((s,pk)=>s+pk.size*8,0)}].slice(-40));
      },750);
      atRef.current=setInterval(()=>{
        if(Math.random()<0.3){
          const t={...pick(THREATS_DATA),id:Date.now(),time:new Date().toISOString(),src:pick(SRCS),dst:pick(DSTS),proto:pick(["TCP","HTTPS","LDAP","RADIUS"]),count:R(1,60)};
          setAlerts(p=>[t,...p].slice(0,40));
          setStats(p=>({...p,threats:p.threats+1}));
        }
      },2500);
    } else { clearInterval(ivRef.current);clearInterval(atRef.current); }
    return()=>{clearInterval(ivRef.current);clearInterval(atRef.current)};
  },[cap,paused]);

  const filtered=useMemo(()=>{
    if(!filter.trim()) return pkts;
    const f=filter.toLowerCase();
    return pkts.filter(p=>p.proto.toLowerCase().includes(f)||p.src.includes(f)||p.dst.includes(f)||p.info.toLowerCase().includes(f)||String(p.dp).includes(f));
  },[pkts,filter]);

  const pieData=useMemo(()=>Object.entries(protoC).map(([name,value])=>({name,value})),[protoC]);
  const totalPkts=Object.values(protoC).reduce((a,b)=>a+b,0)||1;

  const startCap=()=>{setCap(true);t0Ref.current=Date.now()};
  const stopCap =()=>{setCap(false);t0Ref.current=null};
  const clear   =()=>{setPkts([]);setAlerts([]);setProtoC({});setStats({total:0,bytes:0,threats:0,pps:0,elapsed:0});pkId=1;setSel(null)};
  const onSelectPkt=(p)=>{setSel(p);setPktTree(buildTree(p));setPktHex(genHex(p.size));setTab("inspector")};

  const TABS=[
    {id:"live",      ico:"◈", lbl:"Live Capture",       badge:filtered.length},
    {id:"protocols", ico:"◫", lbl:"Protocol Hierarchy"},
    {id:"inspector", ico:"⊕", lbl:"Packet Inspector",    badge:sel?`#${sel.id}`:null,bc:"g"},
    {id:"threats",   ico:"⚠", lbl:"Threat Intel",        badge:alerts.length,bc:alerts.filter(a=>a.severity==="critical").length?"r":null},
    {id:"connections",ico:"◉",lbl:"Connections",          badge:CONNS.length},
    {id:"statistics",ico:"◷", lbl:"Statistics"},
    {id:"dns",       ico:"◎", lbl:"DNS",                 badge:DNS_LOG.length},
    {id:"http",      ico:"⬡", lbl:"HTTP",                badge:HTTP_LOG.length},
    {id:"geomap",    ico:"◬", lbl:"Geo Map"},
  ];

  return <div className="app">
    {/* TOPBAR */}
    <div className="topbar">
      <div className="logo">
        <div className="lmark">◈</div>
        <div>
          <div className="ltxt">NETWATCH</div>
          <div className="lver">UNIVERSITY EDITION — CAMPUS LAN SECURITY</div>
        </div>
      </div>
      <div className="tc">
        <select className="isel">
          <option>eth0  ▸  10.10.0.1/16  (Campus Core)</option>
          <option>eth1  ▸  172.16.0.1/20  (Faculty LAN)</option>
          <option>wlan0 ▸  192.168.10.1/24  (UnivWiFi)</option>
          <option>any   ▸  (all interfaces)</option>
        </select>
        <div className="fb">
          <span className="fbi">⌕</span>
          <input placeholder="Apply filter … (e.g. ldap || ip.src==10.10.1.42 || dns.qry.name contains university.edu)" value={filter} onChange={e=>setFilt(e.target.value)}/>
          {filter&&<button className="fbc" onClick={()=>setFilt("")}>✕</button>}
        </div>
      </div>
      <div className="tr">
        {cap&&!paused&&<span className="blv"><span className="bld"/>LIVE</span>}
        {cap&&paused&&<span className="bp">⏸ PAUSED</span>}
        {!cap&&<button className="btn bs" onClick={startCap}>▶ Start Capture</button>}
        {cap&&<button className="btn bpa" onClick={()=>setPaused(p=>!p)}>{paused?"▶ Resume":"⏸ Pause"}</button>}
        {cap&&<button className="btn bst" onClick={stopCap}>⏹ Stop</button>}
        <button className="btn bcl" onClick={clear}>⌫ Clear</button>
        <button className="btn bex">⬇ Export .pcap</button>
      </div>
    </div>

    {/* METRICS */}
    <div className="mrow">
      <Metric icon="◫" label="Packets Captured"  value={stats.total.toLocaleString()}                           sub={`${Math.round(stats.pps)} pkt/s`}                        color={C.cyan}/>
      <Metric icon="◈" label="Data Volume"        value={fmtBytes(stats.bytes)}                                  sub="campus throughput"                                       color={C.green}/>
      <Metric icon="⚠" label="IDS Alerts"         value={stats.threats}                                          sub={`${alerts.filter(a=>a.severity==="critical").length} critical`} color={C.red}/>
      <Metric icon="◉" label="Active Protocols"   value={Object.keys(protoC).length||0}                          sub={`of ${PROTOS.length} monitored`}                         color={C.purple}/>
      <Metric icon="◷" label="Session Time"       value={fmtTime(stats.elapsed)}                                 sub={cap?(paused?"paused":"live"):"idle"}                     color={C.yellow}/>
      <Metric icon="◎" label="Packet Loss"        value="0"                                                      sub="0.000% drop rate"                                        color={C.orange}/>
    </div>

    {/* TABBAR */}
    <div className="tabbar">
      {TABS.map(t=>(
        <button key={t.id} className={`tb${tab===t.id?" on":""}`} onClick={()=>setTab(t.id)}>
          {t.ico} {t.lbl}
          {t.badge!=null&&t.badge!==false&&<span className={`tbdg${t.bc?" "+t.bc:""}`}>{t.badge}</span>}
        </button>
      ))}
    </div>

    {/* CONTENT */}
    <div className="content">

      {/* LIVE CAPTURE */}
      {tab==="live"&&<div className="lw">
        <div className="pw">
          <table className="pt">
            <thead><tr><th>No.</th><th>Timestamp</th><th>Source</th><th>Src Port</th><th>Destination</th><th>Dst Port</th><th>Protocol</th><th>Length</th><th>TTL</th><th>Flags</th><th>Info</th></tr></thead>
            <tbody>
              {filtered.slice(0,80).map(p=>(
                <tr key={p.id} className={`pk${sel?.id===p.id?" sel":""}`} onClick={()=>onSelectPkt(p)}>
                  <td className="mono muted sm">{p.id}</td>
                  <td className="mono dim sm">{p.tstr}</td>
                  <td className="mono sm">{p.src}</td>
                  <td className="mono muted sm">{p.sp}</td>
                  <td className="mono sm">{p.dst}</td>
                  <td className="mono muted sm">{p.dp||"—"}</td>
                  <td><span className="ptag" style={{background:PC[p.proto]+"22",border:`1px solid ${PC[p.proto]}40`,color:PC[p.proto]||"#888"}}>{p.proto}</span></td>
                  <td className="mono muted sm">{p.size}</td>
                  <td className="mono muted sm">{p.ttl}</td>
                  <td className="mono sm" style={{color:["RST","SYN"].includes(p.flags)?C.red:C.dim,fontSize:9.5}}>{p.flags}</td>
                  <td className="ic mono sm">{p.info}</td>
                </tr>
              ))}
              {filtered.length===0&&<tr><td colSpan={11} className="epk">{cap?"— No packets match filter —":"◈  Press Start Capture to begin monitoring campus traffic"}</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="lsb">
          <div className="ss">
            <div className="sst">Protocol Breakdown</div>
            {Object.entries(protoC).sort((a,b)=>b[1]-a[1]).slice(0,9).map(([p,c])=>{
              const pct=((c/totalPkts)*100).toFixed(1);
              return <div key={p} className="pbr"><span className="pbl" style={{color:PC[p]||"#888"}}>{p}</span><div className="pbb"><div className="pbf" style={{width:`${pct}%`,background:PC[p]||"#888"}}/></div><span className="pbp">{pct}%</span></div>;
            })}
            {Object.keys(protoC).length===0&&<div className="muted sm">Waiting for campus traffic…</div>}
          </div>
          <div className="ss">
            <div className="sst">Traffic Rate</div>
            <ResponsiveContainer width="100%" height={85}>
              <AreaChart data={traffic.slice(-20)}>
                <defs><linearGradient id="tg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.cyan} stopOpacity={.35}/><stop offset="100%" stopColor={C.cyan} stopOpacity={0}/></linearGradient></defs>
                <Area type="monotone" dataKey="pkts" stroke={C.cyan} fill="url(#tg)" strokeWidth={1.5} dot={false}/>
                <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:9,color:C.text}}/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="ss">
            <div className="sst">Latest Alerts</div>
            {alerts.slice(0,5).map(a=>(
              <div key={a.id} className="malt">
                <span className="mals" style={{background:SC[a.severity].bg,border:`1px solid ${SC[a.severity].border}`,color:SC[a.severity].text}}>{a.severity[0].toUpperCase()}</span>
                <span className="maln">{a.name}</span>
              </div>
            ))}
            {alerts.length===0&&<div className="muted sm">No alerts yet</div>}
          </div>
          <div className="ss">
            <div className="sst">Top Hosts</div>
            {Object.entries(pkts.slice(0,100).reduce((acc,p)=>{acc[p.src]=(acc[p.src]||0)+1;return acc},{})).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([ip,c])=>(
              <div key={ip} style={{display:"flex",gap:5,padding:"3px 0",borderBottom:"1px solid #0a1620"}}>
                <span className="mono sm" style={{flex:1,color:C.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{ip}</span>
                <span className="mono sm muted">{c}</span>
              </div>
            ))}
          </div>
        </div>
      </div>}

      {/* PROTOCOL HIERARCHY */}
      {tab==="protocols"&&<div className="ph">
        <div className="phh">
          <div style={{flex:3}}>Protocol</div><div style={{flex:1,textAlign:"right"}}>% Pkts</div><div style={{flex:1,textAlign:"right"}}>Packets</div><div style={{flex:1,textAlign:"right"}}>Bytes</div><div style={{flex:1,textAlign:"right"}}>Bits/s</div><div style={{flex:1,textAlign:"right"}}>End Pkts</div>
        </div>
        <div className="phb"><TreeNode node={PROTO_TREE} depth={0} total={stats.total} open={treeOpen} setOpen={setTreeOpen}/></div>
        <div className="phf">
          <span>{stats.total.toLocaleString()} packets total</span><span>{fmtBytes(stats.bytes)}</span>
          <span>{Object.keys(protoC).length} protocols active</span><span>Interface: eth0 (Campus Core)</span>
        </div>
      </div>}

      {/* PACKET INSPECTOR */}
      {tab==="inspector"&&<div className="inw">
        <div className="inm">
          {!sel?<div className="es"><div className="esic">⊕</div><div style={{fontSize:12}}>Select a packet to inspect</div><div className="muted sm">Full protocol decode + hex dump</div></div>:(
            <>
              <div className="ints">
                <button className={`intt${hexTab==="decode"?" on":""}`} onClick={()=>setHexTab("decode")}>⊕ Protocol Decode</button>
                <button className={`intt${hexTab==="hex"?" on":""}`} onClick={()=>setHexTab("hex")}>◫ Hex / ASCII Dump</button>
              </div>
              {hexTab==="decode"&&<div className="dc">{pktTree?.map((l,i)=><DecodeLayer key={i} layer={l}/>)}</div>}
              {hexTab==="hex"&&<div className="hxd">
                <div className="hxhd"><span>Offset</span><span>00 01 02 03 04 05 06 07 &nbsp; 08 09 0a 0b 0c 0d 0e 0f</span><span>ASCII</span></div>
                {pktHex.map((r,i)=><div key={i} className="hxr"><span className="hxo">{r.off}</span><span className="hxb">{r.hex}</span><span className="hxa">{r.asc}</span></div>)}
              </div>}
            </>
          )}
        </div>
        <div className="ina">
          <div className="sst">Packet Summary</div>
          {sel?[["Frame #",sel.id],["Timestamp",sel.tstr],["Source IP",sel.src],["Src Port",sel.sp],["Destination",sel.dst],["Dst Port",sel.dp||"—"],["Protocol",sel.proto],["Frame Len",`${sel.size} bytes`],["TTL",sel.ttl],["TCP Flags",sel.flags]].map(([k,v])=>(
            <div key={k} className="sr"><span className="sk">{k}</span><span className="sv">{v}</span></div>
          )):<div className="muted sm">No packet selected</div>}
          <div className="nb">
            <button className="nbb" onClick={()=>{const i=pkts.findIndex(p=>p.id===sel?.id);if(i<pkts.length-1){const p=pkts[i+1];setSel(p);setPktTree(buildTree(p));setPktHex(genHex(p.size))}}}>← Prev</button>
            <button className="nbb" onClick={()=>{const i=pkts.findIndex(p=>p.id===sel?.id);if(i>0){const p=pkts[i-1];setSel(p);setPktTree(buildTree(p));setPktHex(genHex(p.size))}}}>Next →</button>
          </div>
          <div className="sst" style={{marginTop:12}}>Actions</div>
          {["Follow TCP Stream","Mark Packet","Export Selected","Apply as Filter","Colorize Rule"].map(a=><button key={a} className="nbb" style={{width:"100%",marginBottom:3,textAlign:"left",padding:"4px 7px",fontSize:10}}>{a}</button>)}
        </div>
      </div>}

      {/* THREATS */}
      {tab==="threats"&&<div className="tw">
        <div className="tmn">
          <div className="svbar">
            {["critical","high","medium","low"].map(s=>{
              const sc=SC[s],ct=alerts.filter(a=>a.severity===s).length;
              return <div key={s} className="svc" style={{background:sc.bg,borderLeft:`3px solid ${sc.border}`}}>
                <div className="svl" style={{color:sc.text}}>{s.toUpperCase()}</div>
                <div className="svn" style={{color:sc.text,textShadow:`0 0 10px ${sc.text}`}}>{ct}</div>
              </div>;
            })}
          </div>
          <div className="als">
            {alerts.length===0?<div className="es"><div className="esic" style={{color:C.green}}>✓</div><div>No campus threats detected</div><div className="muted sm">Start capture to begin monitoring</div></div>
            :alerts.map(a=>{
              const sc=SC[a.severity];
              return <div key={a.id} className="ac" style={{background:sc.bg,borderColor:sc.border,borderLeftColor:sc.text}}>
                <div className="acl">
                  <div className="acsv" style={{color:sc.text,borderColor:sc.border}}>{a.severity.toUpperCase()}</div>
                  <div className="accv" style={{color:sc.text,textShadow:`0 0 8px ${sc.text}`}}>{a.cvss.toFixed(1)}</div>
                  <div style={{fontSize:8,color:sc.text,opacity:.7}}>CVSS</div>
                </div>
                <div className="acbd">
                  <div className="acnm">{a.name}</div>
                  <div className="acmt"><span>SIG: {a.sig}</span><span>{a.cat}</span>{a.cve&&<span className="cve">{a.cve}</span>}</div>
                  <div className="acrl">{a.rule}</div>
                  <div className="acfl">
                    <span className="mono sm">{a.src}</span><span className="fla">→</span><span className="mono sm">{a.dst}</span>
                    <span className="acpt">{a.proto}</span>
                  </div>
                </div>
                <div className="acr">
                  <div className="actm">{new Date(a.time).toLocaleTimeString()}</div>
                  <div className="acct" style={{color:sc.text}}>×{a.count}</div>
                </div>
              </div>;
            })}
          </div>
        </div>
        <div className="tsb">
          <div className="sst">MITRE ATT&CK</div>
          {[
            {t:"Credential Access",  n:alerts.filter(a=>a.cat?.includes("Cred")).length,  c:"#ff2d55"},
            {t:"Brute Force",        n:alerts.filter(a=>a.cat?.includes("Brute")).length, c:"#fb923c"},
            {t:"Data Exfiltration",  n:alerts.filter(a=>a.cat?.includes("Exfil")).length, c:"#ffd60a"},
            {t:"Man-in-the-Middle",  n:alerts.filter(a=>a.cat?.includes("Middle")).length,c:"#c084fc"},
            {t:"Command & Control",  n:alerts.filter(a=>a.cat?.includes("Command")).length,c:"#00e5ff"},
            {t:"Defense Evasion",    n:alerts.filter(a=>a.cat?.includes("Defense")).length,c:"#60a5fa"},
            {t:"Network Recon",      n:alerts.filter(a=>a.cat?.includes("Recon")).length,  c:"#22d3ee"},
          ].map(m=>(
            <div key={m.t} className="mtr">
              <div className="mtb"><div className="mtf" style={{width:`${Math.min(100,(m.n/Math.max(1,alerts.length))*250)}%`,background:m.c}}/></div>
              <span className="mtl">{m.t}</span><span className="mtn" style={{color:m.c}}>{m.n}</span>
            </div>
          ))}
          <div className="sst" style={{marginTop:14}}>Alert Timeline</div>
          <ResponsiveContainer width="100%" height={100}>
            <BarChart data={traffic.slice(-15).map(t=>({...t,al:Math.random()<.3?R(1,3):0}))}>
              <Bar dataKey="al" fill={C.red} radius={[2,2,0,0]}/><XAxis hide/><YAxis hide/>
              <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:9}}/>
            </BarChart>
          </ResponsiveContainer>
          <div className="sst" style={{marginTop:14}}>Campus Segments</div>
          {[{l:"Student LAN (10.10.x)",c:C.cyan},{l:"Faculty (172.16.x)",c:C.green},{l:"UnivWiFi (192.168.x)",c:C.yellow},{l:"Server Zone (10.10.0.x)",c:C.purple}].map(s=>(
            <div key={s.l} style={{display:"flex",alignItems:"center",gap:6,marginBottom:5}}>
              <span style={{width:8,height:8,borderRadius:"50%",background:s.c,flexShrink:0,boxShadow:`0 0 6px ${s.c}`}}/>
              <span style={{fontSize:10,color:"#5a8aaa"}}>{s.l}</span>
            </div>
          ))}
        </div>
      </div>}

      {/* CONNECTIONS */}
      {tab==="connections"&&<div className="cw">
        <div className="ctb">
          <input style={{background:"#071525",border:"1px solid #0d2540",color:C.text,padding:"5px 9px",borderRadius:4,fontFamily:"JetBrains Mono,monospace",fontSize:11,outline:"none",width:260}} placeholder="Filter by IP, port, or process…" value={cSearch} onChange={e=>setCSearch(e.target.value)}/>
          <div className="cst">
            <span><span style={{color:C.green}}>●</span> {CONNS.filter(c=>c.state==="ESTABLISHED").length} ESTABLISHED</span>
            <span><span style={{color:C.yellow}}>●</span> {CONNS.filter(c=>c.state==="TIME_WAIT").length} TIME_WAIT</span>
            <span><span style={{color:C.red}}>●</span> {CONNS.filter(c=>c.state==="SYN_SENT").length} SYN_SENT</span>
          </div>
        </div>
        <table className="ctt">
          <thead><tr><th>Proto</th><th>Local Address</th><th>Foreign Address</th><th>State</th><th>PID</th><th>Process</th><th>Bytes</th><th>Duration</th></tr></thead>
          <tbody>
            {CONNS.filter(c=>!cSearch||c.local.includes(cSearch)||c.remote.includes(cSearch)||c.proc.includes(cSearch)).map((c,i)=>{
              const sc={ESTABLISHED:C.green,TIME_WAIT:C.yellow,SYN_SENT:C.red}[c.state]||C.dim;
              return <tr key={i} className="cr">
                <td><span className="ptag" style={{background:c.proto==="TCP"?C.cyan+"22":C.purple+"22",border:`1px solid ${c.proto==="TCP"?C.cyan:C.purple}40`,color:c.proto==="TCP"?C.cyan:C.purple}}>{c.proto}</span></td>
                <td className="mono sm">{c.local}</td><td className="mono sm">{c.remote}</td>
                <td><span style={{color:sc,fontWeight:600,fontSize:10,fontFamily:"JetBrains Mono,monospace"}}>{c.state}</span></td>
                <td className="mono muted sm">{c.pid}</td>
                <td className="mono sm" style={{color:c.state==="SYN_SENT"?C.red:C.green}}>{c.proc}</td>
                <td className="mono dim sm">{c.bytes}</td><td className="mono muted sm">{c.dur}</td>
              </tr>;
            })}
          </tbody>
        </table>
      </div>}

      {/* STATISTICS */}
      {tab==="statistics"&&<div className="sg">
        <div className="sp">
          <div className="spt">Campus Traffic Volume Over Time</div>
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={traffic}>
              <defs><linearGradient id="tg2" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.cyan} stopOpacity={.4}/><stop offset="100%" stopColor={C.cyan} stopOpacity={0}/></linearGradient></defs>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border}/><XAxis dataKey="t" hide/><YAxis tick={{fontSize:9,fill:C.dim}}/>
              <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:9,color:C.text}}/>
              <Area type="monotone" dataKey="pkts" name="Packets/s" stroke={C.cyan} fill="url(#tg2)" strokeWidth={2} dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="sp">
          <div className="spt">Protocol Distribution</div>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={44} outerRadius={68} dataKey="value" nameKey="name" fontSize={9}>
                {pieData.map((e)=><Cell key={e.name} fill={PC[e.name]||"#888"}/>)}
              </Pie>
              <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:9}}/>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="sp" style={{gridColumn:"1/-1"}}>
          <div className="spt">Top Talkers — Campus Hosts</div>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={Object.entries(pkts.slice(0,200).reduce((acc,p)=>{acc[p.src]=(acc[p.src]||0)+1;return acc},{})).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([ip,count])=>({ip,count}))}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border}/><XAxis dataKey="ip" tick={{fontSize:8.5,fill:C.dim}}/><YAxis tick={{fontSize:9,fill:C.dim}}/>
              <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:9,color:C.text}}/>
              <Bar dataKey="count" name="Packets" fill={C.cyan} radius={[3,3,0,0]}/>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="sp">
          <div className="spt">Packets per Protocol</div>
          <ResponsiveContainer width="100%" height={150}>
            <BarChart data={Object.entries(protoC).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([p,c])=>({p,c}))} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke={C.border}/><XAxis type="number" tick={{fontSize:9,fill:C.dim}}/><YAxis dataKey="p" type="category" tick={{fontSize:9,fill:C.dim}} width={65}/>
              <Tooltip contentStyle={{background:C.bg2,border:`1px solid ${C.border}`,fontSize:9}}/><Bar dataKey="c" name="Packets" radius={[0,3,3,0]}>{Object.entries(protoC).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([p])=><Cell key={p} fill={PC[p]||"#888"}/>)}</Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="sp">
          <div className="spt">Top Destination Hosts</div>
          {Object.entries(pkts.slice(0,200).reduce((acc,p)=>{acc[p.dst]=(acc[p.dst]||0)+1;return acc},{})).sort((a,b)=>b[1]-a[1]).slice(0,7).map(([ip,c])=>(
            <div key={ip} className="tdr"><span className="mono sm" style={{minWidth:126,color:C.text}}>{ip}</span><div className="tdb"><div className="tdf" style={{width:`${(c/Math.max(1,pkts.length))*100*8}%`}}/></div><span className="mono muted sm">{c}</span></div>
          ))}
        </div>
      </div>}

      {/* DNS */}
      {tab==="dns"&&<div className="dnw">
        <div className="dns">
          {[{l:"Total Queries",v:DNS_LOG.length,c:C.cyan},{l:"Resolved",v:DNS_LOG.filter(d=>d.status==="NOERROR").length,c:C.green},{l:"Suspicious",v:DNS_LOG.filter(d=>d.status==="SUSPICIOUS").length,c:C.red},{l:"Unique Domains",v:new Set(DNS_LOG.map(d=>d.query)).size,c:C.purple}].map(s=>(
            <div key={s.l} className="dsc"><span className="dsv" style={{color:s.c}}>{s.v}</span><div className="dsl">{s.l}</div></div>
          ))}
        </div>
        <table className="dnt">
          <thead><tr><th>Time</th><th>Client</th><th>Query Name</th><th>Type</th><th>Response</th><th>TTL</th><th>Status</th></tr></thead>
          <tbody>
            {DNS_LOG.map((d,i)=>(
              <tr key={i} className="dr">
                <td className="mono muted sm">{d.time}</td><td className="mono sm">{d.client}</td>
                <td className="mono sm" style={{color:d.status==="SUSPICIOUS"?C.red:C.text,maxWidth:300,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.query}</td>
                <td><span className="ttg">{d.type}</span></td>
                <td className="mono sm" style={{color:C.green,maxWidth:180,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.resp}</td>
                <td className="mono muted sm">{d.ttl}s</td>
                <td><span style={{color:d.status==="NOERROR"?C.green:d.status==="SUSPICIOUS"?C.red:C.yellow,fontWeight:700,fontSize:10}}>{d.status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>}

      {/* HTTP */}
      {tab==="http"&&<div className="htw">
        <div className="hts">
          {[{l:"GET",v:HTTP_LOG.filter(h=>h.method==="GET").length,c:C.cyan},{l:"POST",v:HTTP_LOG.filter(h=>h.method==="POST").length,c:C.green},{l:"200 OK",v:HTTP_LOG.filter(h=>h.status===200).length,c:C.green},{l:"4xx Errors",v:HTTP_LOG.filter(h=>h.status>=400).length,c:C.red},{l:"Suspicious",v:HTTP_LOG.filter(h=>h.note.includes("⚠")||h.note.includes("❌")).length,c:C.yellow}].map(s=>(
            <div key={s.l} className="hsc" style={{borderLeftColor:s.c}}><span className="hsv" style={{color:s.c}}>{s.v}</span><div className="hsl">{s.l}</div></div>
          ))}
        </div>
        <table className="htt">
          <thead><tr><th>Time</th><th>Method</th><th>URL</th><th>Status</th><th>Content-Type</th><th>Size</th><th>Duration</th><th>Client</th><th>Note</th></tr></thead>
          <tbody>
            {HTTP_LOG.map((h,i)=>(
              <tr key={i} className="hr">
                <td className="mono muted sm">{h.time}</td>
                <td><span className={`mt m${h.method.toLowerCase()}`}>{h.method}</span></td>
                <td className="mono sm" style={{color:h.url.startsWith("http:")?"#fb923c":C.text,maxWidth:240,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{h.url}</td>
                <td className="mono" style={{color:h.status===200?C.green:h.status>=400?C.red:C.yellow,fontWeight:700,fontSize:11.5}}>{h.status}</td>
                <td className="mono muted sm">{h.type}</td><td className="mono muted sm">{h.size}</td>
                <td className="mono muted sm">{h.dur}</td><td className="mono sm">{h.client}</td>
                <td className="sm" style={{color:h.note.includes("⚠")?C.yellow:h.note.includes("❌")?C.red:C.dim}}>{h.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>}

      {/* GEO MAP */}
      {tab==="geomap"&&<div className="gw">
        <div className="gm">
          <div className="gttl">◬ ATTACK ORIGIN MAP — External Threats Targeting University Network</div>
          <div className="ma">
            <svg viewBox="0 0 920 480" className="msv" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <filter id="glow"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                <radialGradient id="mb" cx="50%" cy="50%" r="50%"><stop offset="0%" stopColor="#071525"/><stop offset="100%" stopColor="#020912"/></radialGradient>
              </defs>
              <rect width="920" height="480" fill="url(#mb)"/>
              {[...Array(10)].map((_,i)=><line key={`h${i}`} x1="0" y1={i*48} x2="920" y2={i*48} stroke="#0d2540" strokeWidth="0.5"/>)}
              {[...Array(19)].map((_,i)=><line key={`v${i}`} x1={i*50} y1="0" x2={i*50} y2="480" stroke="#0d2540" strokeWidth="0.5"/>)}
              <path d="M55 195 Q110 168 165 178 Q205 172 248 183 Q265 210 255 248 Q235 278 200 288 Q165 298 135 290 Q100 275 72 248 Q48 222 55 195Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
              <path d="M268 155 Q328 132 408 142 Q468 148 530 160 Q560 172 568 195 Q562 220 535 228 Q492 232 450 226 Q400 218 358 208 Q318 198 290 188 Q268 178 268 155Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
              <path d="M582 138 Q655 125 748 136 Q808 148 848 172 Q868 198 856 228 Q834 258 792 268 Q740 272 688 260 Q636 244 608 218 Q578 192 574 168 Q572 150 582 138Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
              <path d="M294 288 Q328 275 368 292 Q388 318 376 372 Q354 412 322 420 Q298 414 282 388 Q265 358 272 322 Q278 300 294 288Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
              <path d="M490 255 Q518 238 548 245 Q562 262 550 292 Q532 318 506 326 Q484 320 474 298 Q465 275 490 255Z" fill="#0b1e34" stroke="#143050" strokeWidth="1"/>
              {GEO.map(s=>(
                <g key={s.country}>
                  <line x1={s.x} y1={s.y} x2={460} y2={240} stroke={s.color} strokeWidth="0.9" strokeDasharray="5,4" opacity="0.5">
                    <animate attributeName="stroke-dashoffset" from="0" to="-27" dur="2s" repeatCount="indefinite"/>
                  </line>
                  <circle cx={s.x} cy={s.y} r={Math.sqrt(s.count)/2+4} fill={s.color} opacity="0.12" filter="url(#glow)"/>
                  <circle cx={s.x} cy={s.y} r="4" fill={s.color} filter="url(#glow)">
                    <animate attributeName="r" values="3;7;3" dur="2s" repeatCount="indefinite"/>
                    <animate attributeName="opacity" values="1;0.3;1" dur="2s" repeatCount="indefinite"/>
                  </circle>
                  <text x={s.x+9} y={s.y+4} fill={s.color} fontSize="9" fontFamily="JetBrains Mono,monospace" opacity="0.8">{s.code}</text>
                </g>
              ))}
              <circle cx={460} cy={240} r="20" fill="#00e5ff" opacity="0.07" filter="url(#glow)"/>
              <circle cx={460} cy={240} r="5" fill="#00e5ff" filter="url(#glow)">
                <animate attributeName="r" values="4;9;4" dur="2s" repeatCount="indefinite"/>
                <animate attributeName="opacity" values="1;0.3;1" dur="2s" repeatCount="indefinite"/>
              </circle>
              <text x={470} y={260} fill="#00e5ff" fontSize="9" fontFamily="JetBrains Mono,monospace" opacity="0.9">UNIVERSITY.EDU</text>
            </svg>
          </div>
        </div>
        <div className="gsb">
          <div className="sst">Top Attack Sources</div>
          {[...GEO].sort((a,b)=>b.count-a.count).map(s=>(
            <div key={s.country} className="gr">
              <span className="gfl">{getFlag(s.code)}</span><span className="gcn">{s.country}</span>
              <div className="gbg"><div className="gfil" style={{width:`${(s.count/GEO[0].count)*100}%`,background:s.color}}/></div>
              <span className="gct" style={{color:s.color}}>{s.count}</span>
            </div>
          ))}
          <div className="sst" style={{marginTop:14}}>Attack Categories</div>
          {[{l:"Cred Stuffing",c:C.red,p:35},{l:"Recon / Scanning",c:C.yellow,p:28},{l:"Data Scraping",c:C.purple,p:20},{l:"C2 Tunneling",c:C.orange,p:11},{l:"Other",c:C.dim,p:6}].map(x=>(
            <div key={x.l} className="mtr">
              <span className="mtl" style={{minWidth:108}}>{x.l}</span>
              <div className="mtb"><div className="mtf" style={{width:`${x.p}%`,background:x.c}}/></div>
              <span className="mtn" style={{color:x.c}}>{x.p}%</span>
            </div>
          ))}
          <div className="sst" style={{marginTop:14}}>Campus Perimeter</div>
          <div style={{fontSize:10,color:"#5a8aaa",lineHeight:1.7}}>
            <div>🔵 Firewall: <span style={{color:C.green}}>Active</span></div>
            <div>🔵 IDS/IPS: <span style={{color:C.green}}>Online</span></div>
            <div>🔴 WAF: <span style={{color:C.red}}>Alerts Triggered</span></div>
            <div>🔵 VPN Gateway: <span style={{color:C.green}}>Up</span></div>
          </div>
        </div>
      </div>}

    </div>

    {/* STATUS BAR */}
    <div className="sb">
      <span>◈ Campus Core — eth0</span><div className="sbsep"/>
      <span>Pkts: <b style={{color:C.cyan}}>{stats.total.toLocaleString()}</b></span><div className="sbsep"/>
      <span>Shown: <b style={{color:C.text}}>{filtered.length}</b></span><div className="sbsep"/>
      <span>Data: <b style={{color:C.text}}>{fmtBytes(stats.bytes)}</b></span><div className="sbsep"/>
      <span>Filter: <span style={{color:filter?C.yellow:C.muted}}>{filter||"none"}</span></span><div className="sbsep"/>
      <span>Segment: University LAN</span>
      <span className="sbr" style={{color:cap?C.green:C.muted}}>
        {cap&&!paused?`● CAPTURING  ${Math.round(stats.pps)} pkt/s`:cap&&paused?"⏸ PAUSED":"● READY"}
      </span>
    </div>
  </div>;
}
