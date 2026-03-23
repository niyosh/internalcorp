import argparse
import re
import math
import os
from enum import Enum
from typing import List, Dict
from datetime import datetime


# ================= MODELS =================

class Severity(Enum):
    INFO="Info"
    LOW="Low"
    MEDIUM="Medium"
    HIGH="High"
    CRITICAL="Critical"


class Finding:
    def __init__(self,title,severity,service=None):
        self.title=title
        self.severity=severity
        self.service=service


class Service:
    def __init__(self,port,proto,name,version=""):
        self.port=port
        self.proto=proto
        self.name=name.lower()
        self.version=version.lower()
        self.scripts={}
        self.findings:List[Finding]=[]


class Host:
    def __init__(self,ip):
        self.ip=ip
        self.services:List[Service]=[]
        self.risk=0


# ================= PARSER =================

class Parser:

    def parse(self,file):

        hosts=[]
        ch=None
        cs=None

        with open(file,encoding="utf8",errors="ignore") as f:
            lines=f.readlines()

        for line in lines:

            line=line.strip()

            m=re.match(r"Nmap scan report for (.+)",line)
            if m:
                if ch:
                    hosts.append(ch)
                ch=Host(m.group(1))
                continue

            m=re.match(r"(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)",line)
            if m and ch:
                cs=Service(int(m.group(1)),m.group(2),m.group(3),m.group(4))
                ch.services.append(cs)
                continue

            if cs and (line.startswith("|") or line.startswith("|_")):
                line=line.lstrip("|_").strip()
                if ":" in line:
                    k,v=line.split(":",1)
                    cs.scripts[k.strip().lower()]=v.strip().lower()

        if ch:
            hosts.append(ch)

        return hosts


# ================= INTELLIGENCE =================

class Intelligence:

    def analyze(self,s:Service):

        banner=f"{s.name} {s.version}"
        sc=s.scripts

        # RCE services
        rce=["vsftpd 2.3.4","unrealircd","distccd","bindshell","java-rmi","drb","ajp","tomcat"]
        for sig in rce:
            if sig in banner:
                s.findings.append(Finding("Possible Remote Code Execution Service",Severity.CRITICAL,s))

        # legacy remote
        legacy={"telnet":"Cleartext Remote Login","rlogin":"Legacy Remote Login","rexec":"Remote Command Service","vnc":"Remote Desktop Exposure","x11":"X11 Exposure"}
        if s.name in legacy:
            s.findings.append(Finding(legacy[s.name],Severity.HIGH,s))

        # db exposure
        if s.name in ["mysql","postgresql","mssql","oracle"]:
            s.findings.append(Finding("Database Service Exposed",Severity.HIGH,s))

        # infra exposure
        if s.name in ["rpcbind","nfs","mountd","status","nlockmgr"]:
            s.findings.append(Finding("RPC/NFS Exposure",Severity.MEDIUM,s))

        # web outdated
        if "apache" in banner and "2.2" in banner:
            s.findings.append(Finding("Outdated Apache",Severity.HIGH,s))

        # ssh outdated
        if "openssh" in banner and ("4." in banner or "5." in banner):
            s.findings.append(Finding("Outdated OpenSSH",Severity.HIGH,s))

        # samba outdated
        if "samba" in banner:
            s.findings.append(Finding("Outdated Samba",Severity.HIGH,s))

        # dns disclosure
        if "bind" in banner:
            s.findings.append(Finding("DNS Version Disclosure",Severity.MEDIUM,s))

        # NSE logic
        if "ftp-anon" in sc:
            s.findings.append(Finding("Anonymous FTP Enabled",Severity.HIGH,s))

        if "http-title" in sc and ("test" in sc["http-title"] or "metasploitable" in sc["http-title"]):
            s.findings.append(Finding("Default/Test Web App",Severity.MEDIUM,s))

        if "http-server-header" in sc and "apache/2.2" in sc["http-server-header"]:
            s.findings.append(Finding("Outdated Web Server Header",Severity.HIGH,s))

        if "mysql-info" in sc:
            s.findings.append(Finding("Database Info Disclosure",Severity.MEDIUM,s))

        if "rpcinfo" in sc:
            s.findings.append(Finding("Multiple RPC Services",Severity.MEDIUM,s))

        if "smb-security-mode" in sc and "disabled" in sc["smb-security-mode"]:
            s.findings.append(Finding("SMB Signing Disabled",Severity.HIGH,s))

        if "vnc-info" in sc:
            s.findings.append(Finding("Weak VNC Authentication",Severity.HIGH,s))

        if "ssl-cert" in sc:
            s.findings.append(Finding("Expired/Self-Signed Certificate",Severity.MEDIUM,s))

        if "sslv2" in sc:
            s.findings.append(Finding("SSLv2 Supported",Severity.CRITICAL,s))

        if any(w in str(sc) for w in ["rc4","des","export","null"]):
            s.findings.append(Finding("Weak TLS Cipher",Severity.HIGH,s))

        if "ssh-hostkey" in sc and "1024" in sc["ssh-hostkey"]:
            s.findings.append(Finding("Weak SSH Key",Severity.MEDIUM,s))


# ================= RISK =================

class Risk:

    weights={Severity.INFO:0,Severity.LOW:1,Severity.MEDIUM:3,Severity.HIGH:7,Severity.CRITICAL:10}

    def score(self,h):

        t=0
        for s in h.services:
            for f in s.findings:
                t+=self.weights[f.severity]

        if h.services:
            h.risk=t/math.log(len(h.services)+1)


# ================= REPORT =================

class Report:

    def generate(self, hosts):

        html = []

        html.append("""
<html>
<head>
<title>Pentest Report</title>
<style>

body{
    background:#0f172a;
    color:#e5e7eb;
    font-family:Segoe UI,Arial;
    margin:0;
}

.header{
    background:#020617;
    padding:25px;
    border-bottom:2px solid #1e293b;
}

h1{
    margin:0;
    color:#38bdf8;
}

.container{
    padding:25px;
}

.host{
    background:#020617;
    margin-bottom:30px;
    padding:20px;
    border-radius:10px;
    box-shadow:0 0 20px rgba(0,0,0,0.6);
}

.risk{
    font-size:18px;
    font-weight:bold;
    color:#f87171;
}

table{
    width:100%;
    border-collapse:collapse;
    margin-top:15px;
}

th{
    background:#020617;
    color:#38bdf8;
    text-align:left;
    padding:10px;
    border-bottom:1px solid #334155;
}

td{
    padding:10px;
    border-bottom:1px solid #1e293b;
    vertical-align:top;
}

ul{
    margin:0;
    padding-left:18px;
}

.CRITICAL{color:#ef4444;font-weight:bold;}
.HIGH{color:#f97316;font-weight:bold;}
.MEDIUM{color:#eab308;font-weight:bold;}
.LOW{color:#22c55e;font-weight:bold;}
.INFO{color:#94a3b8;}

.port{
    font-weight:bold;
    color:#cbd5f5;
}

.service{
    color:#a5f3fc;
}

.version{
    color:#cbd5f5;
    font-size:13px;
}

</style>
</head>
<body>
<div class="header">
<h1>Automated Pentest Intelligence Report</h1>
""")

        html.append(f"<div>Generated: {datetime.utcnow()}</div>")
        html.append("</div><div class='container'>")

        for h in hosts:

            html.append(f"""
<div class='host'>
<h2>Host: {h.ip}</h2>
<div class='risk'>Risk Score: {round(h.risk,2)}</div>

<table>
<tr>
<th style='width:80px'>Port</th>
<th style='width:160px'>Service</th>
<th style='width:260px'>Version</th>
<th>Findings</th>
</tr>
""")

            for s in h.services:

                findings = "<ul>"

                for f in s.findings:
                    findings += f"<li class='{f.severity.name}'>{f.severity.name}: {f.title}</li>"

                findings += "</ul>"

                version = s.version if s.version else "-"

                html.append(f"""
<tr>
<td class='port'>{s.port}</td>
<td class='service'>{s.name}</td>
<td class='version'>{version}</td>
<td>{findings}</td>
</tr>
""")

            html.append("</table></div>")

        html.append("</div></body></html>")

        return "\n".join(html)

# ================= MAIN =================

def main():

    ap=argparse.ArgumentParser()
    ap.add_argument("-i",required=True,help="root results directory")
    ap.add_argument("-o",required=True)
    args=ap.parse_args()

    parser=Parser()
    hosts_map:Dict[str,Host]={}

    # recursive scan
    for root,dirs,files in os.walk(args.i):
        for file in files:
            if file.endswith(".nmap"):
                path=os.path.join(root,file)
                parsed=parser.parse(path)

                for ph in parsed:

                    if ph.ip not in hosts_map:
                        hosts_map[ph.ip]=ph
                    else:
                        hosts_map[ph.ip].services.extend(ph.services)

    hosts=list(hosts_map.values())

    intel=Intelligence()
    risk=Risk()

    for h in hosts:
        for s in h.services:
            intel.analyze(s)
        risk.score(h)

    html=Report().generate(hosts)

    open(args.o,"w").write(html)

    print("Report generated:",args.o)


if __name__=="__main__":
    main()
