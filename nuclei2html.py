import argparse
import os
import re
from datetime import datetime
from collections import defaultdict


# ================= MODELS =================

class Finding:
    def __init__(self, template, severity, url):
        self.template = template
        self.severity = severity.upper()
        self.url = url


class Host:
    def __init__(self, ip):
        self.ip = ip
        self.findings = []


# ================= PARSER =================

def parse_nuclei_file(file):

    pattern = re.compile(
        r"\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(http[s]?://[^\s]+)"
    )

    hosts = {}

    with open(file, encoding="utf8", errors="ignore") as f:
        for line in f:

            line = line.strip()
            if not line:
                continue

            m = pattern.match(line)
            if not m:
                continue

            template = m.group(1)
            severity = m.group(3)
            url = m.group(4)

            ip_match = re.search(r"http[s]?://([^:/]+)", url)
            if not ip_match:
                continue

            ip = ip_match.group(1)

            if ip not in hosts:
                hosts[ip] = Host(ip)

            hosts[ip].findings.append(Finding(template, severity, url))

    return hosts


# ================= DIRECTORY LOADER =================

def load_all_results(root):

    all_hosts = {}

    for root_dir, dirs, files in os.walk(root):

        for file in files:

            if file.endswith(".txt"):

                path = os.path.join(root_dir, file)

                parsed = parse_nuclei_file(path)

                for ip, host in parsed.items():

                    if ip not in all_hosts:
                        all_hosts[ip] = host
                    else:
                        all_hosts[ip].findings.extend(host.findings)

    return list(all_hosts.values())


# ================= REPORT UI =================

class Report:

    def generate(self, hosts):

        html = []

        html.append("""
<html>
<head>
<title>Nuclei Pentest Report</title>
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

</style>
</head>
<body>
<div class="header">
<h1>Nuclei Automated Vulnerability Report</h1>
""")

        html.append(f"<div>Generated: {datetime.utcnow()}</div>")
        html.append("</div><div class='container'>")

        for h in hosts:

            html.append(f"""
<div class='host'>
<h2>Host: {h.ip}</h2>

<table>
<tr>
<th style='width:260px'>Template / CVE</th>
<th style='width:120px'>Severity</th>
<th>URLs</th>
</tr>
""")

            # dedupe findings
            uniq = defaultdict(list)

            for f in h.findings:
                key = (f.template, f.severity)
                uniq[key].append(f.url)

            for (template, severity), urls in uniq.items():

                url_html = "<ul>"

                for u in urls[:12]:
                    url_html += f"<li>{u}</li>"

                if len(urls) > 12:
                    url_html += f"<li>... {len(urls)-12} more</li>"

                url_html += "</ul>"

                html.append(f"""
<tr>
<td>{template}</td>
<td class='{severity}'>{severity}</td>
<td>{url_html}</td>
</tr>
""")

            html.append("</table></div>")

        html.append("</div></body></html>")

        return "\n".join(html)


# ================= MAIN =================

def main():

    ap = argparse.ArgumentParser()
    ap.add_argument("-i", required=True, help="root directory containing nuclei txt outputs")
    ap.add_argument("-o", required=True)

    args = ap.parse_args()

    hosts = load_all_results(args.i)

    html = Report().generate(hosts)

    with open(args.o, "w") as f:
        f.write(html)

    print("Report generated:", args.o)


if __name__ == "__main__":
    main()
