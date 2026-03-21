#!/usr/bin/env python3

import argparse
import subprocess
import os
import sys
import xml.etree.ElementTree as ET
import concurrent.futures
import threading
import hashlib
import json
import shutil
import time

from colorama import Fore, Style, init
init(autoreset=True)

REQUIRED_TOOLS = [
    "nmap",
    "httpx",
    "katana",
    "dirsearch",
    "nuclei",
    "gowitness"
]

WEB_PORT_HINTS = {80,443,8080,8000,8443,3000,5000,7001,9000}

STATIC_EXT = (
    ".css",".js",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",
    ".webp",".mp4",".pdf",".zip",".woff2",".ttf",".eot"
)

PARAM_REGEX = (
    "?","&","="
)

LOCK = threading.Lock()

# -------------------------------------------------------------

def log(msg,color=Fore.CYAN):
    with LOCK:
        print(color + msg)

# -------------------------------------------------------------

def check_dependencies():
    missing=[]
    for t in REQUIRED_TOOLS:
        if shutil.which(t) is None:
            missing.append(t)
    if missing:
        log(f"[!] Missing tools: {','.join(missing)}",Fore.RED)
        sys.exit(1)

# -------------------------------------------------------------

def run_cmd(cmd,timeout=None):
    try:
        subprocess.run(cmd,shell=True,timeout=timeout,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        log(f"[!] Timeout: {cmd}",Fore.RED)

# -------------------------------------------------------------

def nmap_scan(target, tdir, resume):

    tcp_prefix = f"{tdir}/nmap_tcp"
    udp_prefix = f"{tdir}/nmap_udp"

    # ---------- TCP ----------
    if not (resume and os.path.exists(tcp_prefix + ".xml")):

        log(f"[+] Nmap TCP {target}")

        tcp_cmd = (
            f"nmap -Pn -p- -sS -sV -sC --open "
            f"-T4 --min-rate 500 --max-retries 1 "
            f"--stats-every 30s "
            f"-oA {tcp_prefix} {target}"
        )

        run_cmd(tcp_cmd, timeout=3600)

    else:
        log(f"[RESUME] skip TCP nmap {target}", Fore.YELLOW)

    # ---------- UDP ----------
    if not (resume and os.path.exists(udp_prefix + ".xml")):

        log(f"[+] Nmap UDP {target}")

        udp_cmd = (
            f"nmap -Pn -sU --top-ports 200 "
            f"-T4 --max-retries 1 "
            f"--stats-every 30s "
            f"-oA {udp_prefix} {target}"
        )

        run_cmd(udp_cmd, timeout=3600)

    else:
        log(f"[RESUME] skip UDP nmap {target}", Fore.YELLOW)

# -------------------------------------------------------------

def parse_web_ports(xml_file):
    ports=set()

    if not os.path.exists(xml_file):
        return []

    tree=ET.parse(xml_file)
    root=tree.getroot()

    for port in root.findall(".//port"):
        state=port.find("state")
        service=port.find("service")

        if state is None:
            continue

        if state.attrib.get("state")!="open":
            continue

        p=int(port.attrib.get("portid"))

        svc=""
        if service is not None:
            svc=service.attrib.get("name","")

        if p in WEB_PORT_HINTS or "http" in svc:
            ports.add(p)

    return sorted(list(ports))

# -------------------------------------------------------------

def httpx_probe(target,ports,outfile):
    if not ports:
        return

    urls=[]
    for p in ports:
        proto="https" if p in (443,8443) else "http"
        urls.append(f"{proto}://{target}:{p}")

    tmp=f"{outfile}.input"
    with open(tmp,"w") as f:
        for u in urls:
            f.write(u+"\n")

    cmd=f"httpx -silent -status-code -title -tech-detect -l {tmp} -o {outfile}"
    run_cmd(cmd,timeout=1200)

# -------------------------------------------------------------

def web_enum(httpx_file,tdir):

    katana_out=f"{tdir}/katana.txt"
    dir_out=f"{tdir}/dirsearch.txt"

    cmd1=f"katana -list {httpx_file} -jc -kf -o {katana_out}"
    cmd2=f"dirsearch --url-list {httpx_file} -e php,asp,aspx,jsp,html,json -t 40 -o {dir_out}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        ex.submit(run_cmd,cmd1,1800)
        ex.submit(run_cmd,cmd2,1800)

    return katana_out,dir_out

# -------------------------------------------------------------

def merge_filter_stream(files,outfile):

    seen=set()

    with open(outfile,"w") as out:

        for f in files:
            if not os.path.exists(f):
                continue

            with open(f) as fh:
                for line in fh:
                    u=line.strip()

                    if not u:
                        continue

                    h=hashlib.sha1(u.encode()).hexdigest()

                    if h in seen:
                        continue

                    seen.add(h)

                    low=u.lower()

                    if low.endswith(STATIC_EXT):
                        continue

                    out.write(u+"\n")

# -------------------------------------------------------------

def extract_params(infile,outfile):

    with open(infile) as fi, open(outfile,"w") as fo:
        for line in fi:
            u=line.strip()

            if "?" in u and "=" in u:
                fo.write(u+"\n")

# -------------------------------------------------------------

def nuclei_scan(param_file,tdir):

    if not os.path.exists(param_file):
        return

    out=f"{tdir}/nuclei.json"

    cmd=f"nuclei -l {param_file} -severity low,medium,high,critical -rate-limit 150 -c 50 -json -o {out}"
    run_cmd(cmd,timeout=3600)

# -------------------------------------------------------------

def screenshot(httpx_file,tdir):
    cmd=f"gowitness file -f {httpx_file} -P {tdir}/shots"
    run_cmd(cmd,timeout=1800)

# -------------------------------------------------------------

def process_target(target,resume):

    tdir=f"results/{target.replace(':','_')}"
    os.makedirs(tdir,exist_ok=True)

    xml=f"{tdir}/nmap_tcp.xml"

    nmap_scan(target,tdir,resume)

    ports=parse_web_ports(xml)
    log(f"[WEB PORTS] {target} -> {ports}",Fore.BLUE)

    httpx_file=f"{tdir}/httpx.txt"
    httpx_probe(target,ports,httpx_file)

    screenshot(httpx_file,tdir)

    katana,dirsearch=web_enum(httpx_file,tdir)

    merged=f"{tdir}/filtered_urls.txt"
    merge_filter_stream([katana,dirsearch],merged)

    params=f"{tdir}/params.txt"
    extract_params(merged,params)

    nuclei_scan(params,tdir)

# -------------------------------------------------------------

def main():

    parser=argparse.ArgumentParser()
    parser.add_argument("targets",nargs="*")
    parser.add_argument("-l","--list")
    parser.add_argument("--resume",action="store_true")
    parser.add_argument("-t","--threads",type=int,default=5)

    args=parser.parse_args()

    check_dependencies()

    targets=[]

    if args.list:
        with open(args.list) as f:
            targets=[x.strip() for x in f if x.strip()]

    targets.extend(args.targets)

    if not targets:
        log("No targets",Fore.RED)
        sys.exit()

    os.makedirs("results",exist_ok=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        ex.map(lambda t: process_target(t,args.resume),targets)

    log("[DONE]",Fore.GREEN)

# -------------------------------------------------------------

if __name__=="__main__":
    main()
