#!/usr/bin/env python3

import argparse
import subprocess
import os
import sys
import xml.etree.ElementTree as ET
import concurrent.futures
import threading
import hashlib
import shutil

from colorama import Fore, init
init(autoreset=True)

REQUIRED_TOOLS = ["nmap","katana","dirsearch","nuclei","gowitness"]

WEB_PORT_HINTS = {80,443,8080,8000,8443,3000,5000,7001,9000}

STATIC_EXT = (
    ".css",".js",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",
    ".webp",".mp4",".pdf",".zip",".woff2",".ttf",".eot"
)

LOCK = threading.Lock()

# -------------------------------------------------

def log(msg,color=Fore.CYAN):
    with LOCK:
        print(color + msg)

# -------------------------------------------------

def check_dependencies():
    missing=[]
    for t in REQUIRED_TOOLS:
        if shutil.which(t) is None:
            missing.append(t)
    if missing:
        log(f"[!] Missing tools: {','.join(missing)}",Fore.RED)
        sys.exit(1)

# -------------------------------------------------

def run_cmd(cmd,timeout=None):
    try:
        subprocess.run(cmd,shell=True,timeout=timeout,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        log(f"[!] Timeout: {cmd}",Fore.RED)

# -------------------------------------------------

def nmap_scan(target, tdir, resume):

    tcp_prefix=f"{tdir}/nmap_tcp"
    udp_prefix=f"{tdir}/nmap_udp"

    if not (resume and os.path.exists(tcp_prefix+".xml")):
        log(f"[+] TCP scan {target}")
        cmd=f"nmap -Pn -p- -sS -sV -sC --open -T4 --min-rate 500 --max-retries 1 -oA {tcp_prefix} {target}"
        run_cmd(cmd,3600)

    if not (resume and os.path.exists(udp_prefix+".xml")):
        log(f"[+] UDP scan {target}")
        cmd=f"nmap -Pn -sU --top-ports 200 -T4 --max-retries 1 -oA {udp_prefix} {target}"
        run_cmd(cmd,3600)

# -------------------------------------------------

def parse_web_ports(xml_file):

    ports=set()

    if not os.path.exists(xml_file):
        return []

    tree=ET.parse(xml_file)
    root=tree.getroot()

    for port in root.findall(".//port"):
        state=port.find("state")
        svc=port.find("service")

        if state is None:
            continue
        if state.attrib.get("state")!="open":
            continue

        p=int(port.attrib.get("portid"))

        name=""
        if svc is not None:
            name=svc.attrib.get("name","")

        if p in WEB_PORT_HINTS or "http" in name:
            ports.add(p)

    return sorted(list(ports))

# -------------------------------------------------

def build_base_urls(target,ports,outfile):

    with open(outfile,"w") as f:
        for p in ports:
            proto="https" if p in (443,8443) else "http"
            f.write(f"{proto}://{target}:{p}\n")

# -------------------------------------------------

def web_enum(url_file,tdir):

    katana_out=f"{tdir}/katana.txt"
    dir_out=f"{tdir}/dirsearch.txt"

    cmd1=f"katana -list {url_file} -jc -kf -o {katana_out}"
    cmd2=f"dirsearch --url-list {url_file} -e php,asp,aspx,jsp,html,json -t 40 -o {dir_out}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        ex.submit(run_cmd,cmd1,1800)
        ex.submit(run_cmd,cmd2,1800)

    return katana_out,dir_out

# -------------------------------------------------

def merge_filter(files,outfile):

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

                    if u.lower().endswith(STATIC_EXT):
                        continue

                    out.write(u+"\n")

# -------------------------------------------------

def extract_params(infile,outfile):

    with open(infile) as fi, open(outfile,"w") as fo:
        for line in fi:
            u=line.strip()
            if "?" in u and "=" in u:
                fo.write(u+"\n")

# -------------------------------------------------

def nuclei_scan(param_file,tdir):

    if not os.path.exists(param_file):
        return

    out=f"{tdir}/nuclei.json"
    cmd=f"nuclei -l {param_file} -severity low,medium,high,critical -rate-limit 150 -c 50 -json -o {out}"
    run_cmd(cmd,3600)

# -------------------------------------------------

def screenshot(url_file,tdir):
    cmd=f"gowitness file -f {url_file} -P {tdir}/shots"
    run_cmd(cmd,1800)

# -------------------------------------------------

def process_target(target,resume):

    tdir=f"results/{target.replace(':','_')}"
    os.makedirs(tdir,exist_ok=True)

    nmap_scan(target,tdir,resume)

    xml=f"{tdir}/nmap_tcp.xml"
    ports=parse_web_ports(xml)

    log(f"[WEB] {target} -> {ports}",Fore.BLUE)

    url_file=f"{tdir}/base_urls.txt"
    build_base_urls(target,ports,url_file)

    screenshot(url_file,tdir)

    katana,dirsearch=web_enum(url_file,tdir)

    filtered=f"{tdir}/filtered_urls.txt"
    merge_filter([katana,dirsearch],filtered)

    params=f"{tdir}/params.txt"
    extract_params(filtered,params)

    nuclei_scan(params,tdir)

# -------------------------------------------------

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

# -------------------------------------------------

if __name__=="__main__":
    main()
