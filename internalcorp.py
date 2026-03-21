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

REQUIRED_TOOLS = ["nmap","katana","nuclei"]

WEB_PORT_HINTS = {80,443,8080,8000,8443,3000,5000,7001,9000}

STATIC_EXT = (".css",".js",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".webp",".mp4",".pdf",".zip")

LOCK = threading.Lock()

def log(msg,color=Fore.CYAN):
    with LOCK:
        print(color + msg)

# -------------------------------------------------

def run_cmd(cmd,timeout=None):

    log(f"[EXEC] {cmd}",Fore.YELLOW)

    try:
        return subprocess.run(cmd,shell=True,timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        log("[TIMEOUT]",Fore.RED)
        return -1

# -------------------------------------------------

def nmap_scan(target,tdir,resume):

    tcp_xml=f"{tdir}/nmap_tcp.xml"
    udp_xml=f"{tdir}/nmap_udp.xml"

    if not (resume and os.path.exists(tcp_xml)):
        cmd=f"nmap -Pn -p- -sS -sV -sC --open -T4 --min-rate 500 --max-retries 1 -oA {tdir}/nmap_tcp {target}"
        run_cmd(cmd,3600)

    if not (resume and os.path.exists(udp_xml)):
        cmd=f"nmap -Pn -sU -sV -sC --open --top-ports 200 -T4 --max-retries 1 -oA {tdir}/nmap_udp {target}"
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

    if os.path.getsize(url_file)==0:
        log("[!] No web urls",Fore.RED)
        return katana_out,dir_out

    cmd1=f"katana -list {url_file} -jc -o {katana_out}"
    cmd2=f"dirsearch -l {url_file} -o {dir_out}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futures=[
            ex.submit(run_cmd,cmd1,1800),
            ex.submit(run_cmd,cmd2,1800)
        ]
        concurrent.futures.wait(futures)

    return katana_out,dir_out

# -------------------------------------------------

def merge_filter(files, outfile):

    GOOD_CODES = {"200","302","401","403"}

    KEYWORDS = (
        "admin","login","console","dashboard","manager",
        "phpmyadmin","api","test","dev","config","secure"
    )

    DYNAMIC_EXT = (
        ".php",".jsp",".asp",".aspx",".do",".action",".json"
    )

    seen = set()

    with open(outfile, "w") as out:

        for f in files:

            if not os.path.exists(f):
                continue

            with open(f) as fh:

                for line in fh:

                    line = line.strip()
                    if not line:
                        continue

                    # -------- DIRSEARCH FORMAT --------
                    if line[0].isdigit():

                        parts = line.split()
                        if len(parts) < 3:
                            continue

                        status = parts[0]
                        if status not in GOOD_CODES:
                            continue

                        url = parts[-1]

                    # -------- KATANA FORMAT --------
                    else:
                        url = line

                        # aggressive katana filtering
                        if "?" not in url \
                           and not any(k in url.lower() for k in KEYWORDS) \
                           and not url.lower().endswith(DYNAMIC_EXT):
                            continue

                        # skip deep crawling noise
                        if url.count("/") > 6:
                            continue

                    # -------- STATIC FILTER --------
                    if url.lower().endswith(STATIC_EXT):
                        continue

                    # -------- DEDUP --------
                    h = hashlib.sha1(url.encode()).hexdigest()
                    if h in seen:
                        continue

                    seen.add(h)
                    out.write(url + "\n")

# -------------------------------------------------

def nuclei_scan(url_file,tdir):

    if os.path.getsize(url_file)==0:
        log("[!] No URLs for nuclei",Fore.RED)
        return

    cmd=f"nuclei -l {url_file} -severity low,medium,high,critical -rate-limit 150 -c 50 -o {tdir}/nuclei.txt"
    run_cmd(cmd,3600)

# -------------------------------------------------

def process_target(target,resume):

    log(f"===== {target} =====",Fore.MAGENTA)

    tdir=f"results/{target}"
    os.makedirs(tdir,exist_ok=True)

    nmap_scan(target,tdir,resume)

    ports=parse_web_ports(f"{tdir}/nmap_tcp.xml")

    if not ports:
        log("[!] No web ports",Fore.RED)
        return

    url_file=f"{tdir}/base_urls.txt"
    build_base_urls(target,ports,url_file)

    katana,dirsearch=web_enum(url_file,tdir)

    filtered=f"{tdir}/filtered_urls.txt"
    merge_filter([katana,dirsearch],filtered)

    nuclei_scan(filtered,tdir)

# -------------------------------------------------

def main():

    parser=argparse.ArgumentParser()
    parser.add_argument("targets",nargs="*")
    parser.add_argument("-l","--list")
    parser.add_argument("--resume",action="store_true")
    parser.add_argument("-t","--threads",type=int,default=5)

    args=parser.parse_args()

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

if __name__=="__main__":
    main()
