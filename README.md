# ⚡ Internal Recon Automation Tool

A lightweight, high-performance internal penetration testing automation tool designed to discover open ports and its services and scan web attack surfaces across internal network targets.

This tool combines fast port scanning, intelligent web enumeration, URL filtering, and vulnerability scanning into a simple automated workflow.

---

## 🚀 Features

- 🔎 Full TCP port scan using Nmap
- 📡 UDP top-ports service detection
- 🌐 Automatic web service discovery
- 🕷️ Web crawling using Katana
- 📁 Directory brute-forcing using Dirsearch
- 🧠 Smart URL filtering engine (dedup + noise reduction)
- 🎯 High-value endpoint prioritization
- ⚡ Fast vulnerability scanning using Nuclei
- 🧵 Multi-target parallel execution
- 🔁 Resume support for long scans
- 🎨 Colored CLI logging output
- 📂 Structured per-target result storage

---

## 📦 Requirements
Install required tools:
```bash
sudo apt install nmap
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
pip install dirsearch
pip install colorama
```

---

## ⚙️ Usage
```bash
python3 enum.py -h #help
python3 enum.py 10.10.10.5 #Scan Single Target
python3 enum.py -l targets.txt #Scan Multiple Targets
python3 enum.py -l targets.txt -t 10 #Parallel Execution
python3 enum.py -l targets.txt --resume #Resume Interrupted Scan
```

---

## 🎯 URL Filtering Logic

The tool intelligently keeps:
* HTTP status codes: 200, 302, 401, 403
* Parameterized URLs
* Admin / login / management endpoints
* Dynamic application paths

It removes:
* Static resources (CSS, JS, images, fonts)
* Deep crawl noise
* Duplicate URLs

---

## ⚡ Performance Design

* Multi-threaded target processing
* Timeout protection for long-running tools
* Streaming file processing (memory efficient)
* Aggressive but safe scanning defaults

---

## ⚠️ Disclaimer

This tool is intended for authorized internal penetration testing and security assessments only.
Use responsibly.
