# ⚡ Internal Attack Surface Mapping & Pentest Automation

![Python](https://img.shields.io/badge/python-3.x-blue)
![Nmap](https://img.shields.io/badge/scan-nmap-red)
![Nuclei](https://img.shields.io/badge/vuln-nuclei-purple)
![License](https://img.shields.io/badge/license-internal-green)
![Status](https://img.shields.io/badge/status-active-success)

A lightweight internal penetration testing automation framework that performs **network enumeration, web discovery, vulnerability scanning and automated HTML reporting**.

Designed for **fast internal attack-surface mapping and reporting during security assessments.**

---

## 🚀 Key Capabilities

* 🔎 Full TCP port scanning with service detection
* 📡 UDP top-ports reconnaissance
* 🌐 Automatic web service discovery
* 🕷️ Web crawling using Katana
* 📁 Directory brute forcing using Dirsearch
* 🎯 Smart URL filtering and endpoint prioritization
* ⚡ High-speed vulnerability scanning using Nuclei
* 📊 Automated HTML reporting

  * Infrastructure exposure report
  * Web vulnerability report
* 🧵 Parallel multi-target scanning
* 🔁 Resume long scans
* 🎨 Colored CLI logging
* 📂 Structured per-target result storage

---

## 🏗️ Architecture

```text
Targets
   │
   ├──► Nmap Scan (TCP + UDP)
   │         │
   │         └──► Infra Intelligence Engine
   │                     │
   │                     └──► nmap_report.html
   │
   └──► Web Discovery (Katana + Dirsearch)
             │
             └──► URL Filtering Engine
                         │
                         └──► Nuclei Scan
                                    │
                                    └──► web_report.html
   
```

---

## 📊 Output Reports

### 🖥️ Infrastructure Report

* Exposed services
* Outdated software
* Crypto weaknesses
* Misconfigurations
* Legacy protocols
* Remote access exposure

**File:** `nmap_report.html`

---

### 🌐 Web Vulnerability Report

* CVE findings
* Template-based vulnerabilities
* Affected URLs
* Severity grouping
* Deduplicated results

**File:** `web_report.html`

---

## 📦 Requirements

```bash
sudo apt install nmap
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
pip install dirsearch
pip install colorama
```

---

## ⚙️ Usage

### Help

```bash
python3 enum.py -h
```

### Scan single host

```bash
python3 enum.py 10.10.10.5
```

### Scan multiple targets

```bash
python3 enum.py -l targets.txt
```

### Parallel scanning

```bash
python3 enum.py -l targets.txt -t 10
```

### Resume scan

```bash
python3 enum.py -l targets.txt --resume
```

### Export Report

```bash
# path results/ directory and its subdir should have all the .nmap and nuclei.txt reports
 
python3 nmap2html.py -i results/ -o nmap_report.html
python3 nuclei2html.py -i results/ -o nuclei_report.html
```

---

## 🧠 URL Filtering Logic

**Keeps:**

* Status codes: `200`, `302`, `401`, `403`
* Parameterized endpoints
* Admin / login paths
* Dynamic application URLs

**Removes:**

* Static files (JS, CSS, images, fonts)
* Duplicate URLs
* Deep crawl noise

---

## ⚡ Performance Design

* Multi-threaded target execution
* Timeout protection for long tasks
* Stream-based processing (low RAM usage)
* Safe aggressive scan defaults

---

## 📸 Screenshots

> screenshots

```
docs/
   infra_report.png
   web_report.png
```

---

## ⚠️ Disclaimer

This tool is intended **only for authorized internal penetration testing and security assessments.**
Do not use without proper permission.

---
