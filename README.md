# Internal Web Reconnaissance and Vulnerability Scanner

This is a professional, lightweight, high-performance Python3 script designed for internal penetration testing automation on Kali Linux.

## Features

- TCP and UDP port scanning using Nmap
- Web service detection and HTTP probing with httpx
- Web directory enumeration using Katana and Dirsearch in parallel
- URL filtering and parameter extraction
- Optional parameter URL verification
- Vulnerability scanning with Nuclei including severity filtering, concurrency, and rate limiting
- Resume capability and concurrency support
- Colored terminal output and progress messages
- Modular, production-style code structure

## Requirements

- Kali Linux with installed tools: nmap, httpx, katana, dirsearch, nuclei
- Python 3

## Usage

```bash
python3 internalcorp.py 10.10.10.5
python3 internalcorp.py example.local
python3 internalcorp.py -l ips.txt
python3 internalcorp.py -l ips.txt --resume
python3 internalcorp.py example.local --verify-params
```

## Command Line Options

- `targets`: Single IP or domain targets
- `-l, --list`: File containing list of targets
- `--resume`: Resume from previous scan results
- `--verify-params`: Verify parameter URLs are alive before nuclei scan
- `--severity`: Nuclei severity filter (default: low,medium,high,critical)
- `--concurrency`: Nuclei concurrency (default: 50)
- `--rate-limit`: Nuclei rate limit (default: 150)

## Output

All scan results are saved under `scan_results/<target>/` directories.

## License

This tool is for authorized penetration testing only.

