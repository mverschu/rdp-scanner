
# RDP scanner

This script scans a given IP or range of IP addresses for the status of Network Level Authentication (NLA) on RDP port 3389.

## Screenshots

![image](https://github.com/mverschu/rdp-scanner/assets/69352107/e44f47c4-5029-4918-b4e7-bdb72189d1e4)

## Features
- Initial scan to identify hosts with port 3389 open using `nmap`.
- Detailed scan to check NLA status using `rdesktop` with an option to run quietly in the background using `xvfb-run`.
- Concurrent scanning to speed up the process.

## Prerequisites
- Python 3.6+
- `nmap`
- `rdesktop`
- `xvfb`

### Installation on Debian-based systems:
```bash
sudo apt-get install nmap rdesktop xvfb
pip install psutil termcolor
```

## Usage

### To scan a single IP:
```bash
python3 rdp-scanner.py --ip 192.168.1.1
```

### To scan a range of IPs:
```bash
python3 rdp-scanner.py --range 192.168.1.0/24
```

### To run in quiet mode (without opening RDP windows):
```bash
python3 rdp-scanner.py --range 192.168.1.0/24 --quiet
```

## Options

- `--ip`: Single IP address to scan.
- `--range`: CIDR range of IP addresses to scan.
- `--quiet`: Run the commands in the background without opening RDP windows.

## Example

```bash
python3 rdp-scanner.py --range 10.0.0.3/24 --quiet
```
