import asyncio
import subprocess
from termcolor import colored
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import os
import time
import psutil

def run_nmap(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout

def parse_open_ports(output):
    open_hosts = []
    current_ip = None
    for line in output.splitlines():
        if "Nmap scan report for" in line:
            current_ip = line.split()[-1]
        if current_ip and "3389/tcp open" in line:
            open_hosts.append(current_ip)
    return open_hosts

def terminate_processes(pids):
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
        except psutil.NoSuchProcess:
            pass

def check_nla(host, quiet=False):
    nla_supported = False
    pids = []
    try:
        if quiet:
            with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
                tmpfile_name = tmpfile.name
            command = f"xvfb-run --auto-servernum --server-args='-screen 0 1024x768x24' rdesktop -u '' {host} -vv > {tmpfile_name} 2>&1"
            process = subprocess.Popen(command, shell=True)
            pids.append(process.pid)
            time.sleep(5)  # Wait for 5 seconds
            terminate_processes(pids)
            with open(tmpfile_name, 'r') as tmpfile:
                output = tmpfile.read()
            os.remove(tmpfile_name)
        else:
            command = f"echo 'yes' | rdesktop -u '' {host} -vv"
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout

        if "Failed to connect, CredSSP required by server" in output:
            nla_supported = True
    except FileNotFoundError:
        print(colored(f"Failed to connect to {host}: 'rdesktop' not found. Please install rdesktop.", "red"))
    except Exception as e:
        print(colored(f"Failed to connect to {host}: {e}", "red"))

    if nla_supported:
        return host, colored("NLA Enabled", "green"), "NLA Enabled"
    else:
        return host, colored("NLA Disabled", "red"), "NLA Disabled"

async def run_initial_scan(ip_range):
    print(colored(f"Starting initial scan for range: {ip_range}", "yellow"))
    initial_command = ["nmap", "-p", "3389", "-T4", "-Pn", "-n", ip_range]
    output = await asyncio.to_thread(run_nmap, initial_command)
    open_hosts = parse_open_ports(output)
    return open_hosts

async def scan_range(ip_range, quiet):
    open_hosts = await run_initial_scan(ip_range)
    if not open_hosts:
        print(colored("No hosts with port 3389 open found.", "red"))
        return []

    print(colored(f"Found {len(open_hosts)} hosts with port 3389 open:", "yellow"))
    for host in open_hosts:
        print(colored(host, "cyan"))

    print(colored("Starting detailed scan...", "yellow"))

    results = []
    raw_results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_host = {executor.submit(check_nla, host, quiet): host for host in open_hosts}
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                result = future.result()
                results.append(result[:2])
                raw_results.append(result)
            except Exception as exc:
                print(colored(f"{host} generated an exception: {exc}", "red"))

    print(colored("Detailed scan complete.", "yellow"))
    return results, raw_results

def generate_html_table(raw_results):
    html = "<table>\n"
    html += "  <thead>\n"
    html += "    <tr>\n"
    html += "      <th scope=\"col\">IP Address</th>\n"
    html += "      <th scope=\"col\">NLA Status</th>\n"
    html += "    </tr>\n"
    html += "  </thead>\n"
    html += "  <tbody>\n"
    for result in raw_results:
        html += "    <tr>\n"
        html += f"      <td>{result[0]}</td>\n"
        html += f"      <td>{result[2]}</td>\n"
        html += "    </tr>\n"
    html += "  </tbody>\n"
    html += "</table>"
    return html

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan IP or range for NLA status on RDP port 3389.")
    parser.add_argument("--ip", help="Single IP address to scan")
    parser.add_argument("--range", help="CIDR range of IP addresses to scan")
    parser.add_argument("--quiet", action="store_true", help="Run the commands in the background without opening RDP windows")
    parser.add_argument("--output", help="Specify output format: html")
    args = parser.parse_args()

    if args.ip:
        print(colored(f"Starting scan for IP: {args.ip}", "yellow"))
        results, raw_results = asyncio.run(scan_range(args.ip, args.quiet))
        if args.output == "html":
            html_output = generate_html_table(raw_results)
            print(html_output)
        else:
            for ip, status in results:
                print(f"{ip}: {status}")
        print(colored("Scanning complete.", "yellow"))
    elif args.range:
        results, raw_results = asyncio.run(scan_range(args.range, args.quiet))
        if args.output == "html":
            html_output = generate_html_table(raw_results)
            print(html_output)
        else:
            for ip, status in results:
                print(f"{ip}: {status}")
    else:
        print(colored("Please provide --ip or --range argument.", "red"))
