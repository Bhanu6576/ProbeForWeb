

import sys
import argparse
import subprocess
import os
import time
import threading
import json
import re
import signal
import shutil
from urllib.parse import urlparse
import http.server
import socketserver
from concurrent.futures import ThreadPoolExecutor

# ANSI color codes
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Time display
def display_time(seconds):
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m {int(seconds % 60)}s"

# URL formatting
def url_maker(url):
    if not re.match(r'https?://', url):
        url = 'http://' + url
    parsed = urlparse(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

# Check internet connectivity
def check_internet(retries=3, delay=5):
    for attempt in range(retries):
        try:
            subprocess.check_output('ping -c1 google.com', shell=True)
            return True
        except subprocess.CalledProcessError:
            print(f"{bcolors.WARNING}Internet check failed, retrying ({attempt+1}/{retries})...{bcolors.ENDC}")
            time.sleep(delay)
    return False

# Toolset (assumes tools are pre-installed in /opt/probeforweb-tools/)
TOOLS = [
    ["/opt/probeforweb-tools/nmap", "Nmap - Port Scan", "nmap -F --open -Pn ", "open", "l", "Open ports detected"],
    ["/opt/probeforweb-tools/nmap", "Nmap - SSL Vulns", "nmap -p443 --script ssl-enum-ciphers -Pn ", "VULNERABLE", "h", "SSL vulnerabilities"],
    ["/opt/probeforweb-tools/nmap", "Nmap - Vuln Scan", "nmap --script vuln -Pn ", "VULNERABLE", "m", "Vulnerabilities detected"],
    ["/opt/probeforweb-tools/dnsrecon", "DNSRecon - Zone Xfer", "dnsrecon -d ", "Zone Transfer", "h", "Zone transfer successful"],
    ["/opt/probeforweb-tools/whois", "WHOIS Lookup", "whois ", "registrar", "i", "Admin info found"],
    ["/opt/probeforweb-tools/amass", "Amass - Subdomains", "amass enum -d ", "discovered", "m", "Subdomains found"],
    ["/opt/probeforweb-tools/subfinder", "Subfinder - Subdomains", "subfinder -d ", "Found", "m", "Subdomains discovered"],
    ["/opt/probeforweb-tools/wget", "WordPress Check", "wget -q -O /tmp/wp_check --tries=1 ", "/wp-", "i", "WordPress detected"],
    ["/opt/probeforweb-tools/wget", "Drupal Check", "wget -q -O /tmp/drupal_check --tries=1 ", "drupal", "i", "Drupal detected"],
    ["/opt/probeforweb-tools/nikto", "Nikto - Web Vulns", "nikto -h ", "OSVDB", "m", "Web vulnerabilities"],
    ["/opt/probeforweb-tools/whatweb", "WhatWeb - Tech Stack", "whatweb ", "HTTP", "i", "Tech stack identified"],
    ["/opt/probeforweb-tools/httpx", "HTTPX - Probe", "httpx -u ", "http", "i", "Live endpoints"],
    ["/opt/probeforweb-tools/nuclei", "Nuclei - Vuln Scan", "nuclei -u ", "[info]", "m", "Vulnerabilities detected"],
    ["/opt/probeforweb-tools/dirsearch", "Dirsearch - Dir Brute", "dirsearch -u ", "FOUND", "m", "Directories found"],
    ["/opt/probeforweb-tools/sqlmap", "SQLMap - SQL Inj", "sqlmap -u ", "sqlmap identified", "h", "SQL injection possible"],
    ["/opt/probeforweb-tools/wpscan", "WPScan - WP Vulns", "wpscan --url ", "[+]", "m", "WP vulnerabilities"],
    ["/opt/probeforweb-tools/ffuf", "FFUF - Fuzzing", "ffuf -u FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200 ", "200", "m", "Fuzzing hits"],
    ["/opt/probeforweb-tools/gobuster", "Gobuster - Dir Scan", "gobuster dir -u ", "200", "m", "Directories found"],
    ["/opt/probeforweb-tools/shcheck", "SHCheck - Headers", "shcheck ", "Missing", "m", "Header misconfigs"],
    ["/opt/probeforweb-tools/testssl.sh", "TestSSL - SSL Check", "testssl.sh ", "vulnerable", "h", "SSL issues"],
    ["/opt/probeforweb-tools/waybackurls", "WaybackURLs - History", "waybackurls ", "", "i", "Historical URLs"],
    ["/opt/probeforweb-tools/gau", "GAU - URL Fetch", "gau ", "", "i", "Fetched URLs"],
    ["/opt/probeforweb-tools/git-dumper", "GitDumper - Git Exposure", "git-dumper ", "Dumped", "h", "Git repo exposed"],
    ["/opt/probeforweb-tools/trufflehog", "TruffleHog - Secrets", "trufflehog http://", "found", "h", "Secrets detected"],
    ["/opt/probeforweb-tools/dnsx", "DNSX - DNS Lookup", "dnsx -d ", "resolved", "i", "DNS records"],
    ["/opt/probeforweb-tools/cloud_enum", "CloudEnum - Cloud Assets", "cloud_enum -k ", "found", "m", "Cloud assets"],
    ["/opt/probeforweb-tools/sublist3r", "Sublist3r - Subdomains", "sublist3r -d ", "Subdomains", "m", "Subdomains found"],
    ["/opt/probeforweb-tools/aquatone", "Aquatone - Screenshots", "aquatone -u ", "screenshot", "i", "Screenshots taken"],
    ["/opt/probeforweb-tools/commix", "Commix - Cmd Inj", "commix -u ", "vulnerable", "h", "Command injection"],
]

# Results storage
results = []
lock = threading.Lock()
skip_current = False

# Signal handlers
def signal_handler_ctrl_c(sig, frame):
    global skip_current
    skip_current = True
    print(f"\n{bcolors.WARNING}Skipping current tool...{bcolors.ENDC}")

def signal_handler_ctrl_z(sig, frame):
    print(f"\n{bcolors.BADFAIL}Stopping scan... Displaying partial results.{bcolors.ENDC}")
    display_partial_results()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler_ctrl_c)
signal.signal(signal.SIGTSTP, signal_handler_ctrl_z)

# Run a single scan
def run_scan(tool, target):
    global skip_current
    skip_current = False
    
    binary = tool[0]
    if not os.path.exists(binary):
        elapsed = 0
        with lock:
            results.append({
                "tool": tool[1],
                "severity": "i",
                "message": "Tool not found",
                "details": f"{tool[0]} not found in /opt/probeforweb-tools/",
                "time": display_time(elapsed)
            })
        return elapsed
    
    url_target = f"http://{target}"
    if tool[1] == "FFUF - Fuzzing":
        cmd = f"{binary} {url_target} > /tmp/{tool[1].replace(' ', '_')}_out 2>&1"
    elif tool[1] == "Gobuster - Dir Scan":
        cmd = f"{binary} -w /usr/share/wordlists/dirb/common.txt -q {url_target} > /tmp/{tool[1].replace(' ', '_')}_out 2>&1"
    elif tool[1] in ["Nmap - Port Scan", "Nmap - SSL Vulns", "Nmap - Vuln Scan", "DNSRecon - Zone Xfer", "WHOIS Lookup", "Amass - Subdomains", "Subfinder - Subdomains", "DNSX - DNS Lookup", "Sublist3r - Subdomains"]:
        cmd = f"{binary} {target} > /tmp/{tool[1].replace(' ', '_')}_out 2>&1"
    elif tool[1] in ["WordPress Check", "Drupal Check"]:
        cmd = f"{binary} {url_target} > /tmp/{tool[1].replace(' ', '_')}_out 2>&1"
    elif tool[1] == "TruffleHog - Secrets":
        cmd = f"{binary} {url_target} > /tmp/{tool[1].replace(' ', '_')}_out 2>&1"
    else:
        cmd = f"{binary} {url_target} > /tmp/{tool[1].replace(' ', '_')}_out 2>&1"
    
    start_time = time.time()
    spinner = Spinner(tool[1])
    spinner.start()
    
    try:
        process = subprocess.Popen(cmd, shell=True)
        process.wait(timeout=120)
        if skip_current:
            spinner.stop()
            return 0
        with open(f"/tmp/{tool[1].replace(' ', '_')}_out", 'r') as f:
            output = f.read()
        elapsed = time.time() - start_time
        severity = tool[4] if (tool[3] and tool[3] in output) else "i"
        message = tool[5] if (tool[3] and tool[3] in output) else "No significant findings"
        if "Usage:" in output or "error:" in output.lower() or "not found" in output:
            severity = "i"
            message = "Tool execution failed"
        with lock:
            results.append({
                "tool": tool[1],
                "severity": severity,
                "message": message,
                "details": output[:1000],
                "time": display_time(elapsed)
            })
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        if not skip_current:
            elapsed = time.time() - start_time
            with lock:
                results.append({
                    "tool": tool[1],
                    "severity": "i",
                    "message": "Scan failed or timed out",
                    "details": "N/A",
                    "time": display_time(elapsed)
                })
    spinner.stop()
    return elapsed

# Parallel scanning
def scan_target(target):
    total_time = 0
    print(f"{bcolors.OKBLUE}Starting scan on {target} with {len(TOOLS)} tools{bcolors.ENDC}")
    
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(run_scan, tool, target) for tool in TOOLS]
        for future, tool in zip(futures, TOOLS):
            elapsed = future.result()
            if elapsed > 0:
                total_time += elapsed
                print(f"{bcolors.OKGREEN}{tool[1]} completed in {display_time(elapsed)}{bcolors.ENDC}")
            else:
                print(f"{bcolors.WARNING}{tool[1]} skipped{bcolors.ENDC}")
    
    return total_time

# Store results in JSON
def store_results(target):
    output_file = f"scan_results_{target}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    return output_file

# Generate HTML with improved color differentiation
def generate_html_page(target, json_file):
    html_file = f"results_{target}.html"
    severity_counts = {"c": 0, "h": 0, "m": 0, "l": 0, "i": 0}
    for res in results:
        severity_counts[res["severity"]] += 1

    html = """
    <html>
    <head>
        <title>Probeforweb Scan Results</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
            h1 { color: #333; text-align: center; }
            .result { border: 1px solid #999; padding: 15px; margin: 15px 0; border-radius: 5px; }
            .critical { background-color: #ffcccc; border-color: #ff0000; }
            .high { background-color: #ff9999; border-color: #cc0000; }
            .medium { background-color: #ffff99; border-color: #cccc00; }
            .low { background-color: #ccffcc; border-color: #00cc00; }
            .info { background-color: #cce5ff; border-color: #0066cc; }
            pre { background-color: #fff; padding: 10px; border: 1px dashed #ccc; max-height: 300px; overflow-y: auto; }
            #graph-container { width: 300px; height: 200px; border: 2px solid #333; margin: 20px auto; }
            h2 { margin: 0; color: #444; }
            p { margin: 5px 0; }
        </style>
    </head>
    <body>
    <h1>Scan Results for """ + target + """</h1>
    <div id="graph-container">
        <canvas id="severityChart"></canvas>
    </div>
    """
    if not results:
        html += "<p>No significant findings detected.</p>"
    else:
        html += "<ul>"
        for res in results:
            severity_class = {"c": "critical", "h": "high", "m": "medium", "l": "low", "i": "info"}[res["severity"]]
            html += f"""
            <li class="result {severity_class}">
                <h2>{res["tool"]}</h2>
                <p><strong>Severity:</strong> <span style="color: {'#ff0000' if res['severity'] == 'c' else '#cc0000' if res['severity'] == 'h' else '#cccc00' if res['severity'] == 'm' else '#00cc00' if res['severity'] == 'l' else '#0066cc'}">{res["severity"].upper()}</span></p>
                <p><strong>Message:</strong> {res["message"]}</p>
                <p><strong>Time:</strong> {res["time"]}</p>
                <pre>{res["details"]}</pre>
            </li>
            """
        html += "</ul>"
    html += """
    <script>
    var ctx = document.getElementById('severityChart').getContext('2d');
    var chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['C', 'H', 'M', 'L', 'I'],
            datasets: [{
                label: 'Severity',
                data: [""" + str(severity_counts["c"]) + "," + str(severity_counts["h"]) + "," + str(severity_counts["m"]) + "," + str(severity_counts["l"]) + "," + str(severity_counts["i"]) + """],
                backgroundColor: ['#ffcccc', '#ff9999', '#ffff99', '#ccffcc', '#cce5ff'],
                borderColor: ['#ff0000', '#cc0000', '#cccc00', '#00cc00', '#0066cc'],
                borderWidth: 1
            }]
        },
        options: {
            scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
            plugins: { legend: { display: false } }
        }
    });
    </script>
    </body></html>
    """
    
    with open(html_file, "w") as f:
        f.write(html)
    return html_file

# Display partial results
def display_partial_results():
    json_file = store_results(target)
    html_file = generate_html_page(target, json_file)
    print(f"{bcolors.OKGREEN}Partial results stored in {json_file}{bcolors.ENDC}")
    try:
        start_server(target, html_file)
    except OSError as e:
        print(f"{bcolors.BADFAIL}Server error: {e}. Try a different port or close existing server.{bcolors.ENDC}")

# Start local web server
def start_server(target, html_file):
    PORT = 8000
    Handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", PORT), Handler, bind_and_activate=False)
    httpd.server_bind()
    httpd.server_activate()
    print(f"{bcolors.OKGREEN}Results available at http://localhost:{PORT}/{html_file}{bcolors.ENDC}")
    print("Press Ctrl+C to stop the server.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
        print(f"\n{bcolors.WARNING}Server stopped.{bcolors.ENDC}")
        os.system(f'rm /tmp/*_out > /dev/null 2>&1')
        sys.exit(0)

# ASCII logo with instructions
def print_logo():
    logo = r"""
{bcolors.OKBLUE}
 ____            _          _____        __        __   _     
|  _ \ _ __ ___ | |__   ___|  ___|__  _ _\ \      / /__| |__  
| |_) | '__/ _ \| '_ \ / _ \ |_ / _ \| '__\ \ /\ / / _ \ '_ \ 
|  __/| | | (_) | |_) |  __/  _| (_) | |   \ V  V /  __/ |_) |
|_|   |_|  \___/|_.__/ \___|_|  \___/|_|    \_/\_/ \___|_.__/ 
{bcolors.ENDC}      (The ProbeForWeb Vulnerability Scanner)
(Author: Bhanu)
    Note: Download tools from https://github.com/<your-repo>/probeforweb-tools and place them in /opt/probeforweb-tools/
    """
    print(logo.format(bcolors=bcolors))

# Argument parser
def get_parser():
    parser = argparse.ArgumentParser(description="Probeforweb - Multi-Tool Web Scanner")
    parser.add_argument("target", help="URL to scan (e.g., domain.com)")
    return parser

# Main execution
if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_logo()
        print("Usage: python3 probeforweb.py domain.com")
        print("Controls: Ctrl+C to skip a tool, Ctrl+Z to stop and view partial results")
        sys.exit(1)

    print_logo()
    args = get_parser().parse_args()
    target = url_maker(args.target)

    # Clean up previous files
    os.system(f'rm /tmp/*_out > /dev/null 2>&1')
    os.system(f'rm results_{target}.html > /dev/null 2>&1')
    os.system(f'rm scan_results_{target}.json > /dev/null 2>&1')

    # Check internet
    if not check_internet():
        print(f"{bcolors.BADFAIL}No internet connection after retries. Exiting.{bcolors.ENDC}")
        sys.exit(1)

    # Run scan
    total_time = scan_target(target)
    print(f"{bcolors.OKBLUE}Total scan time: {display_time(total_time)}{bcolors.ENDC}")

    # Store and display results
    json_file = store_results(target)
    html_file = generate_html_page(target, json_file)
    print(f"{bcolors.OKGREEN}Results stored in {json_file}{bcolors.ENDC}")

    try:
        start_server(target, html_file)
    except OSError as e:
        print(f"{bcolors.BADFAIL}Server error: {e}. Try a different port or close existing server.{bcolors.ENDC}")
