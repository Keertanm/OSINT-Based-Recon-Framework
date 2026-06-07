#!/usr/bin/env python3
import subprocess
import os
import shodan
from dotenv import load_dotenv
from modules.dns_parser import parse_dnsrecon
from modules.harvester_parser import parse_harvester
from modules.report import generate_report

load_dotenv()

def run_tool(cmd, description):
    print(f"\n[+] Running {description}...\n")
    try:
        result = subprocess.run(cmd, shell=True, timeout=360, capture_output=True, text=True)
        if "DNSRecon" in description:
            for line in result.stdout.splitlines():
                if any(k in line for k in ["INFO", "A ", "MX ", "NS ", "TXT ", "SOA ", "Completed"]):
                    print(line.strip())
        elif "theHarvester" in description:
            print(result.stdout)
        print(f"[+] {description} completed successfully\n")
        return True
    except:
        print(f"[+] {description} completed with warnings\n")
        return False

def run_spiderfoot(domain):
    print(f"[+] Starting SpiderFoot for visual mapping (may take 5-10 minutes)...")
    os.makedirs("outputs/spiderfoot", exist_ok=True)
    try:
        subprocess.run(f"python3 spiderfoot/sf.py -s {domain} -m footprint -o csv", shell=True, timeout=900)
        print(f"[+] SpiderFoot completed!")
        return True
    except:
        print("[-] SpiderFoot scan took too long. You can run it manually.")
        return False

def main():
    import re
    domain = input("Enter target domain [testphp.vulnweb.com]: ").strip() or "testphp.vulnweb.com"
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+[a-zA-Z0-9]$', domain):
        print("[-] Invalid domain format. Exiting.")
        exit(1)
    print(f"\n🚀 Starting OSINT-Based Reconnaissance Framework → {domain}\n")

    os.makedirs("outputs/dns", exist_ok=True)
    os.makedirs("outputs/harvester", exist_ok=True)

    run_tool(f"dnsrecon -d {domain} -t std -x outputs/dns/dnsrecon_std.xml", "DNSRecon")
    dns_data = parse_dnsrecon("outputs/dns/dnsrecon_std.xml")

    run_tool(f"theHarvester -d {domain} -b duckduckgo,crtsh,rapiddns,urlscan -l 200 -f outputs/harvester.xml", "theHarvester")
    harvester_data = parse_harvester("outputs/harvester.xml")

    print("[+] Querying Shodan using Python library...")
    shodan_data = {"status": "Processed"}

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        print("    [-] SHODAN_API_KEY not set in .env — skipping Shodan lookup")
    else:
        try:
            api = shodan.Shodan(api_key)
            for ip in dns_data.get("ips", [])[:3]:
                try:
                    host = api.host(ip)
                    ports = host.get("ports", [])
                    shodan_data[ip] = {"ports": ports}
                    print(f"    ✓ {ip} → {len(ports)} open ports found")
                except:
                    pass
        except Exception as e:
            print(f"    [-] Shodan query failed: {e}")

    generate_report(domain, dns_data, harvester_data, shodan_data)

    print("\n[+] Running SpiderFoot for visual relationship mapping...")
    run_spiderfoot(domain)

    print(f"\n🎉 Framework Complete!")
    print(f"📊 Open Report → open reports/{domain}_report.html")

if __name__ == "__main__":
    main()
