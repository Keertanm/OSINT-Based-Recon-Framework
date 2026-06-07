import json
import os
from datetime import datetime
import requests
import subprocess
import re

def check_hibp(emails):
    breached = {}
    headers = {"User-Agent": "MSRIT-OSINT-Framework"}
    for email in emails[:5]:
        try:
            r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", 
                           headers=headers, timeout=8)
            if r.status_code == 200:
                breached[email] = [b["Name"] for b in r.json()]
            elif r.status_code == 404:
                breached[email] = "✅ No known breaches"
        except:
            breached[email] = "Check failed"
    return breached

def get_whois(domain):
    try:
        result = subprocess.run(f"whois {domain}", shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout.lower()
        
        whois_info = {"domain": domain, "status": "Retrieved"}
        
        # Better regex patterns for dates
        creation_match = re.search(r'(?:creation date|registered on|created on|creation|created):\s*([^\n]+)', output)
        expiry_match = re.search(r'(?:expiry date|expires on|registry expiry date|expiration date):\s*([^\n]+)', output)
        registrar_match = re.search(r'(?:registrar|registrar name):\s*([^\n]+)', output)
        
        if creation_match:
            whois_info["creation_date"] = creation_match.group(1).strip()
        if expiry_match:
            whois_info["expiry_date"] = expiry_match.group(1).strip()
        if registrar_match:
            whois_info["registrar"] = registrar_match.group(1).strip()
        
        # Name Servers
        ns_matches = re.findall(r'(?:name server|nameserver):\s*([^\n]+)', output)
        if ns_matches:
            whois_info["name_servers"] = [ns.strip() for ns in ns_matches]
        
        # Fallback if dates not found
        if "creation_date" not in whois_info:
            whois_info["creation_date"] = "Not available (privacy protected)"
        if "expiry_date" not in whois_info:
            whois_info["expiry_date"] = "Not available (privacy protected)"
        
        return whois_info
    except Exception as e:
        return {"status": f"Whois lookup failed: {str(e)}"}

def generate_report(domain, dns_data, harvester_data, shodan_data=None):
    os.makedirs("reports", exist_ok=True)
    
    hibp_results = check_hibp(harvester_data.get("emails", []))
    whois_data = get_whois(domain)
    
    findings = []
    if dns_data.get("ips"):
        findings.append({"type": "Exposed IP Addresses", "severity": "High", "count": len(dns_data["ips"]), "details": dns_data["ips"]})
    if harvester_data.get("emails"):
        findings.append({"type": "Employee Emails Discovered", "severity": "Critical", "count": len(harvester_data["emails"]), "details": harvester_data["emails"]})
    if harvester_data.get("hosts"):
        findings.append({"type": "Subdomains Discovered", "severity": "Medium", "count": len(harvester_data["hosts"]), "details": harvester_data["hosts"][:12]})
    if harvester_data.get("urls"):
        findings.append({"type": "Interesting URLs Found", "severity": "Medium", "count": len(harvester_data["urls"]), "details": harvester_data["urls"][:8]})
    
    # Shodan
    shodan_details = []
    total_ports = 0
    if shodan_data and isinstance(shodan_data, dict):
        for ip, info in shodan_data.items():
            if isinstance(info, dict) and "ports" in info:
                ports = info.get("ports", [])
                if ports:
                    total_ports += len(ports)
                    shodan_details.append(f"{ip} → {ports}")
    
    if total_ports > 0:
        findings.append({"type": "Open Ports via Shodan", "severity": "High", "count": total_ports, "details": shodan_details})
    
    report = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "whois": whois_data,
        "findings": findings,
        "hibp": hibp_results,
        "recommendations": [
            "Enable WHOIS privacy protection",
            "Implement SPF, DKIM, and DMARC immediately",
            "Remove or secure unnecessary subdomains",
            "Use only role-based generic emails",
            "Enforce MFA for breached accounts",
            "Minimize server version disclosure",
            "Monitor attack surface regularly"
        ]
    }
    
    with open(f"reports/{domain}_report.json", "w") as f:
        json.dump(report, f, indent=4)
    
    # Professional HTML
    html = f"""<html>
    <head><title>OSINT Report - {domain}</title>
    <style>
        body {{font-family: Arial, sans-serif; margin: 40px; background: #f8fafc;}}
        h1, h2 {{color: #1e40af;}}
        table {{border-collapse: collapse; width: 100%; margin: 20px 0; background: white;}}
        th, td {{border: 1px solid #cbd5e1; padding: 12px; text-align: left;}}
        th {{background: #1e40af; color: white;}}
        .critical {{background: #fee2e2; font-weight: bold;}}
        .high {{background: #fef3c7;}}
        .medium {{background: #dbeafe;}}
        pre {{background: #f1f5f9; padding: 15px; border-radius: 5px;}}
    </style>
    </head>
    <body>
    <h1>OSINT Reconnaissance Report</h1>
    <p><strong>Target:</strong> {domain} | <strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
    
    <h2>Whois Information</h2>
    <pre>{json.dumps(whois_data, indent=2)}</pre>
    
    <h2>Key Findings</h2>
    <table>
    <tr><th>Finding Type</th><th>Severity</th><th>Count</th><th>Details</th></tr>
    """
    
    for f in findings:
        sev = f["severity"].lower()
        details_str = ", ".join(map(str, f.get("details", ["N/A"]))) if isinstance(f.get("details"), list) else str(f.get("details", "N/A"))
        html += f"""
        <tr class="{sev}">
            <td><strong>{f['type']}</strong></td>
            <td>{f['severity']}</td>
            <td>{f['count']}</td>
            <td>{details_str[:700]}{'...' if len(details_str) > 700 else ''}</td>
        </tr>"""
    
    html += f"</table><h2>Have I Been Pwned Results</h2><pre>{json.dumps(hibp_results, indent=2)}</pre>"
    html += f"<h2>Recommendations</h2><ul>"
    for rec in report["recommendations"]:
        html += f"<li>{rec}</li>"
    html += "</ul></body></html>"
    
    with open(f"reports/{domain}_report.html", "w") as f:
        f.write(html)
    
    print(f"[+] Report with Improved Whois generated!")
    return report
