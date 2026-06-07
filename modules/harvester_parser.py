import xml.etree.ElementTree as ET
import json
import os

def parse_harvester(xml_file):
    results = {"emails": [], "urls": [], "hosts": [], "subdomains": []}
    if not os.path.exists(xml_file):
        return results
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for email in root.findall(".//email"):
            if email.text: results["emails"].append(email.text.strip())
        for url in root.findall(".//url"):
            if url.text: results["urls"].append(url.text.strip())
        for host in root.findall(".//host"):
            if host.text: results["hosts"].append(host.text.strip())
    except:
        json_file = xml_file.replace('.xml', '.json')
        if os.path.exists(json_file):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    results["urls"] = data.get("interesting_urls", [])
            except:
                pass
    for k in results:
        results[k] = list(set(results[k]))
    return results
