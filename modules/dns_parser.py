import xml.etree.ElementTree as ET
import os

def parse_dnsrecon(xml_file):
    results = {"ips": [], "records": [], "nameservers": [], "mx": []}
    if not os.path.exists(xml_file):
        return results
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for record in root.findall(".//record"):
            rec_type = record.get("type")
            if rec_type == "A" and record.get("address"):
                results["ips"].append(record.get("address"))
            elif rec_type:
                results["records"].append({
                    "type": rec_type,
                    "name": record.get("name", ""),
                    "value": record.get("address") or record.get("exchange") or ""
                })
    except Exception as e:
        print(f"[-] DNS parse error: {e}")
    return results
