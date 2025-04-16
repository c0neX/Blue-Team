import os
import requests
import pandas as pd
import time
import logging

# ===============================
# Setup logging
# ===============================
logging.basicConfig(filename="ioc_collector.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ===============================
# API KEYS - use environment variables
# ===============================
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

COMMON_HEADERS = {
    "User-Agent": "IOCCollector/1.0"
}

# ===============================
# AbuseIPDB
# ===============================
def fetch_abuseipdb(limit=20):
    print("[*] Querying AbuseIPDB...")
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY,
        **COMMON_HEADERS
    }
    params = {"confidenceMinimum": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        if "data" not in data:
            return []
        return [{"ip": x["ipAddress"], "abuse_score": x["abuseConfidenceScore"]} for x in data["data"][:limit]]
    except Exception as e:
        logging.error(f"AbuseIPDB error: {e}")
        return []

# ===============================
# URLhaus
# ===============================
def fetch_urlhaus():
    print("[*] Fetching recent URLs from URLhaus...")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    urls = []
    try:
        r = requests.get(url, headers=COMMON_HEADERS)
        r.raise_for_status()
        r.encoding = "utf-8"
        for line in r.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) > 6:
                urls.append({
                    "url": parts[2],
                    "host": parts[3],
                    "threat": parts[6]
                })
        return urls
    except Exception as e:
        logging.error(f"URLhaus error: {e}")
        return []

# ===============================
# VirusTotal
# ===============================
def fetch_virustotal_domain(domain):
    print(f"[*] Checking domain {domain} on VirusTotal...")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        **COMMON_HEADERS
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        return {
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0)
        }
    except Exception as e:
        logging.error(f"VirusTotal error for {domain}: {e}")
        return {"domain": domain, "error": str(e)}

# ===============================
# AlienVault OTX
# ===============================
def fetch_otx_pulses(limit=10):
    print("[*] Querying AlienVault OTX...")
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        **COMMON_HEADERS
    }
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    pulses = []
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        for pulse in data.get("results", [])[:limit]:
            for indicator in pulse.get("indicators", []):
                pulses.append({
                    "indicator": indicator.get("indicator"),
                    "type": indicator.get("type"),
                    "description": pulse.get("name"),
                    "malware_family": pulse.get("malware_family")
                })
        return pulses
    except Exception as e:
        logging.error(f"OTX error: {e}")
        return []

# ===============================
# MalwareBazaar
# ===============================
def fetch_malwarebazaar(limit=20):
    print("[*] Querying MalwareBazaar for recent samples...")
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_recent", "selector": "time"}
    try:
        response = requests.post(url, data=data, headers=COMMON_HEADERS)
        response.raise_for_status()
        results = response.json().get("data", [])
        samples = []
        for sample in results[:limit]:
            samples.append({
                "sha256": sample.get("sha256_hash"),
                "file_type": sample.get("file_type"),
                "signature": sample.get("signature"),
                "tags": ",".join(sample.get("tags", []))
            })
        return samples
    except Exception as e:
        logging.error(f"MalwareBazaar error: {e}")
        return []

# ===============================
# Main
# ===============================
if __name__ == "__main__":
    all_iocs = {}

    all_iocs["abuseipdb"] = fetch_abuseipdb()
    time.sleep(1)

    all_iocs["urlhaus"] = fetch_urlhaus()
    time.sleep(1)

    vt_result = fetch_virustotal_domain("example.com")
    all_iocs["virustotal"] = [vt_result]
    time.sleep(15)

    all_iocs["otx"] = fetch_otx_pulses()
    time.sleep(6)

    all_iocs["malwarebazaar"] = fetch_malwarebazaar()

    print("\n[✓] Exporting results to CSV...")

    for key, data in all_iocs.items():
        df = pd.DataFrame(data)
        df.to_csv(f"{key}_iocs.csv", index=False)
        print(f"[+] Saved {len(data)} entries to {key}_iocs.csv")

    print("\n[✓] IOC collection complete.")
