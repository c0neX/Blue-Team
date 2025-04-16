import requests
import json
import datetime
import os
import sys

# Configurações
CVSS_THRESHOLD = 7.0  # Inclui apenas CVEs com score maior ou igual
TARGET_VENDOR = ""    # Deixe vazio para aceitar todos os vendors (ex: "microsoft")
DEBUG = True          # Ativa impressão dos CPEs para debug
OUTPUT_FILE = "filtered_cves.json"

# Configurações da API da NVD
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = ""  # Insira sua chave da API da NVD aqui (opcional)

def fetch_recent_cves():
    today = datetime.datetime.now(datetime.timezone.utc).date()
    yesterday = today - datetime.timedelta(days=1)

    params = {
        "pubStartDate": f"{yesterday}T00:00:00.000Z",
        "pubEndDate": f"{today}T00:00:00.000Z",
    }
    headers = {"apiKey": API_KEY} if API_KEY else {}

    try:
        response = requests.get(BASE_URL, params=params, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except requests.exceptions.RequestException as e:
        print(f"[ERRO] Falha ao acessar a API da NVD: {e}")
    except json.JSONDecodeError as e:
        print(f"[ERRO] Erro ao decodificar JSON da resposta: {e}")
    return []

def cve_matches_criteria(cve_item):
    cve = cve_item.get("cve", {})
    cvss_score = None

    metrics = cve.get("metrics", {})
    try:
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    except (IndexError, KeyError, TypeError):
        cvss_score = None

    if cvss_score is None or cvss_score < CVSS_THRESHOLD:
        return False

    if TARGET_VENDOR:
        nodes = cve.get("configurations", {}).get("nodes", [])
        found = False
        for node in nodes:
            cpes = node.get("cpeMatch", [])
            for cpe in cpes:
                criteria = cpe.get("criteria", "")
                if DEBUG:
                    print("CPE encontrado:", criteria)
                if TARGET_VENDOR.lower() in criteria.lower():
                    found = True
                    break
            if found:
                break
        if not found:
            return False

    return True

def append_to_json_file(data):
    if os.path.exists(OUTPUT_FILE):
        if not os.access(OUTPUT_FILE, os.W_OK):
            print(f"[ERRO] Sem permissão de escrita no arquivo {OUTPUT_FILE}")
            return
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing_data = []
    else:
        existing_data = []

    existing_data.extend(data)

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2)
        print(f"[OK] Dados salvos em '{OUTPUT_FILE}' com sucesso.")
    except IOError as e:
        print(f"[ERRO] Falha ao escrever no arquivo: {e}")

def main():
    print("🔍 Buscando CVEs recentes na NVD...")
    recent_cves = fetch_recent_cves()

    if not recent_cves:
        print("[INFO] Nenhuma CVE encontrada ou erro ao buscar dados.")
        return

    print(f"[INFO] {len(recent_cves)} CVEs recuperadas.")
    filtered_cves = [cve for cve in recent_cves if cve_matches_criteria(cve)]
    print(f"[INFO] {len(filtered_cves)} CVEs filtradas com base nos critérios.")

    if filtered_cves:
        append_to_json_file(filtered_cves)
    else:
        print("[INFO] Nenhuma CVE corresponde aos critérios definidos.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[ABORTADO] Execução interrompida pelo usuário.")
        sys.exit(1)
