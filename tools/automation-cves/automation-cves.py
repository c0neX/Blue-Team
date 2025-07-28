import requests
import json
import datetime
import os
import sys
import argparse

# Configurações da API da NVD
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = ""  # Insira sua chave da API da NVD aqui (opcional)
OUTPUT_FILE = "filtered_cves.json"
DEBUG = True


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor", help="Vendor alvo (ex: microsoft)", default="")
    parser.add_argument("--cvss", help="Score mínimo CVSS", type=float, default=7.0)
    return parser.parse_args()


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
        if response.status_code == 429:
            print("[ERRO] Rate limit excedido. Tente novamente mais tarde ou adicione uma API Key.")
            return []
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except requests.exceptions.RequestException as e:
        print(f"[ERRO] Falha ao acessar a API da NVD: {e}")
    except json.JSONDecodeError as e:
        print(f"[ERRO] Erro ao decodificar JSON da resposta: {e}")
    return []


def get_cvss_score(metrics):
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            try:
                return metrics[key][0]["cvssData"]["baseScore"]
            except (KeyError, IndexError, TypeError):
                continue
    return None


def vendor_matches(cve_item, target_vendor):
    nodes = cve_item.get("cve", {}).get("configurations", {}).get("nodes", [])
    for node in nodes:
        cpes = node.get("cpeMatch", [])
        for cpe in cpes:
            criteria = cpe.get("criteria", "")
            if DEBUG:
                print("CPE encontrado:", criteria)
            if target_vendor.lower() in criteria.lower():
                return True
    return False


def cve_matches_criteria(cve_item, cvss_threshold, target_vendor):
    cve = cve_item.get("cve", {})
    score = get_cvss_score(cve.get("metrics", {}))

    if score is None or score < cvss_threshold:
        return False

    if target_vendor and not vendor_matches(cve_item, target_vendor):
        return False

    return True


def resumir_cve(cve_item):
    cve = cve_item.get("cve", {})
    id = cve.get("id", "")
    description = cve.get("descriptions", [{}])[0].get("value", "")
    publish_date = cve_item.get("published", "")
    score = get_cvss_score(cve.get("metrics", {}))

    return {
        "id": id,
        "score": score,
        "description": description,
        "published": publish_date
    }


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
    args = get_args()
    target_vendor = args.vendor
    cvss_threshold = args.cvss

    print("🔍 Buscando CVEs recentes na NVD...")
    recent_cves = fetch_recent_cves()

    if not recent_cves:
        print("[INFO] Nenhuma CVE encontrada ou erro ao buscar dados.")
        return

    print(f"[INFO] {len(recent_cves)} CVEs recuperadas.")
    filtered_cves = [cve for cve in recent_cves if cve_matches_criteria(cve, cvss_threshold, target_vendor)]
    print(f"[INFO] {len(filtered_cves)} CVEs filtradas com base nos critérios.")

    if filtered_cves:
        resumo_cves = [resumir_cve(cve) for cve in filtered_cves]
        append_to_json_file(resumo_cves)
    else:
        print("[INFO] Nenhuma CVE corresponde aos critérios definidos.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[ABORTADO] Execução interrompida pelo usuário.")
        sys.exit(1)
