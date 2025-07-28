import os
import re
import tweepy
import csv
import time
import argparse
import requests
from dotenv import load_dotenv

#Carrega variáveis do .env
load_dotenv()

#Argumentos de terminal
parser = argparse.ArgumentParser()
parser.add_argument("--max", type=int, default=10, help="Máximo de tweets por keyword (padrão: 10)")
parser.add_argument("--delay", type=int, default=60, help="Delay entre buscas (padrão: 60s)")
args = parser.parse_args()

#Autenticação Twitter API v2
bearer_token = os.getenv("TWITTER_BEARER_TOKEN")
if not bearer_token:
    raise Exception("[ERRO] TWITTER_BEARER_TOKEN não definido no .env")

client = tweepy.Client(bearer_token=bearer_token)

#Palavras-chave para IOC hunting
IOC_KEYWORDS = ["#malware", "#IOC", "phishing", "ransomware", "APT", "C2 server"]

#Palavras-chave para conteúdo Bug Bounty
BB_KEYWORDS = [
    "#bugbounty", "#infosec", "bug bounty report", "xss writeup",
    "rce writeup", "bypass auth", "CSP bypass", "SSRF trick", 
    "HackerOne report", "Bugcrowd finding", "recon tip", "web hacking"
]

#Padrões de IOCs
IOC_PATTERNS = {
    "ipv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "domain": r'\b(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,})\b',
    "sha256": r'\b[A-Fa-f0-9]{64}\b',
    "md5": r'\b[A-Fa-f0-9]{32}\b',
    "url": r'https?://[^\s]+'
}


def extract_iocs(text):
    iocs = {}
    for name, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            iocs[name] = matches
    return iocs


def search_tweets(query, max_results):
    try:
        tweets = client.search_recent_tweets(query=query, max_results=max_results, tweet_fields=["text"])
        return tweets.data if tweets.data else []
    except tweepy.errors.TooManyRequests as e:
        retry_after = int(e.response.headers.get('Retry-After', 60))
        print(f"[ERRO] Rate limit excedido. Esperando {retry_after} segundos...")
        time.sleep(retry_after)
        return search_tweets(query, max_results)
    except Exception as e:
        print(f"[ERRO] Falha ao buscar tweets: {e}")
        return []


def save_to_csv(data, output_file="iocs_collected.csv"):
    fieldnames = ["tweet"] + list(IOC_PATTERNS.keys())
    with open(output_file, "w", newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            writer.writerow({k: ", ".join(v) if isinstance(v, list) else v for k, v in row.items()})


def save_bugbounty_tweets(data, output_file="bugbounty_tweets.csv"):
    with open(output_file, "w", newline='', encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["keyword", "tweet"])
        writer.writeheader()
        for row in data:
            writer.writerow(row)


def send_slack_alert(ioc_data):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("[ERRO] SLACK_WEBHOOK_URL não definido no .env")
        return

    for ioc in ioc_data:
        tweet_text = ioc.get('tweet', '')[:400].replace('"', '\"')
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*IOC encontrado!*\n{tweet_text}"
                }
            },
            {"type": "divider"}
        ]

        for tipo, valores in ioc.items():
            if tipo == "tweet":
                continue
            if isinstance(valores, list):
                for val in valores:
                    blocks.append({
                        "type": "context",
                        "elements": [
                            {"type": "mrkdwn", "text": f"*{tipo.upper()}*: `{val}`"}
                        ]
                    })

        try:
            response = requests.post(webhook_url, json={"blocks": blocks})
            response.raise_for_status()
        except Exception as e:
            print(f"[ERRO] Falha ao enviar alerta pro Slack: {e}")


def send_slack_tips(data):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("[ERRO] SLACK_WEBHOOK_URL não definido no .env")
        return

    for tip in data:
        tweet_text = tip.get("tweet", "")[:400].replace('"', '\"')
        keyword = tip.get("keyword", "")
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Bug Bounty Tip!*\n> Palavra-chave: `{keyword}`\n\n{tweet_text}"
                }
            },
            {"type": "divider"}
        ]
        try:
            response = requests.post(webhook_url, json={"blocks": blocks})
            response.raise_for_status()
        except Exception as e:
            print(f"[ERRO] Falha ao enviar dica pro Slack: {e}")


def main():
    all_iocs = []
    bb_tweets = []

    # === IOC HUNTING ===
    for i, keyword in enumerate(IOC_KEYWORDS):
        print(f"\nBuscando IOCs com: {keyword}")
        tweets = search_tweets(keyword, max_results=args.max)

        if tweets:
            for tweet in tweets:
                iocs = extract_iocs(tweet.text)
                if iocs:
                    print(f"\nTweet: {tweet.text}\nIOCs extraídos: {iocs}")
                    all_iocs.append({"tweet": tweet.text, **iocs})

        if i < len(IOC_KEYWORDS) - 1:
            print(f"Esperando {args.delay} segundos...")
            time.sleep(args.delay)

    # === BUG BOUNTY CONTENT ===
    for i, keyword in enumerate(BB_KEYWORDS):
        print(f"\nBuscando conteúdo Bug Bounty: {keyword}")
        tweets = search_tweets(keyword, max_results=args.max)

        if tweets:
            for tweet in tweets:
                print(f"Tweet: {tweet.text}\n")
                bb_tweets.append({"keyword": keyword, "tweet": tweet.text})

        if i < len(BB_KEYWORDS) - 1:
            print(f"Aguardando {args.delay} segundos...")
            time.sleep(args.delay)

    # === OUTPUT ===
    if all_iocs:
        save_to_csv(all_iocs)
        send_slack_alert(all_iocs)
        print(f"\n{len(all_iocs)} IOCs salvos e enviados.")

    if bb_tweets:
        save_bugbounty_tweets(bb_tweets)
        send_slack_tips(bb_tweets)
        print(f"\n{len(bb_tweets)} dicas Bug Bounty salvas e enviadas.")


if __name__ == "__main__":
    main()
