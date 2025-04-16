import os
import re
import tweepy
import csv
from dotenv import load_dotenv

# Load Twitter credentials
load_dotenv()
bearer_token = os.getenv("TWITTER_BEARER_TOKEN")

# Setup Tweepy client (v2)
client = tweepy.Client(bearer_token=bearer_token)

# Keywords to track
KEYWORDS = ["#malware", "#IOC", "phishing", "ransomware", "APT", "C2 server"]

# IOC regex patterns
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

def search_tweets(query, max_results=20):
    tweets = client.search_recent_tweets(query=query, max_results=max_results, tweet_fields=["text"])
    return tweets.data if tweets.data else []

def main():
    all_iocs = []

    for keyword in KEYWORDS:
        print(f"\n🔍 Searching tweets for: {keyword}")
        tweets = search_tweets(keyword)
        for tweet in tweets:
            iocs = extract_iocs(tweet.text)
            if iocs:
                print(f"\nTweet: {tweet.text}\nExtracted IOCs: {iocs}")
                all_iocs.append({"tweet": tweet.text, **iocs})

    # Save to CSV
    with open("iocs_collected.csv", "w", newline='', encoding='utf-8') as csvfile:
        fieldnames = ["tweet", "ipv4", "domain", "sha256", "md5", "url"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_iocs:
            writer.writerow({k: ", ".join(v) if isinstance(v, list) else v for k, v in row.items()})

if __name__ == "__main__":
    main()
