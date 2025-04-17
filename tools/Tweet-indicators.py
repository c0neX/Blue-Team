import os
import re
import tweepy
import csv
from dotenv import load_dotenv
import time

# Load Twitter credentials from .env file
load_dotenv()
bearer_token = os.getenv("TWITTER_BEARER_TOKEN")

# Setup Tweepy client (v2) using the bearer token
client = tweepy.Client(bearer_token=bearer_token)

# Keywords to track for Indicator of Compromise (IOC) searches
KEYWORDS = ["#malware", "#IOC", "phishing", "ransomware", "APT", "C2 server"]

# Regular expression patterns to identify different types of IOCs
IOC_PATTERNS = {
    "ipv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "domain": r'\b(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,})\b',
    "sha256": r'\b[A-Fa-f0-9]{64}\b',
    "md5": r'\b[A-Fa-f0-9]{32}\b',
    "url": r'https?://[^\s]+'
}

def extract_iocs(text):
    """
    Extracts Indicators of Compromise (IOCs) from a given text based on predefined regex patterns.
    Returns a dictionary where keys are IOC types and values are lists of found IOCs.
    """
    iocs = {}
    for name, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            iocs[name] = matches
    return iocs

def search_tweets(query, max_results=20):
    """
    Searches recent tweets based on a given query using the Twitter API.
    Handles potential TooManyRequests errors by waiting and retrying.
    This function is designed to be used with the Free Tier of the Twitter API.
    """
    try:
        tweets = client.search_recent_tweets(query=query, max_results=max_results, tweet_fields=["text"])
        return tweets.data if tweets.data else []
    except tweepy.errors.TooManyRequests as e:
        print(f"Rate limit error detected: {e}")
        retry_after = int(e.response.headers.get('Retry-After', 60)) # Get suggested wait time
        print(f"Waiting {retry_after} seconds before retrying...")
        time.sleep(retry_after)
        return search_tweets(query, max_results) # Retry after waiting
    except Exception as e:
        print(f"An error occurred while searching tweets: {e}")
        return []

def main():
    """
    Main function to iterate through keywords, search for tweets, extract IOCs, and save them to a CSV file.
    Implements delays between searches to respect the Twitter API Free Tier rate limits.
    """
    all_iocs = []

    for i, keyword in enumerate(KEYWORDS):
        print(f"\n🔍 Searching tweets for: {keyword}")
        tweets = search_tweets(keyword, max_results=10) # Limiting max results for Free Tier
        if tweets:
            for tweet in tweets:
                iocs = extract_iocs(tweet.text)
                if iocs:
                    print(f"\nTweet: {tweet.text}\nExtracted IOCs: {iocs}")
                    all_iocs.append({"tweet": tweet.text, **iocs})

        if i < len(KEYWORDS) - 1:
            wait_time = 60  # Wait time in seconds to respect Free Tier rate limits
            print(f"Waiting {wait_time} seconds before searching for the next keyword...")
            time.sleep(wait_time)

    # Save the collected IOCs to a CSV file
    with open("iocs_collected.csv", "w", newline='', encoding='utf-8') as csvfile:
        fieldnames = ["tweet", "ipv4", "domain", "sha256", "md5", "url"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_iocs:
            writer.writerow({k: ", ".join(v) if isinstance(v, list) else v for k, v in row.items()})

if __name__ == "__main__":
    main()
