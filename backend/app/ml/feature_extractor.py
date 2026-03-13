import re
import math
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login","secure","account","update","verify",
    "bank","paypal","signin","confirm","password"
]

SHORTENERS = [
    "bit.ly","tinyurl","goo.gl","t.co","ow.ly"
]

RISKY_TLDS = [
    ".tk",".ml",".ga",".cf",".gq",".top",".xyz",".work"
]


def shannon_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def extract_features(url: str):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path

    features = {}

    # URL length
    features["url_length"] = len(url)

    # IP usage
    features["has_ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", domain) else 0

    # HTTPS
    features["has_https"] = 1 if parsed.scheme == "https" else 0

    # subdomains
    features["num_subdomains"] = max(len(domain.split(".")) - 2, 0)

    # dots
    features["num_dots"] = url.count(".")

    # hyphens
    features["num_hyphens"] = url.count("-")

    # digits
    features["num_digits"] = sum(c.isdigit() for c in url)

    # parameters
    features["num_params"] = url.count("?")

    # path length
    features["path_length"] = len(path)

    # domain length
    features["domain_length"] = len(domain)

    # suspicious keywords
    features["suspicious_words"] = sum(word in url for word in SUSPICIOUS_WORDS)

    # url shorteners
    features["shortener_used"] = any(short in url for short in SHORTENERS)

    # risky TLD
    features["risky_tld"] = any(domain.endswith(tld) for tld in RISKY_TLDS)

    # domain entropy (random-looking domains)
    features["domain_entropy"] = shannon_entropy(domain)

    # digit ratio
    digits = sum(c.isdigit() for c in domain)
    letters = sum(c.isalpha() for c in domain)

    if letters > 0:
        features["digit_ratio"] = digits / letters
    else:
        features["digit_ratio"] = 0

    return features