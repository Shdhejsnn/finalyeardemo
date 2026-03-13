from __future__ import annotations


COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.in",
    "com.br",
    "com.mx",
    "co.jp",
}


def normalize_hostname(domain: str) -> str:
    hostname = (domain or "").strip().lower()
    if ":" in hostname:
        hostname = hostname.split(":", 1)[0]
    return hostname.strip(".")


def extract_registered_domain(domain: str) -> str:
    hostname = normalize_hostname(domain)
    parts = [part for part in hostname.split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)

    suffix = ".".join(parts[-2:])
    if suffix in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def extract_domain_label(domain: str) -> str:
    registered_domain = extract_registered_domain(domain)
    labels = registered_domain.split(".")
    if len(labels) >= 2:
        return labels[0]
    return registered_domain


def extract_subdomain_text(domain: str) -> str:
    hostname = normalize_hostname(domain)
    registered_domain = extract_registered_domain(hostname)
    if not hostname or not registered_domain or hostname == registered_domain:
        return ""

    suffix = f".{registered_domain}"
    if hostname.endswith(suffix):
        return hostname[: -len(suffix)]

    return ""
