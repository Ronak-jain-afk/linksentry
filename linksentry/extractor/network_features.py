import ipaddress
import socket
import ssl
import time
from datetime import datetime
from urllib.parse import urlparse

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


def _resolve_host(hostname: str):
    try:
        return [addr[4][0] for addr in socket.getaddrinfo(hostname, 80)]
    except Exception:
        return []


def _is_private_host(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        for ip_str in _resolve_host(hostname):
            try:
                if ipaddress.ip_address(ip_str).is_private:
                    return True
            except ValueError:
                continue
    except Exception:
        pass
    return False


def get_response_time(url: str, timeout: int = 5) -> float:
    if not REQUESTS_AVAILABLE:
        return -1

    if _is_private_host(url):
        return -1

    try:
        start = time.time()
        requests.head(url, timeout=timeout, allow_redirects=False)
        return round(time.time() - start, 3)
    except Exception:
        return -1


def get_redirect_count(url: str, timeout: int = 5) -> int:
    if not REQUESTS_AVAILABLE:
        return -1

    if _is_private_host(url):
        return -1

    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        for redirect_url in response.history:
            if _is_private_host(redirect_url.url):
                return -1
        if _is_private_host(response.url):
            return -1
        return len(response.history)
    except Exception:
        return -1


def check_ssl_certificate(domain: str) -> int:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return 1 if cert else 0
    except Exception:
        return 0


def get_dns_info(domain: str) -> dict:
    info = {
        'qty_ip_resolved': -1,
        'qty_nameservers': -1,
        'qty_mx_servers': -1,
        'ttl_hostname': -1,
        'asn_ip': -1,
        'domain_spf': -1,
    }

    if not DNS_AVAILABLE:
        return info

    try:
        answers = dns.resolver.resolve(domain, 'A')
        info['qty_ip_resolved'] = len(answers)
        info['ttl_hostname'] = answers.rrset.ttl
    except Exception:
        pass

    try:
        ns_answers = dns.resolver.resolve(domain, 'NS')
        info['qty_nameservers'] = len(ns_answers)
    except Exception:
        pass

    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        info['qty_mx_servers'] = len(mx_answers)
    except Exception:
        pass

    try:
        txt_answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in txt_answers:
            if 'spf' in str(rdata).lower():
                info['domain_spf'] = 1
                break
        if info['domain_spf'] == -1:
            info['domain_spf'] = 0
    except Exception:
        pass

    return info


def get_whois_info(domain: str) -> dict:
    info = {
        'time_domain_activation': -1,
        'time_domain_expiration': -1,
    }

    if not WHOIS_AVAILABLE:
        return info

    try:
        w = whois.whois(domain)

        if w.creation_date:
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            days_since_creation = (datetime.now() - creation).days
            info['time_domain_activation'] = days_since_creation

        if w.expiration_date:
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            days_until_expiration = (expiration - datetime.now()).days
            info['time_domain_expiration'] = days_until_expiration
    except Exception:
        pass

    return info


def extract_external_features_default() -> dict:
    return {
        'time_response': -1,
        'domain_spf': -1,
        'asn_ip': -1,
        'time_domain_activation': -1,
        'time_domain_expiration': -1,
        'qty_ip_resolved': -1,
        'qty_nameservers': -1,
        'qty_mx_servers': -1,
        'ttl_hostname': -1,
        'tls_ssl_certificate': -1,
        'qty_redirects': -1,
        'url_google_index': -1,
        'domain_google_index': -1,
    }


def extract_external_features_full(url: str, domain: str) -> dict:
    features = {}

    features['time_response'] = get_response_time(url)
    features['qty_redirects'] = get_redirect_count(url)
    features['tls_ssl_certificate'] = check_ssl_certificate(domain)

    dns_info = get_dns_info(domain)
    features.update(dns_info)

    whois_info = get_whois_info(domain)
    features.update(whois_info)

    features['url_google_index'] = -1
    features['domain_google_index'] = -1

    return features
