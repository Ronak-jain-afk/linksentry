import re
import socket
import ssl
import time
from urllib.parse import urlparse, parse_qs
from typing import Optional

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


SPECIAL_CHARS = [
    ('.', 'dot'),
    ('-', 'hyphen'),
    ('_', 'underline'),
    ('/', 'slash'),
    ('?', 'questionmark'),
    ('=', 'equal'),
    ('@', 'at'),
    ('&', 'and'),
    ('!', 'exclamation'),
    (' ', 'space'),
    ('~', 'tilde'),
    (',', 'comma'),
    ('+', 'plus'),
    ('*', 'asterisk'),
    ('#', 'hashtag'),
    ('$', 'dollar'),
    ('%', 'percent'),
]

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'shorte.st', 'short.io'
]


def count_char(text: str, char: str) -> int:
    return text.count(char)


def count_vowels(text: str) -> int:
    return sum(1 for c in text.lower() if c in 'aeiou')


def is_ip_address(domain: str) -> int:
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return 1 if re.match(ip_pattern, domain) else 0


def has_server_client(domain: str) -> int:
    keywords = ['server', 'client']
    return 1 if any(kw in domain.lower() for kw in keywords) else 0


def is_shortened_url(domain: str) -> int:
    return 1 if any(shortener in domain.lower() for shortener in SHORTENERS) else 0


def has_email_in_url(url: str) -> int:
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return 1 if re.search(email_pattern, url) else 0


def has_tld_in_params(params: str) -> int:
    tld_pattern = r'\.(com|net|org|info|biz|edu|gov|co|io|xyz|online|site)'
    return 1 if re.search(tld_pattern, params.lower()) else 0


def extract_url_components(url: str) -> dict:
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    
    domain = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    
    path_parts = path.rsplit('/', 1)
    if len(path_parts) > 1 and '.' in path_parts[1]:
        directory = path_parts[0]
        filename = path_parts[1]
    else:
        directory = path
        filename = ""
    
    return {
        'url': url,
        'domain': domain,
        'directory': directory,
        'file': filename,
        'params': query
    }


def extract_char_features(components: dict) -> dict:
    features = {}
    
    for char, name in SPECIAL_CHARS:
        features[f'qty_{name}_url'] = count_char(components['url'], char)
        features[f'qty_{name}_domain'] = count_char(components['domain'], char)
        
        if components['directory']:
            features[f'qty_{name}_directory'] = count_char(components['directory'], char)
        else:
            features[f'qty_{name}_directory'] = -1
        
        if components['file']:
            features[f'qty_{name}_file'] = count_char(components['file'], char)
        else:
            features[f'qty_{name}_file'] = -1
        
        if components['params']:
            features[f'qty_{name}_params'] = count_char(components['params'], char)
        else:
            features[f'qty_{name}_params'] = -1
    
    return features


def extract_length_features(components: dict) -> dict:
    features = {}
    
    features['qty_tld_url'] = 1
    features['length_url'] = len(components['url'])
    
    features['qty_vowels_domain'] = count_vowels(components['domain'])
    features['domain_length'] = len(components['domain'])
    features['domain_in_ip'] = is_ip_address(components['domain'])
    features['server_client_domain'] = has_server_client(components['domain'])
    
    if components['directory']:
        features['directory_length'] = len(components['directory'])
    else:
        features['directory_length'] = -1
    
    if components['file']:
        features['file_length'] = len(components['file'])
    else:
        features['file_length'] = -1
    
    if components['params']:
        features['params_length'] = len(components['params'])
        features['tld_present_params'] = has_tld_in_params(components['params'])
        features['qty_params'] = len(parse_qs(components['params']))
    else:
        features['params_length'] = -1
        features['tld_present_params'] = -1
        features['qty_params'] = -1
    
    features['email_in_url'] = has_email_in_url(components['url'])
    features['url_shortened'] = is_shortened_url(components['domain'])
    
    return features


def get_response_time(url: str, timeout: int = 5) -> float:
    if not REQUESTS_AVAILABLE:
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
    
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
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
        'domain_spf': -1
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
        'time_domain_expiration': -1
    }
    
    if not WHOIS_AVAILABLE:
        return info
    
    try:
        w = whois.whois(domain)
        
        if w.creation_date:
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            from datetime import datetime
            days_since_creation = (datetime.now() - creation).days
            info['time_domain_activation'] = days_since_creation
        
        if w.expiration_date:
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            from datetime import datetime
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
        'domain_google_index': -1
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


def extract_features(url: str, full: bool = False) -> dict:
    components = extract_url_components(url)
    
    features = {}
    
    char_features = extract_char_features(components)
    features.update(char_features)
    
    length_features = extract_length_features(components)
    features.update(length_features)
    
    if full:
        external_features = extract_external_features_full(url, components['domain'])
    else:
        external_features = extract_external_features_default()
    features.update(external_features)
    
    return features


FEATURE_ORDER = [
    'qty_dot_url', 'qty_hyphen_url', 'qty_underline_url', 'qty_slash_url',
    'qty_questionmark_url', 'qty_equal_url', 'qty_at_url', 'qty_and_url',
    'qty_exclamation_url', 'qty_space_url', 'qty_tilde_url', 'qty_comma_url',
    'qty_plus_url', 'qty_asterisk_url', 'qty_hashtag_url', 'qty_dollar_url',
    'qty_percent_url', 'qty_tld_url', 'length_url', 'qty_dot_domain',
    'qty_hyphen_domain', 'qty_underline_domain', 'qty_slash_domain',
    'qty_questionmark_domain', 'qty_equal_domain', 'qty_at_domain',
    'qty_and_domain', 'qty_exclamation_domain', 'qty_space_domain',
    'qty_tilde_domain', 'qty_comma_domain', 'qty_plus_domain',
    'qty_asterisk_domain', 'qty_hashtag_domain', 'qty_dollar_domain',
    'qty_percent_domain', 'qty_vowels_domain', 'domain_length', 'domain_in_ip',
    'server_client_domain', 'qty_dot_directory', 'qty_hyphen_directory',
    'qty_underline_directory', 'qty_slash_directory', 'qty_questionmark_directory',
    'qty_equal_directory', 'qty_at_directory', 'qty_and_directory',
    'qty_exclamation_directory', 'qty_space_directory', 'qty_tilde_directory',
    'qty_comma_directory', 'qty_plus_directory', 'qty_asterisk_directory',
    'qty_hashtag_directory', 'qty_dollar_directory', 'qty_percent_directory',
    'directory_length', 'qty_dot_file', 'qty_hyphen_file', 'qty_underline_file',
    'qty_slash_file', 'qty_questionmark_file', 'qty_equal_file', 'qty_at_file',
    'qty_and_file', 'qty_exclamation_file', 'qty_space_file', 'qty_tilde_file',
    'qty_comma_file', 'qty_plus_file', 'qty_asterisk_file', 'qty_hashtag_file',
    'qty_dollar_file', 'qty_percent_file', 'file_length', 'qty_dot_params',
    'qty_hyphen_params', 'qty_underline_params', 'qty_slash_params',
    'qty_questionmark_params', 'qty_equal_params', 'qty_at_params',
    'qty_and_params', 'qty_exclamation_params', 'qty_space_params',
    'qty_tilde_params', 'qty_comma_params', 'qty_plus_params',
    'qty_asterisk_params', 'qty_hashtag_params', 'qty_dollar_params',
    'qty_percent_params', 'params_length', 'tld_present_params', 'qty_params',
    'email_in_url', 'time_response', 'domain_spf', 'asn_ip',
    'time_domain_activation', 'time_domain_expiration', 'qty_ip_resolved',
    'qty_nameservers', 'qty_mx_servers', 'ttl_hostname', 'tls_ssl_certificate',
    'qty_redirects', 'url_google_index', 'domain_google_index', 'url_shortened'
]


def get_ordered_features(features: dict) -> dict:
    return {key: features.get(key, -1) for key in FEATURE_ORDER}
