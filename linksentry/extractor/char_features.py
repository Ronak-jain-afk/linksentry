import ipaddress
import re
from urllib.parse import parse_qs

from .url_parser import extract_url_components


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
    'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'shorte.st', 'short.io',
]


def count_char(text: str, char: str) -> int:
    return text.count(char)


def count_vowels(text: str) -> int:
    return sum(1 for c in text.lower() if c in 'aeiou')


def is_ip_address(domain: str) -> int:
    try:
        ipaddress.ip_address(domain)
        return 1
    except ValueError:
        return 0


def has_server_client(domain: str) -> int:
    keywords = ['server', 'client']
    return 1 if any(kw in domain.lower() for kw in keywords) else 0


def is_shortened_url(domain: str) -> int:
    domain_lower = domain.lower()
    for shortener in SHORTENERS:
        if domain_lower == shortener or domain_lower.endswith('.' + shortener):
            return 1
    return 0


def has_email_in_url(url: str) -> int:
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return 1 if re.search(email_pattern, url) else 0


def has_tld_in_params(params: str) -> int:
    tld_pattern = r'\.(com|net|org|info|biz|edu|gov|co|io|xyz|online|site)'
    return 1 if re.search(tld_pattern, params.lower()) else 0


def extract_char_features(components: dict) -> dict:
    features = {}

    for char, name in SPECIAL_CHARS:
        features[f'qty_{name}_url'] = count_char(components['url'], char)

    for char, name in SPECIAL_CHARS:
        features[f'qty_{name}_domain'] = count_char(components['domain'], char)

    for char, name in SPECIAL_CHARS:
        if components['directory']:
            features[f'qty_{name}_directory'] = count_char(components['directory'], char)
        else:
            features[f'qty_{name}_directory'] = -1

    for char, name in SPECIAL_CHARS:
        if components['file']:
            features[f'qty_{name}_file'] = count_char(components['file'], char)
        else:
            features[f'qty_{name}_file'] = -1

    for char, name in SPECIAL_CHARS:
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
