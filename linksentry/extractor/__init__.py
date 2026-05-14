from .url_parser import extract_url_components
from .char_features import (
    SPECIAL_CHARS,
    SHORTENERS,
    count_char,
    count_vowels,
    is_ip_address,
    has_server_client,
    is_shortened_url,
    has_email_in_url,
    has_tld_in_params,
    extract_char_features,
    extract_length_features,
)
from .network_features import (
    DNS_AVAILABLE,
    WHOIS_AVAILABLE,
    REQUESTS_AVAILABLE,
    get_response_time,
    get_redirect_count,
    check_ssl_certificate,
    get_dns_info,
    get_whois_info,
    extract_external_features_default,
    extract_external_features_full,
)


EXTERNAL_FEATURE_NAMES = {
    'time_response', 'domain_spf', 'asn_ip',
    'time_domain_activation', 'time_domain_expiration', 'qty_ip_resolved',
    'qty_nameservers', 'qty_mx_servers', 'ttl_hostname', 'tls_ssl_certificate',
    'qty_redirects', 'url_google_index', 'domain_google_index',
}


def extract_features(url: str, full: bool = False) -> dict:
    components = extract_url_components(url)

    features = {}
    features.update(extract_char_features(components))
    features.update(extract_length_features(components))

    if full:
        features.update(extract_external_features_full(url, components['domain']))
    else:
        features.update(extract_external_features_default())

    return features


def _generate_feature_order() -> list:
    dummy_url = "http://example.com/path/file.txt?query=value&a=1"
    return list(extract_features(dummy_url, full=False))


FEATURE_ORDER = _generate_feature_order()


def get_ordered_features(features: dict) -> dict:
    return {key: features.get(key, -1) for key in FEATURE_ORDER}


__all__ = [
    "extract_features", "get_ordered_features", "FEATURE_ORDER",
    "EXTERNAL_FEATURE_NAMES", "extract_url_components",
    "extract_char_features", "extract_length_features",
    "extract_external_features_default", "extract_external_features_full",
    "is_ip_address", "is_shortened_url",
]
