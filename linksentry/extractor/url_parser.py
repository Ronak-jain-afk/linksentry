from urllib.parse import urlparse


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
        'params': query,
    }
