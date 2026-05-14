# LinkSentry

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://linksentry.streamlit.app)

A CLI tool and web UI to detect phishing URLs using machine learning.

## Quick Start

```bash
pip install linksentry

# Check a URL
linksentry check "https://example.com"

# Launch the web UI
linksentry web
```

Or try the hosted web UI at **[linksentry.streamlit.app](https://linksentry.streamlit.app)**

## Features

- **Web UI** — Streamlit dashboard at `linksentry web` (or [hosted](https://linksentry.streamlit.app))
- **Single URL Check** — Analyze any URL with optional explainable predictions
- **Batch Processing** — Check multiple URLs from a file, export results as CSV
- **Watch Mode** — `linksentry watch urls.txt --interval 300` — periodic rechecking with change detection
- **ML-Powered** — RandomForest, XGBoost, or LightGBM trained on 57k+ URLs with 111 features
- **DNS/WHOIS/SSL** — Optional deep analysis with `--full` flag
- **Feature Explorer** — Inspect all 111 extracted features for any URL
- **Configurable** — TOML config file at `~/.config/linksentry/config.toml`
- **Multiple Outputs** — Plain text, JSON, or CSV

## Installation

```bash
pip install linksentry
```

### Optional extras

```bash
pip install linksentry[full]     # DNS/WHOIS lookups
pip install linksentry[xgb]      # XGBoost model support
pip install linksentry[lgb]      # LightGBM model support
pip install linksentry[web]      # Streamlit web UI
pip install linksentry[all]      # everything above
```

## Usage

### Single URL

```bash
linksentry check "https://example.com"
linksentry check "https://example.com" --full    # with DNS/WHOIS
linksentry check "https://example.com" --explain # show top features
linksentry check "https://example.com" --json    # JSON output
```

### Batch check

```bash
linksentry check-file urls.txt
linksentry check-file urls.txt --output results.csv
linksentry check-file urls.txt --full --json
```

### Watch mode

```bash
linksentry watch urls.txt --interval 60
linksentry watch urls.txt --interval 300 --full
```

### Train a custom model

```bash
linksentry train --data dataset.csv                        # RandomForest
linksentry train --data dataset.csv --model xgb            # XGBoost
linksentry train --data dataset.csv --model lgb --full     # LightGBM (full mode)
```

### Extract features to CSV

```bash
linksentry extract urls.txt --output features.csv
```

### Web UI

```bash
linksentry web
# opens http://localhost:8501
```

### Config

```bash
linksentry config init
linksentry config show
```

## Model Performance

| Model | Mode | Accuracy | ROC-AUC |
|-------|------|----------|---------|
| RandomForest | Basic | 90.85% | 0.9664 |
| XGBoost | Basic | 90.44% | 0.9676 |
| LightGBM | Basic | 90.09% | 0.9655 |
| RandomForest | Full | 95.76% | 0.9913 |

## Feature Extraction

111 features across 7 categories:

| Category | Count | Description |
|----------|-------|-------------|
| URL Characters | 17 | Count of special characters (., -, _, /, ?, etc.) in full URL |
| Domain | 21 | Domain length, character counts, IP address check |
| Directory | 18 | Path structure analysis |
| File | 17 | Filename analysis |
| Parameters | 20 | Query string analysis |
| Email/Shortener | 2 | Email in URL, URL shortener detection |
| External* | 13 | DNS, WHOIS, SSL certificate, response time, redirects |

*External features require `--full` flag and `linksentry[full]` installation.

## Python API

```python
from linksentry import predict_url, extract_features

# Predict a URL
result = predict_url("https://example.com", explain=True)
print(result['label'], result['confidence'])
print(result['top_features'])  # top 3 features by importance

# Extract features
features = extract_features("https://example.com", full=True)
```

## Architecture

```
linksentry/
  cli.py          # CLI commands: check, watch, train, extract, web, config, info
  predictor.py    # URL prediction, model loading, parallel batch processing
  train.py        # Model training pipeline
  model.py        # Pipeline builders (RF/XGBoost/LightGBM), evaluation, manifest
  preprocess.py   # Data loading and cleaning
  config.py       # TOML configuration
  cache.py        # Disk cache for DNS/WHOIS/HTTP results
  extractor/      # Feature extraction package
    __init__.py
    url_parser.py
    char_features.py
    network_features.py   # DNS, WHOIS, SSL, HTTP, SSRF guard
  app.py          # Streamlit web UI
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | URL is legitimate |
| 1 | URL is phishing (or at least one in batch) |
| 2 | Error occurred |

## License

MIT
