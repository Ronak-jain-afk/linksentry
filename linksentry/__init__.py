__version__ = "0.1.1"
__author__ = "Ronak"
__description__ = "A CLI tool to detect phishing URLs using machine learning"

from .predictor import predict_url, load_model
from .extractor import extract_features

__all__ = ["predict_url", "load_model", "extract_features", "__version__"]
