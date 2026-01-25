import os
from pathlib import Path
from typing import Optional, Union

import pandas as pd
import joblib

from .extractor import extract_features, get_ordered_features, FEATURE_ORDER


def get_model_path() -> Path:
    return Path(__file__).parent / "models" / "phishing_rf_model.pkl"


def load_model(model_path: Optional[Union[str, Path]] = None):
    if model_path is None:
        model_path = get_model_path()
    
    model_path = Path(model_path)
    
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found at: {model_path}")
    
    return joblib.load(model_path)


def predict_url(url: str, model=None, full: bool = False) -> dict:
    if model is None:
        model = load_model()
    
    features = extract_features(url, full=full)
    ordered_features = get_ordered_features(features)
    
    df = pd.DataFrame([ordered_features])
    df = df[FEATURE_ORDER]
    
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]
    
    return {
        'url': url,
        'prediction': int(prediction),
        'label': 'phishing' if prediction == 1 else 'legitimate',
        'confidence': float(max(probability)),
        'probability_legitimate': float(probability[0]),
        'probability_phishing': float(probability[1]),
        'features_extracted': len(ordered_features)
    }


def predict_urls(urls: list, model=None, full: bool = False) -> list:
    if model is None:
        model = load_model()
    
    results = []
    for url in urls:
        try:
            result = predict_url(url, model=model, full=full)
            result['error'] = None
        except Exception as e:
            result = {
                'url': url,
                'prediction': None,
                'label': 'error',
                'confidence': None,
                'probability_legitimate': None,
                'probability_phishing': None,
                'features_extracted': None,
                'error': str(e)
            }
        results.append(result)
    
    return results


def predict_from_csv(csv_path: str, model=None, output_path: Optional[str] = None) -> pd.DataFrame:
    if model is None:
        model = load_model()
    
    df = pd.read_csv(csv_path)
    
    if 'phishing' in df.columns:
        df = df.drop(columns=['phishing'])
    
    predictions = model.predict(df)
    probabilities = model.predict_proba(df)
    
    results = pd.DataFrame({
        'prediction': predictions,
        'label': ['phishing' if p == 1 else 'legitimate' for p in predictions],
        'probability_legitimate': probabilities[:, 0],
        'probability_phishing': probabilities[:, 1]
    })
    
    if output_path:
        results.to_csv(output_path, index=False)
    
    return results
