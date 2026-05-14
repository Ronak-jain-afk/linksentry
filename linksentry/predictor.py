from pathlib import Path
from typing import Optional, Union

import pandas as pd
import joblib

from .extractor import extract_features, get_ordered_features, FEATURE_ORDER, EXTERNAL_FEATURE_NAMES
from .model import load_manifest


def get_model_path(full: bool = False) -> Path:
    model_dir = Path(__file__).parent / "models"
    if full:
        return model_dir / "phishing_rf_model_full.pkl"
    return model_dir / "phishing_rf_model.pkl"


def load_model(model_path: Optional[Union[str, Path]] = None, full: bool = False):
    if model_path is None:
        model_path = get_model_path(full=full)
    
    model_path = Path(model_path)
    
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found at: {model_path}")
    
    return joblib.load(model_path)


def predict_url(url: str, model=None, full: bool = False, explain: bool = False) -> dict:
    if model is None:
        model = load_model(full=full)
    
    features = extract_features(url, full=full)
    ordered_features = get_ordered_features(features)
    
    df = pd.DataFrame([ordered_features])
    df = df[FEATURE_ORDER]
    
    if not full:
        cols_to_drop = [c for c in EXTERNAL_FEATURE_NAMES if c in df.columns]
        df = df.drop(columns=cols_to_drop)
    
    scaler = model.named_steps['scaler']
    model_feature_names = getattr(scaler, 'feature_names_in_', df.columns)
    df = df[list(model_feature_names)]
    
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]
    
    result = {
        'url': url,
        'prediction': int(prediction),
        'label': 'phishing' if prediction == 1 else 'legitimate',
        'confidence': float(max(probability)),
        'probability_legitimate': float(probability[0]),
        'probability_phishing': float(probability[1]),
        'features_extracted': df.shape[1],
        'error': None,
    }
    
    if explain:
        importances = model.named_steps['classifier'].feature_importances_
        feature_names_list = list(model_feature_names)
        contribs = []
        for name, imp in zip(feature_names_list, importances):
            val = float(df.iloc[0][name])
            contribs.append({
                'feature': name,
                'value': val,
                'importance': round(imp, 4),
            })
        contribs.sort(key=lambda x: x['importance'], reverse=True)
        result['top_features'] = contribs[:3]
    
    return result


def predict_urls(urls: list, model=None, full: bool = False, explain: bool = False) -> list:
    if model is None:
        model = load_model(full=full)
    
    results = []
    for url in urls:
        try:
            result = predict_url(url, model=model, full=full, explain=explain)
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
