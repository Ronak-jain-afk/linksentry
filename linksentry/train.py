import os
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.model_selection import train_test_split

from .preprocess import load_data, clean_data, split_features_labels, check_class_distribution
from .model import create_pipeline, evaluate_model, save_model


def get_default_model_path() -> Path:
    return Path(__file__).parent / "models" / "phishing_rf_model.pkl"


def train_model(
    data_path: str,
    output_path: Optional[str] = None,
    test_size: float = 0.2,
    random_state: int = 42
) -> dict:
    print("="*60)
    print("LINKSENTRY - MODEL TRAINING")
    print("="*60)
    
    df = load_data(data_path)
    df = clean_data(df)
    X, y = split_features_labels(df, target_col='phishing')
    check_class_distribution(y)
    
    print("\n--- Train-Test Split ---")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        stratify=y,
        random_state=random_state
    )
    print(f"Training set: {X_train.shape[0]:,} samples")
    print(f"Test set:     {X_test.shape[0]:,} samples")
    
    pipeline = create_pipeline()
    
    print("\n--- Training Model ---")
    print("Training in progress...")
    pipeline.fit(X_train, y_train)
    print("Training complete!")
    
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    
    metrics = evaluate_model(y_test, y_pred, y_proba)
    
    print("\n--- Top 10 Feature Importances ---")
    feature_names = X.columns.tolist()
    importances = pipeline.named_steps['classifier'].feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    
    top_features = []
    for rank, idx in enumerate(indices, 1):
        print(f"{rank:2d}. {feature_names[idx]:<30} {importances[idx]:.4f}")
        top_features.append({
            'rank': rank,
            'feature': feature_names[idx],
            'importance': float(importances[idx])
        })
    
    if output_path is None:
        output_path = str(get_default_model_path())
    
    save_model(pipeline, output_path)
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    
    return {
        'model_path': output_path,
        'metrics': metrics,
        'top_features': top_features,
        'train_samples': X_train.shape[0],
        'test_samples': X_test.shape[0]
    }
