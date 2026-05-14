import os
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score,
)

try:
    from xgboost import XGBClassifier
    _XGB_AVAILABLE = True
except ImportError:
    _XGB_AVAILABLE = False

try:
    from lightgbm import LGBMClassifier
    _LGB_AVAILABLE = True
except ImportError:
    _LGB_AVAILABLE = False


def _create_rf_pipeline() -> Pipeline:
    return Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', RandomForestClassifier(
            n_estimators=100,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        )),
    ])


def _create_xgb_pipeline() -> Pipeline:
    return Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', XGBClassifier(
            n_estimators=100,
            eval_metric='logloss',
            use_label_encoder=False,
            random_state=42,
            n_jobs=-1,
        )),
    ])


def _create_lgb_pipeline() -> Pipeline:
    return Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', LGBMClassifier(
            n_estimators=100,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
            verbose=-1,
        )),
    ])


_MODEL_BUILDERS = {
    'rf': ('RandomForest', _create_rf_pipeline),
    'xgb': ('XGBoost', _create_xgb_pipeline),
    'lgb': ('LightGBM', _create_lgb_pipeline),
}


MODEL_TYPES = tuple(_MODEL_BUILDERS.keys())


def create_pipeline(model_type: str = 'rf') -> Pipeline:
    model_type = model_type.lower()
    if model_type not in _MODEL_BUILDERS:
        valid = ', '.join(_MODEL_BUILDERS)
        raise ValueError(f"Unknown model type '{model_type}'. Valid: {valid}")

    name, builder = _MODEL_BUILDERS[model_type]
    print(f"\n--- Creating Pipeline ({name}) ---")
    pipeline = builder()
    print(f"Pipeline components: 1. StandardScaler  2. {name}")
    return pipeline


def evaluate_model(y_true, y_pred, y_proba=None) -> dict:
    print("\n" + "="*60)
    print("MODEL EVALUATION")
    print("="*60)
    
    acc = accuracy_score(y_true, y_pred)
    print(f"\nAccuracy: {acc:.4f} ({acc*100:.2f}%)")
    
    roc_auc = None
    if y_proba is not None:
        roc_auc = roc_auc_score(y_true, y_proba)
        print(f"ROC-AUC Score: {roc_auc:.4f}")
    
    print("\n--- Classification Report ---")
    print(classification_report(y_true, y_pred, 
                                target_names=['Legitimate (0)', 'Phishing (1)']))
    
    print("--- Confusion Matrix ---")
    cm = confusion_matrix(y_true, y_pred)
    print(f"\n                 Predicted")
    print(f"                 Legit  Phishing")
    print(f"Actual Legit    {cm[0,0]:6d}  {cm[0,1]:6d}")
    print(f"Actual Phishing {cm[1,0]:6d}  {cm[1,1]:6d}")
    
    tn, fp, fn, tp = cm.ravel()
    print(f"\nTrue Negatives (TN):  {tn:,} - Correctly identified legitimate")
    print(f"False Positives (FP): {fp:,} - Legitimate marked as phishing")
    print(f"False Negatives (FN): {fn:,} - Phishing marked as legitimate")
    print(f"True Positives (TP):  {tp:,} - Correctly identified phishing")
    
    return {
        'accuracy': acc,
        'roc_auc': roc_auc,
        'confusion_matrix': cm,
        'classification_report': classification_report(y_true, y_pred, output_dict=True)
    }


def save_model(pipeline: Pipeline, filepath: str):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    joblib.dump(pipeline, filepath)
    print(f"\nModel saved to: {filepath}")
