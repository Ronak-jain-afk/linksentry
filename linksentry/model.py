import os
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score
)


def create_pipeline() -> Pipeline:
    print("\n--- Creating Pipeline ---")
    
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', RandomForestClassifier(
            n_estimators=100,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        ))
    ])
    
    print("Pipeline components:")
    print("  1. StandardScaler (normalize features)")
    print("  2. RandomForestClassifier (n_estimators=100, class_weight='balanced')")
    
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
