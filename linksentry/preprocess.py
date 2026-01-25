import pandas as pd


def load_data(filepath: str) -> pd.DataFrame:
    print(f"Loading data from: {filepath}")
    df = pd.read_csv(filepath)
    print(f"Dataset shape: {df.shape}")
    return df


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    print("\n--- Data Cleaning ---")
    
    duplicates = df.duplicated().sum()
    print(f"Duplicate rows found: {duplicates}")
    
    if duplicates > 0:
        df = df.drop_duplicates()
        print(f"Shape after removing duplicates: {df.shape}")
    
    null_count = df.isnull().sum().sum()
    print(f"Null values in dataset: {null_count}")
    
    return df


def split_features_labels(df: pd.DataFrame, target_col: str = 'phishing'):
    print(f"\n--- Splitting Features & Labels ---")
    
    X = df.drop(columns=[target_col])
    y = df[target_col]
    
    print(f"Features shape: {X.shape}")
    print(f"Labels shape: {y.shape}")
    print(f"Feature columns: {X.columns.tolist()[:5]}... (showing first 5)")
    
    return X, y


def check_class_distribution(y: pd.Series):
    print("\n--- Class Distribution ---")
    
    counts = y.value_counts().sort_index()
    print(f"Class 0 (Legitimate): {counts[0]:,}")
    print(f"Class 1 (Phishing):   {counts[1]:,}")
    
    imbalance_ratio = counts[0] / counts[1]
    print(f"Imbalance ratio (0:1): {imbalance_ratio:.2f}:1")
    
    return counts
