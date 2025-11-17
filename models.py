# -------------------------------------------
# models.py  (100% WORKING)
# -------------------------------------------

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split


from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report
)
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neighbors import KNeighborsClassifier
import joblib
import os, json

TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

cols = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent',
    'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty_level'
]

def load_and_prepare():
    df_train = pd.read_csv(TRAIN_URL, names=cols)
    df_test = pd.read_csv(TEST_URL, names=cols)
    df = pd.concat([df_train, df_test], ignore_index=True)

    df.drop("difficulty_level", axis=1, inplace=True)

    # Binary classification
    df["label"] = df["label"].str.strip().str.lower().apply(lambda x: 0 if "normal" in x else 1)

    cat_cols = ["protocol_type", "service", "flag"]
    num_cols = [c for c in df.columns if c not in cat_cols + ["label"]]

    for col in num_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df.dropna(subset=num_cols, how="all", inplace=True)
    df["label"] = df["label"].astype(int)

    X = df.drop("label", axis=1)
    y = df["label"]

    return X, y, num_cols, cat_cols


def build_preprocessor(num_cols, cat_cols):
    return ColumnTransformer(
        transformers=[
            ('num', Pipeline([
                ('imputer', SimpleImputer(strategy='median')),
                ('scaler', StandardScaler())
            ]), num_cols),

            ('cat', Pipeline([
                ('imputer', SimpleImputer(strategy='most_frequent')),
                ('enc', OneHotEncoder(handle_unknown='ignore'))
            ]), cat_cols)
        ]
    )


def train_and_save_all():
    X, y, num_cols, cat_cols = load_and_prepare()
    pre = build_preprocessor(num_cols, cat_cols)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    models = {
        "logistic_regression": LogisticRegression(max_iter=500),
        "random_forest": RandomForestClassifier(n_estimators=120, random_state=42),
        "knn": KNeighborsClassifier(n_neighbors=5)
    }

    metrics_summary = {}
    best_acc = -1
    best_pipeline = None
    best_name = None

    for name, model in models.items():
        pipe = Pipeline([("pre", pre), ("clf", model)])
        pipe.fit(X_train, y_train)

        pred = pipe.predict(X_test)

        acc = accuracy_score(y_test, pred)
        prec = precision_score(y_test, pred)
        rec = recall_score(y_test, pred)
        f1 = f1_score(y_test, pred)

        try:
            prob = pipe.predict_proba(X_test)[:, 1]
            roc = roc_auc_score(y_test, prob)
        except:
            roc = None

        metrics_summary[name] = {
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1": float(f1),
            "roc_auc": float(roc) if roc else None
        }

        joblib.dump(pipe, f"{MODEL_DIR}/{name}_pipeline.joblib")

        if acc > best_acc:
            best_acc = acc
            best_name = name
            best_pipeline = pipe

    joblib.dump(best_pipeline, f"{MODEL_DIR}/best_pipeline.joblib")
    json.dump(list(models.keys()), open(f"{MODEL_DIR}/model_list.json", "w"))
    json.dump(metrics_summary, open(f"{MODEL_DIR}/metrics_summary.json", "w"), indent=2)

    # Isolation Forest
    num_pipe = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])
    X_num = num_pipe.fit_transform(X[num_cols])
    iso = IsolationForest(contamination=0.1, random_state=42)
    iso.fit(X_num)
    joblib.dump((num_pipe, iso), f"{MODEL_DIR}/isoforest.joblib")

# -----------------------------------------------------------
# BEHAVIORAL ANOMALY DETECTION (Isolation Forest)
# -----------------------------------------------------------

def train_behavioral_isolation_forest():
    print("Training Behavioral Isolation Forest...")

    df_train = pd.read_csv(TRAIN_URL, names=cols)
    df_test = pd.read_csv(TEST_URL, names=cols)
    df = pd.concat([df_train, df_test], ignore_index=True)

    df.drop("difficulty_level", axis=1, inplace=True)

    behavioral_features = [
        'num_failed_logins','logged_in','is_guest_login','is_host_login',
        'root_shell','su_attempted',
        'count','srv_count','duration','src_bytes','dst_bytes',
        'diff_srv_rate','same_srv_rate','srv_diff_host_rate',
        'dst_host_count','dst_host_diff_srv_rate',
        'serror_rate','srv_serror_rate','rerror_rate',
        'srv_rerror_rate','dst_host_serror_rate','dst_host_rerror_rate'
    ]

    # Numeric conversion
    for col in behavioral_features:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df.dropna(subset=behavioral_features, inplace=True)

    X = df[behavioral_features]

    # Simple preprocessing
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(contamination=0.10, random_state=42)
    iso.fit(X_scaled)

    joblib.dump((scaler, iso), f"{MODEL_DIR}/behavior_iso.joblib")
    print("Saved → models/behavior_iso.joblib")



def generate_geo_sample(n=1, center=(28.61, 77.21), radius_km=50):
    out = []
    lat0, lon0 = center
    for _ in range(n):
        d = np.random.random() * radius_km
        angle = np.random.random() * 360
        dlat = (d / 111) * np.cos(np.deg2rad(angle))
        dlon = (d / 111) * np.sin(np.deg2rad(angle)) / np.cos(np.deg2rad(lat0))
        out.append({"lat": float(lat0 + dlat), "lon": float(lon0 + dlon)})
    return out


if __name__ == "__main__":
    train_and_save_all()
    from app import train_attack_type_classifier
    train_attack_type_classifier()
    

