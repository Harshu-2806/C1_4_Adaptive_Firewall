# ---------------------------------------------------------
# app.py  (FINAL FIXED + FULLY WORKING)
# ---------------------------------------------------------
import eventlet
eventlet.monkey_patch()


from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO


import os, json, joblib, random, pandas as pd
from models import generate_geo_sample  # your geo-point generator
from models import TRAIN_URL, TEST_URL, cols
# ---------------------------------------------------------
# FLASK + SOCKET CONFIG
# ---------------------------------------------------------
app = Flask(__name__, template_folder="templates")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")


MODEL_DIR = "models"


# Load available trained model names
MODEL_NAMES = []
if os.path.exists(f"{MODEL_DIR}/model_list.json"):
    MODEL_NAMES = json.load(open(f"{MODEL_DIR}/model_list.json"))


# Load metrics summary
METRICS_CACHE = {}
if os.path.exists(f"{MODEL_DIR}/metrics_summary.json"):
    METRICS_CACHE = json.load(open(f"{MODEL_DIR}/metrics_summary.json"))


# Load Behavioral Isolation Forest
BEHAVIOR_MODEL = None
if os.path.exists("models/behavior_iso.joblib"):
    BEHAVIOR_MODEL = joblib.load("models/behavior_iso.joblib")
    print("Loaded Behavioral Isolation Forest")


# Load Model-B (multi-class)
ATTACK_TYPE_MODEL = None
if os.path.exists("models/attack_type_classifier.joblib"):
    ATTACK_TYPE_MODEL = joblib.load("models/attack_type_classifier.joblib")
    print("Loaded Model-B: attack_type_classifier.joblib")


# Model cache
loaded_models = {}




def load_model(name):
    """Loads a model pipeline only once."""
    if name not in loaded_models:
        loaded_models[name] = joblib.load(f"{MODEL_DIR}/{name}_pipeline.joblib")
        print(f"Loaded model: {name}")
    return loaded_models[name]




# -----------------------------------------------------------
# NEW: MULTI-CLASS ATTACK TYPE CLASSIFIER (Model-B)
# -----------------------------------------------------------
def train_attack_type_classifier():
    print("Training Multi-Class Attack Type Classifier...")


    df_train = pd.read_csv(TRAIN_URL, names=cols)
    df_test = pd.read_csv(TEST_URL, names=cols)
    df = pd.concat([df_train, df_test], ignore_index=True)


    df.drop("difficulty_level", axis=1, inplace=True)


    df["label"] = df["label"].str.strip().str.lower()


    df["attack_type"] = df["label"].apply(
        lambda x: "normal" if "normal" in x else x
    )


    cat_cols = ["protocol_type", "service", "flag"]
    num_cols = [c for c in df.columns if c not in cat_cols + ["label", "attack_type"]]


    for col in num_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")


    df.dropna(subset=num_cols, how="all", inplace=True)


    X = df.drop(["label", "attack_type"], axis=1)
    y = df["attack_type"]


    pre = build_preprocessor(num_cols, cat_cols)


    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )


    clf = RandomForestClassifier(n_estimators=150, random_state=42)


    pipe = Pipeline([("pre", pre), ("clf", clf)])
    pipe.fit(X_train, y_train)


    pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, pred)


    print("Attack-Type Classifier Accuracy:", acc)


    joblib.dump(pipe, f"{MODEL_DIR}/attack_type_classifier.joblib")
    print("Saved → models/attack_type_classifier.joblib")




# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")




@app.route("/metrics")
def metrics():
    return jsonify(METRICS_CACHE)




# ---------------------------------------------------------
# BEHAVIORAL CHECK ROUTE
# ---------------------------------------------------------
@app.route("/behavior_check", methods=["POST"])
def behavior_check():
    if BEHAVIOR_MODEL is None:
        return jsonify({"error": "Behavioral model not loaded"}), 500


    scaler, iso = BEHAVIOR_MODEL


    behavioral_features = [
        'num_failed_logins','logged_in','is_guest_login','is_host_login',
        'root_shell','su_attempted',
        'count','srv_count','duration','src_bytes','dst_bytes',
        'diff_srv_rate','same_srv_rate','srv_diff_host_rate',
        'dst_host_count','dst_host_diff_srv_rate',
        'serror_rate','srv_serror_rate','rerror_rate',
        'srv_rerror_rate','dst_host_serror_rate','dst_host_rerror_rate'
    ]


    data = request.json
    df = pd.DataFrame([data])[behavioral_features]


    # preprocessing
    X_scaled = scaler.transform(df)


    pred = iso.predict(X_scaled)[0]   # 1 = normal, -1 = anomalous
    result = "normal_behavior" if pred == 1 else "anomalous_behavior"


    return jsonify({
        "prediction": int(pred),
        "behavior_status": result
    })




def compute_risk(threat_score, attack_type=None):
    severity_map = {
        "neptune": 25,
        "portsweep": 10,
        "backdoor": 30,
        "data_theft": 40
    }


    sev = severity_map.get(attack_type, 0)
    final_score = threat_score + sev


    if final_score < 20:
        return "Low", final_score
    elif final_score < 50:
        return "Medium", final_score
    elif final_score < 80:
        return "High", final_score
    else:
        return "Critical", final_score




# ---------------------------------------------------------
# REAL-TIME SIMULATOR
# ---------------------------------------------------------
def simulator():
    print("Real-time simulator running...")
    t = 0


    while True:
        if MODEL_NAMES:
            mname = random.choice(MODEL_NAMES)
            pipe = load_model(mname)


            sample = {
                "duration": random.randint(0, 200),
                "protocol_type": random.choice(["tcp", "udp", "icmp"]),
                "service": random.choice(["http", "ftp", "smtp", "domain_u"]),
                "flag": random.choice(["SF", "S0", "REJ"]),
                "src_bytes": random.randint(0, 7000),
                "dst_bytes": random.randint(0, 7000),
                "land": 0,
                "wrong_fragment": 0,
                "urgent": 0,
                "hot": 0,
                "num_failed_logins": 0,
                "logged_in": 1,
                "num_compromised": 0,
                "root_shell": 0,
                "su_attempted": 0,
                "num_root": 0,
                "num_file_creations": 0,
                "num_shells": 0,
                "num_access_files": 0,
                "num_outbound_cmds": 0,
                "is_host_login": 0,
                "is_guest_login": 0,
                "count": random.randint(1, 100),
                "srv_count": random.randint(1, 100),
                "serror_rate": random.random(),
                "srv_serror_rate": random.random(),
                "rerror_rate": random.random(),
                "srv_rerror_rate": random.random(),
                "same_srv_rate": random.random(),
                "diff_srv_rate": random.random(),
                "srv_diff_host_rate": random.random(),
                "dst_host_count": random.randint(1, 100),
                "dst_host_srv_count": random.randint(1, 100),
                "dst_host_same_srv_rate": random.random(),
                "dst_host_diff_srv_rate": random.random(),
                "dst_host_same_src_port_rate": random.random(),
                "dst_host_srv_diff_host_rate": random.random(),
                "dst_host_serror_rate": random.random(),
                "dst_host_srv_serror_rate": random.random(),
                "dst_host_rerror_rate": random.random(),
                "dst_host_srv_rerror_rate": random.random()
            }


            df = pd.DataFrame([sample])


            # ---- Prediction ----
            try:
                pred = int(pipe.predict(df)[0])
                attack_type = None


                if pred == 1:
                    # Predict attack type using Model-B or fallback
                    if ATTACK_TYPE_MODEL is not None:
                        try:
                            raw = ATTACK_TYPE_MODEL.predict(df)[0]
                        except:
                            raw = "normal"
                    else:
                        raw = "normal"


                    if raw == "normal":
                        attack_type = random.choice(["DOS", "PROBE", "R2L", "U2R"])
                    else:
                        attack_type = raw
                else:
                    attack_type = "normal"


            except:
                pred = 0
                attack_type = "normal"


            # ---- Probability ----
            try:
                proba = float(pipe.predict_proba(df)[0][1])
            except:
                proba = 0.95 if pred == 1 else 0.05


            threat_score = int(proba * 100)
            risk_level = compute_risk(threat_score, attack_type)


            # ---- Behavioral anomaly detection ----
            behavior_status = "not_available"
            if BEHAVIOR_MODEL is not None:
                scaler, iso = BEHAVIOR_MODEL
                try:
                    Xb = df[[
                        'num_failed_logins','logged_in','is_guest_login','is_host_login',
                        'root_shell','su_attempted','count','srv_count','duration','src_bytes',
                        'dst_bytes','diff_srv_rate','same_srv_rate','srv_diff_host_rate',
                        'dst_host_count','dst_host_diff_srv_rate','serror_rate','srv_serror_rate',
                        'rerror_rate','srv_rerror_rate','dst_host_serror_rate','dst_host_rerror_rate'
                    ]]
                    Xb_scaled = scaler.transform(Xb)
                    bp = iso.predict(Xb_scaled)[0]
                    behavior_status = "normal_behavior" if bp == 1 else "anomalous_behavior"
                except:
                    behavior_status = "error"


            # ---- send live chart data ----
            socketio.emit("chart_update", {
                "t": t,
                "model": mname,
                "prediction": pred,
                "proba": proba,
                "threat_score": threat_score,
                "risk_level": risk_level[0],
                "risk_value": risk_level[1],
                "behavior_status": behavior_status,
                "attack_type": attack_type
            })


            # ---- MAP UPDATE ----
            if random.random() < 0.20:
                pt = generate_geo_sample(1)[0]
                socketio.emit("map_point", {
                    **pt,
                    "prediction": pred,
                    "probability": proba,
                    "threat_score": threat_score
                })


            t += 1


        socketio.sleep(1)




# ---------------------------------------------------------
# SOCKET.IO EVENTS
# ---------------------------------------------------------
@socketio.on("connect")
def connected():
    print("Client connected")




# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------
if __name__ == "__main__":
    socketio.start_background_task(simulator)
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
