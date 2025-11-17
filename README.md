ta-driven models.

 Features
 1. Binary Threat Detection (Attack / Normal)

Multiple ML models are trained (Random Forest, Logistic Regression, etc.)

Models are auto-loaded and compared

Predictions stream live to the UI

 2. Multi-Class Attack Type Classification

Uses an NSL-KDD trained Random Forest to classify attacks like:

DoS (Neptune, Smurf)

Probe (Portsweep, Nmap)

R2L (Guess_passwd, FTP_write)

U2R (Buffer_overflow, Rootkit)

3. Behavioral Anomaly Detection (Isolation Forest)

Detects unusual behavior based on:

login attempts

shell access

privilege escalation attempts

traffic volume & rates

Outputs either:
✔ normal_behavior
❌ anomalous_behavior

🛡️ 4. Threat Score & Dynamic Risk Level

Risk score = threat probability + attack severity
Firewall assigns:

🟢 Low

🟡 Medium

🟠 High

🔴 Critical

🌍 5. Real-Time Geo Map

Incoming packets get randomly assigned geolocation points → streamed live.

📡 6. Real-Time Streaming Dashboard

Built with Flask + Socket.IO, updating charts every second.

🧠 Dataset Used – NSL-KDD Dataset

Your system is trained on the NSL-KDD dataset, an improved version of KDD’99.

It includes:

41 features

Normal traffic + 39 attack types

4 attack categories (DoS, Probe, R2L, U2R)

Preprocessing includes:

✔ Numeric conversion
✔ One-hot encoding of protocol/service/flag
✔ Merging train & test
✔ Removing difficulty level
✔ Attack grouping into categories

🏗️ System Architecture
             +--------------------------+
             |      User Dashboard      |
             |  (HTML / JS / SocketIO)  |
             +------------+-------------+
                          |
                    Real-time Events
                          |
             +------------v-------------+
             |        Flask API         |
             |  +---------------------+ |
             |  | Threat Detection    | |
             |  | Attack Classifier   | |
             |  | Behavior Detector   | |
             |  +---------------------+ |
             +------------+-------------+
                          |
                   Machine Learning
         +-----------------+------------------+
         |   Binary Classifier (RF etc.)     |
         |   Attack-Type Classifier (RF)     |
         |   Behavioral Isolation Forest     |
         +----------------------------------+

📦 Directory Structure
adaptive-firewall/
│
├── app.py                     # Main backend + real-time streaming
├── models/
│   ├── attack_type_classifier.joblib
│   ├── behavior_iso.joblib
│   ├── model_list.json
│   ├── metrics_summary.json
│   ├── random_forest_pipeline.joblib
│   └── ...
│
├── templates/
│   ├── index.html
│   └── model_compare.html
│
├── static/
│   ├── main.js
│   ├── modelscompare.js
│   └── styles.css
│
├── precompute_metrics.py      # Generates accuracy, F1, precision, recall
├── model.py                   # Training models, pipelines
└── README.md

🧪 Machine Learning Models Used
1️⃣ Random Forest (Supervised)

Used for:

Binary attack prediction

Multi-class attack type classification

Why used:

Handles categorical + numeric well

Works on imbalanced data

Provides probability scores

Best accuracy for NSL-KDD

2️⃣ Isolation Forest (Unsupervised)

Used for behavior anomaly detection.

Why:

Works on unlabeled data

Detects novel attacks

Good for “unknown behavior”

3️⃣ Logistic Regression (Benchmark)

Used only for:

Baseline comparison

Probability estimates

4️⃣ KNN (Optional Benchmark)

Used only for metrics comparison.

💡 Risk Scoring Logic
Risk Score = Threat Score (0–100) + Attack Severity


Severity example:

neptune → 25
portsweep → 10
backdoor → 30
data_theft → 40


Risk Levels:

<20 → Low

<50 → Medium

<80 → High

else → Critical

🔌 API Endpoints
1. /behavior_check

Checks for behavioral anomaly
POST JSON:

{
 "num_failed_logins":0,
 "logged_in":1,
 "count":45,
 ...
}


Response:

{
 "prediction": 1,
 "behavior_status": "normal_behavior"
}

2. /metrics

Returns model accuracies.

▶️ How to Run
1. Install dependencies
pip install -r requirements.txt

2. Run the Flask server
python app.py

3. Open dashboard
http://localhost:5000

🎥 Screenshots (Add yourself)
/screenshots/dashboard.png
/screenshots/map.png
/screenshots/metrics.png

🛠️ Future Enhancements

Integrating real network sniffing (PCAP live feed)

Deploying on cloud firewall

Auto-blocking malicious IPs

Storing timeline of attacks

Email/SMS alerts

🤝 Contributing

Pull requests welcome!

📜 License

MIT License
