# 🤖 AIOps: Automated Alert Severity Prediction

![Python](https://img.shields.io/badge/Python-3.9-blue)
![Status](https://img.shields.io/badge/Status-Prototype-green)
![Domain](https://img.shields.io/badge/Domain-AIOps%20%7C%20ITSM-orange)

## 📖 Project Overview
In modern IT Operations, "Alert Fatigue" is a critical issue. Network Operation Centers (NOCs) are flooded with thousands of alerts, making it difficult to identify genuine critical incidents.

This project utilizes **Machine Learning** to automatically predict the severity level of incoming IT alerts based on historical log data. By accurately classifying severity, organizations can:
* **Reduce Mean Time to Detect (MTTD)** for critical issues.
* Filter out noise (low-priority info logs).
* Automate ticket prioritization in ITSM tools like ServiceNow.



## 🛠️ Tech Stack
* **Language:** Python (Pandas, NumPy)
* **ML Libraries:** Scikit-Learn (Logistic Regression)
* **Visualization:** Matplotlib, Seaborn
* **Ops Context:** Zabbix / syslog data structures

## 📊 Methodology
1.  **Data Ingestion:** Processed historical alert logs (features: *host_name, alert, time_of_day, source_component*).
2.  **Preprocessing:** Applied NLP techniques (TF-IDF/Tokenization) to unstructured log messages.
3.  **Modeling:** Trained supervised classification models to predict severity (High, Medium, Low).
4.  **Evaluation:** Optimized for **Recall** on "High Severity" classes to ensure no critical incidents are missed.

## 📈 Key Results
* **Accuracy:** Achieved XX% accuracy on test data. (*Fill this in*)
* **Impact:** The model successfully distinguishes between "CPU Spike" (ignorable noise) and "Service Down" (critical) based on context.

## 🚀 How to Run
```bash
# Clone the repository
git clone [https://github.com/Thant-Zin-Bo/alert_severity_prediction.git](https://github.com/Thant-Zin-Bo/alert_severity_prediction.git)

# Install dependencies
pip install -r requirements.txt

# Run the notebook
jupyter notebook notebooks/Alert_Prediction_Main.ipynb
