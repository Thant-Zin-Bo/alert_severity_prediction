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
## 🚀 How to Run

This project uses a sequential data pipeline to transform raw infrastructure logs into privacy-safe training data for the AI models.

### 1. Prerequisites
Ensure you have Python 3.8+ and the required libraries:

pip install pandas numpy scikit-learn matplotlib seaborn torch transformers
2. Data Pipeline Execution
Phase 1: Extraction & Parsing The hybrid extractor uses Regex and Heuristic NER to parse unstructured log messages from Alert_raw.csv.



# Ensure 'Alert_raw.csv' is in the root directory
python extract_hybrid.py

# ✅ Output: Creates 'out/alerts_with_fields_hybrid.csv'
Phase 2: Privacy Preservation (Pseudonymization) Before training, we mask sensitive infrastructure data (IP addresses, Hostnames, IDs) to ensure data privacy.



python psedonymize.py

# ✅ Output: Creates the final training set 'out/alerts_pseudo.csv'
3. Model Training & Analysis
Once the data is processed, you can reproduce the results using the provided Jupyter Notebooks:

📊 Exploratory Data Analysis: Run EDA.ipynb to visualize class imbalance and alert distribution patterns.

⚡ Baseline Model (Logistic Regression): Run train_logistic_regression.ipynb. This trains a lightweight TF-IDF model optimized for CPU inference.

Artifacts: Saves confusion matrix and metrics to artifacts/priority_model_lr.

🧠 Deep Learning Model (DistilBERT): Run train_distilbert.ipynb. This fine-tunes a Transformer model for context-aware severity classification.

Note: Training may take time on CPU. GPU is recommended but not required.
