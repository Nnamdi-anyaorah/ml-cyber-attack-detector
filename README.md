# 🛡️ ML Cyber Attack Detection System

Machine Learning-based Network Intrusion Detection System achieving **85% accuracy** using ensemble learning methods.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![ML](https://img.shields.io/badge/ML-Scikit--learn-orange)
![Accuracy](https://img.shields.io/badge/Accuracy-85%25-success)

## 🎯 Overview

Binary classification system that detects cyber attacks in network traffic using **Random Forest** and **Gradient Boosting** algorithms. Trained on real-world cybersecurity datasets with over 350,000 network flows.

## 📊 Performance Results

### UNSW-NB15 Dataset (257K flows)
- ✅ Random Forest: **79.78%**
- ✅ Gradient Boosting: **79.69%**

### CICIDS2017 Dataset (100K flows)
- ✅ Random Forest: **84.09%**
- ✅ Gradient Boosting: **84.92%** ⭐ Best Model

## 📊 Training

The models were trained using Jupyter notebooks:

- `notebooks/DataPreprocessing_ModelDev.ipynb` - Main training pipeline
- `notebooks/Data_Exploratory.ipynb` - Exploratory data analysis
- `notebooks/Data_Preprocessing.ipynb` - Data preprocessing steps

### Training Process:
1. Load UNSW-NB15 (257K flows) and CICIDS2017 (100K flows) datasets
2. Handle missing values and encode categorical features
3. Scale features using StandardScaler
4. Balance classes using SMOTE
5. Train Random Forest (200 trees) and Gradient Boosting models
6. Evaluate on test set and save models

### Results:
- UNSW-NB15: RF 79.78%, GB 79.69%
- CICIDS2017: RF 84.09%, GB 84.92%

## 🔧 Technologies Used

- **Python 3.13**
- **Scikit-learn** - Machine Learning
- **Pandas & NumPy** - Data Processing
- **SMOTE** - Class Balancing
- **Joblib** - Model Persistence

## 🚀 Features

- ✅ Real-time attack detection
- ✅ Multiple ML models (ensemble voting)
- ✅ Binary classification (Normal/Attack)
- ✅ 42-76 network traffic features
- ✅ Production-ready CLI tool
- ✅ Saved models for deployment

## 📁 Project Structure
```
ml-cyber-attack-detector/
├── cyber_attack_detector.py     # Main detection tool
├── models/                       # Trained models (6 files)
│   ├── random_forest_unsw.pkl
│   ├── gradient_boosting_unsw.pkl
│   ├── random_forest_cicids.pkl
│   ├── gradient_boosting_cicids.pkl
│   ├── scaler_unsw.pkl
│   └── scaler_cic.pkl
└── README.md
```

## 💻 Usage
```bash
# Run demo
python cyber_attack_detector.py
```
```python
# Use in code
from cyber_attack_detector import CyberAttackDetector

detector = CyberAttackDetector(models_dir='models')
detector.load_models()

# Detect attack
result = detector.detect_cicids(network_data)
print(result['gb_prediction'])  # 'ATTACK' or 'NORMAL'
print(f"Confidence: {result['gb_confidence']:.2f}%")
```

## 📚 Datasets

### UNSW-NB15
- **Source:** University of New South Wales, Australia
- **Size:** 257,673 network flows
- **Features:** 49 features (42 used)
- **Classes:** Normal, Exploits, DoS, Reconnaissance, etc.

### CICIDS2017
- **Source:** Canadian Institute for Cybersecurity
- **Size:** 100,000+ flows (sampled from 2.8M)
- **Features:** 78 features (76 used)
- **Classes:** BENIGN, DDoS, PortScan, Infiltration, etc.

## 🧠 ML Pipeline

1. **Data Loading** - Load UNSW-NB15 and CICIDS2017 datasets
2. **Preprocessing** - Handle missing values, encode categories
3. **Feature Engineering** - Select 42-76 network features
4. **Scaling** - StandardScaler normalization
5. **Balancing** - SMOTE for class imbalance
6. **Training** - Random Forest (200 trees) + Gradient Boosting
7. **Evaluation** - Accuracy, Precision, Recall, F1-Score
8. **Deployment** - Save models for production use

## 🎓 Academic Context

- **Project Type:** MSc Cybersecurity Dissertation
- **University:** University of Chester
- **Grade:** 99% accuracy (dissertation)
- **Purpose:** Real-world intrusion detection

## 👨‍💻 Author

**Nnamdi Victor Anyaorah**  
MSc Cybersecurity, University of Chester  
ISO 27001 ISMS Certified

## 📜 License

This project is for educational and portfolio purposes.

## 🔗 Related Projects

- [Port Scanner](https://github.com/[Nnamdi-anyaorah]/port-scanner)
- [Web Vulnerability Scanner](https://github.com/[Nnamdi-anyaorah]/web-vuln-scanner)
- [Password Security Suite](https://github.com/[Nnamdi-anyaorah]/password-security)

---

**⭐ If you find this project useful, please give it a star!**
