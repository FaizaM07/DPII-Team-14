# Network Intrusion Detection System (NIDS) using Machine Learning Using CIC_IDS_2017 Dataset

## Overview
This repository contains the implementation and full report of a **Network Intrusion Detection System (NIDS)** built using machine learning techniques on the **CIC-IDS-2017 dataset**.  
The goal of this project is to identify and classify network intrusions such as DDoS, brute-force and infiltration attacks using a combination of data preprocessing, feature engineering and supervised learning models.

The system integrates a **Flask-based web interface** for real-time prediction and a **trained machine learning backend** for automated threat detection.

---

## Authors

| Name | Student ID |
|------|-------------|
| Faiza Maliat | 210042163 |
| Namisa Najah Raisa | 210042112 |
| Ishmaam Iftekhar Khan | 210042125 |
---

## Supervisors

- **Dr. Md Moniruzzaman**, Assistant Professor, Department of CSE, Islamic University of Technology (IUT)  
- **Faisal Hussain**, Assistant Professor, Department of CSE, Islamic University of Technology (IUT)

---

## Project Description

### Objective
To design and develop a pure intrusion detection system capable of distinguishing between normal and malicious network traffic using machine learning algorithms. The system aims to achieve high detection accuracy and low false positive rates across multiple types of attacks.

### Key Contributions
- Preprocessing and analysis of the CIC-IDS-2017 dataset.
- Implementation and comparison of multiple ML classifiers (Random Forest, Logistic Regression, SVM, XGBoost, etc.).
- Flask-based web interface for real-time network intrusion prediction.
- Comprehensive model evaluation using confusion matrices, ROC-AUC scores and performance metrics.
- Full LaTeX-based research report prepared using the **iutbscthesis** class.

---

## Dataset

**CIC-IDS-2017 Dataset**  
Developed by the Canadian Institute for Cybersecurity, this dataset contains modern realistic network traffic with labeled attacks such as:
- DDoS  
- Port Scan  
- Brute Force  
- Infiltration  
- Botnet  
- Web Attack  

**Link:** [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

---

## System Architecture

```
            +----------------------+
            |   CIC-IDS-2017 CSVs  |
            +----------+-----------+
                       |
                       v
        +--------------------------------+
        | Data Preprocessing & Cleaning  |
        |  - Missing values              |
        |  - Encoding categorical data   |
        |  - Normalization               |
        +--------------------------------+
                       |
                       v
        +--------------------------------+
        |  Feature Engineering           |
        |  - Feature selection           |
        |  - Dimensionality reduction    |
        +--------------------------------+
                       |
                       v
        +--------------------------------+
        |  Model Training & Evaluation   |
        |  - Random Forest               |
        |  - Logistic Regression         |
        |  - SVM / XGBoost               |
        +--------------------------------+
                       |
                       v
        +--------------------------------+
        | Flask Web Application          |
        | - Real-time prediction         |
        | - JSON API endpoints           |
        +--------------------------------+
```

---

## Implementation Details

### Technologies Used

| Component | Technology |
|------------|-------------|
| **Language** | Python 3.x |
| **Web Framework** | Flask |
| **ML Libraries** | scikit-learn, pandas, numpy, xgboost |
| **Visualization** | matplotlib, seaborn |
| **Model Deployment** | Flask API |
| **Documentation** | LaTeX (`iutbscthesis.cls` template) |

---

## Project Structure

```
Network-Intrusion-Detection-System/
│
├── data/
│   ├── CICIDS2017/
│   ├── processed_data.csv
│   └── feature_selected.csv
│
├── notebooks/
│   ├── data_preprocessing.ipynb
│   ├── feature_engineering.ipynb
│   ├── model_training.ipynb
│   └── evaluation.ipynb
│
├── app/
│   ├── app.py
│   ├── model.pkl
│   ├── scaler.pkl
│   └── templates/
│       └── index.html
│
├── report/
│   ├── ids_report.tex
│   ├── citations.bib
│   ├── iutbscthesis.cls
│   └── figures/
│       ├── system_architecture.png
│       ├── confusion_matrix.png
│       ├── roc_curve.png
│       ├── feature_importance.png
│       └── github_activity.png
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Machine Learning Models Used

| Model | Accuracy | Precision | Recall | F1-Score |
|--------|-----------|------------|----------|-----------|
| Random Forest | 99.87% | 99.85% | 99.89% | 99.87% |
| XGBoost | 99.45% | 99.32% | 99.41% | 99.36% |
| Logistic Regression | 98.45% | 98.32% | 97.88% | 98.10% |
| SVM | 97.12% | 96.85% | 96.75% | 96.80% |



---

## Flask Web Application(Future Scope)

The **Flask web interface** allows users to upload network traffic samples in CSV format and receive real-time predictions.  

### Example Endpoints
| Endpoint | Method | Description |
|-----------|--------|-------------|
| `/` | GET | Home page |
| `/predict` | POST | Upload CSV file and get predictions |
| `/api/predict` | POST | JSON-based API for integration |

### Example Usage
```bash
curl -X POST -F "file=@sample.csv" http://127.0.0.1:5000/predict
```

---

## How to Run the Project

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/Network-Intrusion-Detection-System.git
cd Network-Intrusion-Detection-System
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate    # Linux/Mac
venv\Scripts\activate       # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Train Models (if needed)
Run Jupyter notebooks inside the notebook folder for preprocessing and training.

### 5. Start the Flask Server
```bash
cd app
python app.py
```

### 6. Access Application
Go to:  
[http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Report Compilation Guide

### Using Overleaf
1. Upload `main.tex`, `citations.bib`, and `iutbscthesis.cls`
2. Upload all figures inside `/report/figures/`
3. Compile using **pdfLaTeX** or **XeLaTeX**

### Using Local LaTeX
```bash
pdflatex main.tex
biber main
pdflatex main.tex
pdflatex main.tex
```

---

## References
The project cites over 25 academic papers related to:
- Intrusion Detection Systems (Denning 1987)
- DDoS attack analysis (Mirkovic & Reiher 2004)
- Machine Learning in Cybersecurity (Buczak & Guven 2016)
- CIC-IDS-2017 dataset (Sharafaldin et al. 2018)
- Random Forest algorithm (Breiman 2001)
- Deep learning IDS (Vinayakumar et al. 2017, Yin et al. 2017)

All citations are managed in `citations.bib` and formatted via **biblatex**.

---

## Results and Evaluation

### Example Figures
- System Architecture Diagram  
- Confusion Matrix  
- ROC-AUC Curves  
- Feature Importance Graphs  
- GitHub Contribution Graphs

All figures are located in `/report/figures/`.

---

## Future Improvements
- Integration with deep learning models (LSTM, CNN)
- Real-time traffic monitoring with packet sniffing
- Integration with SIEM tools
- Dockerized deployment for production environments
- REST API extension with authentication and logging

---


## Acknowledgements

We thank our supervisors Dr. Md. Moniruzzaman and Faisal Hussain, Assistant Professors at IUT, for their continuous guidance and support throughout the project.

---

## License
This project is intended for academic use as part of the B.Sc. thesis submission at **Islamic University of Technology (IUT)**.  
You may modify and extend it for educational and research purposes.



## Contact
For further queries or collaboration:

**Author**  
Email: faizamaliat@iut-dhaka.edu

  

