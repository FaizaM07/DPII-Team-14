# DDoS detection system with Machine Learning Using CIC_IDS_2017 Dataset

## Overview
This repository contains the implementation and full report of a *DDoS Detection System* built using machine learning techniques on the *CIC-IDS-2017 dataset*.  
The goal of this project is to identify and classify network intrusions such as DDoS using a combination of data preprocessing, feature engineering and supervised learning models.

The system integrates a *Flask-based web interface* for real-time prediction and a *trained machine learning backend* for automated threat detection.

---

## Authors

| Name | Student ID |
|------|-------------|
| Faiza Maliat | 210042163 |
| Namisa Najah Raisa | 210042112 |
| Ishmaam Iftekhar Khan | 210042125 |


## Supervisors

- *Dr. Md Moniruzzaman*, Assistant Professor, Department of CSE, Islamic University of Technology (IUT)  
- *Faisal Hussain*, Assistant Professor, Department of CSE, Islamic University of Technology (IUT)

---

## Project Description

### Objective
To design and develop a pure DDoS detection system capable of distinguishing between normal and malicious network traffic using machine learning algorithms. The system aims to achieve high detection accuracy and low false positive rates across DDoS attacks.

### Key Contributions
- Preprocessing and analysis of the CIC-IDS-2017 dataset.
- Implementation and comparison of multiple ML classifiers (Random Forest, Logistic Regression and Neural Network).
- Flask-based web interface for real-time network intrusion prediction.
- Comprehensive model evaluation using confusion matrices, ROC-AUC scores and performance metrics.

---

## Dataset

*CIC-IDS-2017 Dataset*  
Developed by the Canadian Institute for Cybersecurity, this dataset contains modern realistic network traffic with labeled attacks such as:
- DDoS  
- Port Scan  
- Brute Force  
- Infiltration  
- Botnet  
- Web Attack  

*Link:* [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

The dataset was processed to filter only the DDoS attacks.
---

## System Architecture

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
        |  - Neural Network              |
        +--------------------------------+
                       |
                       v
        +-------------------------------------+
        | Flask Web Application               |
        | - Real-time Network packets capture |
        | - JSON API endpoints                | 
        +-------------------------------------+

---

## Implementation Details

### Technologies Used

| Component | Technology |
|------------|-------------|
| *Language* | Python 3.x |
| *Web Framework* | Flask |
| *ML Libraries* | scikit-learn, pandas, numpy |
| *Visualization* | matplotlib, seaborn |
| *Model Deployment* | Flask API |
| *Documentation* | LaTeX template |

---

## Project Structure

Network-Intrusion-Detection-System/
│
├── data/
│   ├── CICIDS2017/
│   ├── DDos.csv
│
├── notebooks/
│   ├── radnom_forest.ipynb
│
├── app/
│   ├── app.py
│   └── templates/
│       └── index.html
|       └── base.html
│       └── error.html
|       └── results.html
│
├── requirements.txt
├── README.md
└── .gitignore

---

## Machine Learning Models Used

| Model | Accuracy | Precision | Recall | F1-Score |
|--------|-----------|------------|----------|-----------|
| Random Forest | 99.95% | 100% | 99.90% | 99.95% |
| Logistic Regression | 94.39% | 90.85% | 99.36% | 94.92% |
| Neural Network | 98.24% | 99.22% | 97.43% | 98.32% |



---

## Flask Web Application

The *Flask web interface* allows users to capture network traffic samples with PyShark and receive real-time predictions.  

### Example Endpoints
| Endpoint | Method | Description |
|-----------|--------|-------------|
| / | GET | Home page |
| /predict | POST | JSON-based API for integration |

---

## How to Run the Project

### 1. Clone the Repository
git clone https://github.com/N4M154/DPII-Team-14.git

### 2. Create Virtual Environment
python -m venv venv
source venv/bin/activate    # Linux/Mac
venv\Scripts\activate       # Windows

### 3. Install Dependencies
pip install -r requirements.txt

### 4. Train Models (if needed)
Run Jupyter notebook inside the notebook folder for preprocessing, training and getting the model.

### 5. Start the Flask Server
cd app
python app.py

### 6. Access Application
Go to:  
[http://127.0.0.1:5000](http://127.0.0.1:5000)

### 7. Send multiple requests at once
for ($i = 1; $i -le 50; $i++) {
    curl.exe -s -X POST -H "Accept: application/json" http://127.0.0.1:5000/predict | Out-Null
}
[change the loop number for however many request you want to send]

---

## References
The project cites over 25 academic papers related to:
- Intrusion Detection Systems (Denning 1987)
- DDoS attack analysis (Mirkovic & Reiher 2004)
- Machine Learning in Cybersecurity (Buczak & Guven 2016)
- CIC-IDS-2017 dataset (Sharafaldin et al. 2018)
- Random Forest algorithm (Breiman 2001)
- Deep learning IDS (Vinayakumar et al. 2017, Yin et al. 2017)

All citations are managed in citations.bib and formatted via *biblatex*.

---

## Results and Evaluation

### Example Figures
- System Architecture Diagram  
- Confusion Matrix  
- ROC-AUC Curves  
- Feature Importance Graphs  
- GitHub Contribution Graphs

All figures are located in /report/figures/.

---

## Future Scope
- Integration with deep learning models
- Integration with SIEM tools
- Dockerized deployment for production environments
---


## Acknowledgements

We thank our supervisors *Dr. Md. Moniruzzaman* and *Faisal Hussain*, *Assistant Professors at IUT*, for their continuous guidance and support throughout the project.

---

## License
This project is intended for academic use as part of the B.Sc. thesis submission at *Islamic University of Technology (IUT)*
