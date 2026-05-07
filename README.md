# Log Analyzer Web Application

## Overview
The Log Analyzer Web Application is a Python-based web system built using Flask for analyzing, visualizing, and monitoring log files. It supports multi-file uploads, real-time log streaming, statistical visualization, and basic security threat detection such as suspicious IP identification and brute-force attack detection.

The project follows a modular architecture to ensure scalability, maintainability, and ease of extension for future improvements in security analysis and system monitoring.

---

## Features

### Log Processing
- Upload and analyze multiple log files simultaneously
- Parse logs into severity levels: INFO, WARNING, ERROR
- Supports both timestamped and non-timestamped log formats
- Structured and modular log parsing system

### Data Visualization
- Interactive charts using Chart.js
- Visual breakdown of log statistics
- Dashboard-based analytics view

### Real-Time Monitoring
- Live log streaming using Flask-SocketIO
- Instant detection of new log entries
- Continuous monitoring capability

### Security Analysis
- Detection of suspicious IP addresses based on repeated failed login attempts
- Brute-force attack pattern detection
- Threat classification system (Normal, Suspicious, Critical)

### Reporting
- PDF report generation using ReportLab
- Includes log summary and security insights
- Downloadable reports for auditing and documentation

---

## Technology Stack

- Backend: Python, Flask  
- Frontend: HTML, CSS, Bootstrap, JavaScript  
- Visualization: Chart.js  
- Real-Time Communication: Flask-SocketIO  
- PDF Generation: ReportLab  

---

## Project Structure


log-analyser/

├── app.py

├── analyzer/

│ ├── parser.py

│ ├── stats.py

│ ├── monitor.py

│ └── security.py

├── templates/

│ └── index.html

├── static/

├── uploads/

├── reports/

└── requirements.txt


---

## Installation and Setup

### 1. Clone the repository

git clone https://github.com/your-username/log-analyzer.git

cd log-analyzer


### 2. Create virtual environment

python -m venv .venv


### 3. Activate virtual environment

Windows:

.venv\Scripts\activate


Linux / Mac:

source .venv/bin/activate


### 4. Install dependencies

pip install -r requirements.txt


### 5. Run the application

python app.py


### 6. Open in browser

http://127.0.0.1:10000


---

## Sample Log Types for Testing

- Standard application logs
- Authentication logs
- Brute-force attack simulation logs
- Mixed system and security logs

---

## Future Improvements

- Machine learning-based anomaly detection
- Integration with real-world server logs (Apache/Nginx)
- Role-based authentication system
- Advanced security dashboard with SIEM-like features
- Export logs to CSV, JSON, and Excel formats

---

## Author

This project was developed as a learning and portfolio project to strengthen skills in Python development, web applications, and cybersecurity fundamentals.
