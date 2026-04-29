# 🛡️ AI-NIDS: AI-Powered Network Intrusion Detection System

Real-time threat detection using **Isolation Forest ML** + **Llama 3.2 LLM**. Detects SQL injection, XSS, command injection, and zero-day anomalies in network traffic. Features a local AI chatbot for threat explanations.

![Demo](https://img.shields.io/badge/AI-Powered-00f5a0?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask)
![Ollama](https://img.shields.io/badge/Ollama-Llama3.2-000000?style=for-the-badge)

## ✨ Features

- **ML Anomaly Detection**: Isolation Forest algorithm catches unknown threats & zero-day attacks
- **Signature-Based AI**: Detects SQL Injection, XSS, Command Injection, Path Traversal
- **Local LLM Chatbot**: Llama 3.2 explains threats in plain English. 100% offline via Ollama
- **Risk Scoring**: Auto-classifies threats as Critical/High/Medium/Low with AI confidence %
- **Modern UI**: Aesthetic glassmorphism dashboard with real-time results
- **Multi-format Support**: Analyzes `.pcap`, `.csv`, `.log`, `.json`, `.txt` files

## 🧠 AI Stack

| Component | Technology | Purpose |
| --- | --- | --- |
| **Anomaly Detection** | Scikit-learn `IsolationForest` | Unsupervised ML to flag statistical outliers |
| **LLM Chatbot** | `Llama 3.2:1b` via Ollama | Explains threats, answers security questions |
| **Backend** | Flask + Python | API server, file processing, ML inference |
| **Frontend** | HTML/CSS/JS | Interactive dashboard + chatbot widget |

## 🚀 Quick Start

### 1. Prerequisites
```bash
# Install Python 3.10+ and Ollama
https://ollama.ai/download

SETUP:
git clone https://github.com/yourusername/AI-NIDS.git
cd AI-NIDS
# Install Python dependencies
pip install flask scikit-learn pandas requests
# Download LLM model (one time)
ollama pull llama3.2:1b

upload(empty storage space)

RUN:
# Terminal 1: Start Ollama
ollama serve
# Terminal 2: Start Flask app
python app.py

PROJECT STRUCTURE:
<img width="513" height="181" alt="image" src="https://github.com/user-attachments/assets/c5f57570-84a1-44a7-a4a9-ae818a169ba6" />

MIT LICENSE:(Educational use)
1. **Under 350 chars repo description** is already in your last reply
2. **README covers**: Features, AI stack, setup, how it works, privacy
3. **Badges** make it look professional for your demo
4. **Table format** clearly shows the 2 AI systems you used

Replace `SANJANA H S` with your GitHub username before pushing.


