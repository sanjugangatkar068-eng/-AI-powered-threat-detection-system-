import os
import re
import json
import pandas as pd
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from scapy.all import rdpcap
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)
app.secret_key = 'ai-threat-detection-2024'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

THREAT_SIGNATURES = {
    'sql_injection': {
        'patterns': [r'union\s+select.*from', r';\s*drop\s+table', r'1=1\s*--', r'or\s+1=1', r'information_schema'],
        'risk_level': 'Critical',
        'description': 'SQL Injection Attack'
    },
    'xss': {
        'patterns': [r'<script[^>]*>.*?</script>', r'javascript:', r'on\w+\s*=', r'<iframe[^>]*>', r'eval\s*\('],
        'risk_level': 'High',
        'description': 'Cross-Site Scripting (XSS)'
    },
    'command_injection': {
        'patterns': [r';\s*(ls|dir|cat|type|whoami|pwd)', r'\|\s*(ls|dir|cat|type|whoami|pwd)', r'`.*`', r'\$\(.*\)'],
        'risk_level': 'Critical',
        'description': 'Command Injection'
    },
    'path_traversal': {
        'patterns': [r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'etc/passwd', r'boot\.ini'],
        'risk_level': 'High',
        'description': 'Directory Path Traversal'
    }
}

class AIThreatDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.anomaly_model = IsolationForest(contamination=0.08, random_state=42, n_estimators=100)
        
    def signature_based_detection(self, text):
        if not text or not isinstance(text, str):
            return []
        detected = []
        text_lower = text.lower()
        for threat_type, config in THREAT_SIGNATURES.items():
            for pattern in config['patterns']:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    detected.append({
                        'threat_type': threat_type,
                        'risk_level': config['risk_level'],
                        'description': config['description'],
                        'pattern': pattern,
                        'evidence': text[:200] + '...' if len(text) > 200 else text,
                        'detection_method': 'AI Signature Match'
                    })
        return detected

    def ml_anomaly_detection(self, df):
        if df.empty or len(df) < 5:
            df['anomaly_score'] = 1
            df['ai_confidence'] = 0
            return df, False
        
        features = ['protocol', 'length', 'dst_port', 'src_port']
        for f in features:
            if f not in df.columns:
                df[f] = 0
        X = df[features].fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        df['anomaly_score'] = self.anomaly_model.fit_predict(X_scaled)
        df['ai_confidence'] = self.anomaly_model.decision_function(X_scaled)
        return df, True

    def classify_network_threat(self, row):
        if row['dst_port'] == 22 and row['length'] < 100:
            return 'SSH Brute Force', 'High'
        elif row['dst_port'] == 3389:
            return 'RDP Reconnaissance', 'High'
        elif row['dst_port'] == 445:
            return 'SMB Exploit Attempt', 'Critical'
        elif row['length'] > 1500:
            return 'Data Exfiltration', 'Medium'
        elif row['dst_port'] in [1433, 3306, 5432]:
            return 'Database Attack', 'High'
        else:
            return 'Network Anomaly', 'Low'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pcap', 'pcapng', 'cap', 'csv', 'json', 'txt', 'log'}

def parse_pcap_file(filepath):
    packets = rdpcap(filepath)
    data = []
    for pkt in packets:
        if pkt.haslayer('IP'):
            payload = ""
            if pkt.haslayer('Raw'):
                try: payload = pkt['Raw'].load.decode('utf-8', errors='ignore')
                except: payload = str(pkt['Raw'].load)[:500]
            data.append({
                'timestamp': float(pkt.time),
                'src_ip': pkt['IP'].src,
                'dst_ip': pkt['IP'].dst,
                'protocol': pkt['IP'].proto,
                'length': len(pkt),
                'src_port': pkt['TCP'].sport if pkt.haslayer('TCP') else (pkt['UDP'].sport if pkt.haslayer('UDP') else 0),
                'dst_port': pkt['TCP'].dport if pkt.haslayer('TCP') else (pkt['UDP'].dport if pkt.haslayer('UDP') else 0),
                'payload': payload
            })
    return pd.DataFrame(data) if data else None

def parse_log_file(filepath):
    data = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line: continue
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            ports = re.findall(r'port[:\s](\d+)', line.lower())
            data.append({
                'timestamp': idx,
                'src_ip': ips[0] if ips else f"10.0.0.{idx % 255}",
                'dst_ip': ips[1] if len(ips) > 1 else f"10.0.0.{(idx+1) % 255}",
                'protocol': 6,
                'length': len(line),
                'src_port': 0,
                'dst_port': int(ports[0]) if ports else 80,
                'payload': line
            })
    return pd.DataFrame(data) if data else None

def parse_json_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    df_data = []
    records = data if isinstance(data, list) else [data]
    
    for idx, item in enumerate(records):
        log_text = str(
            item.get('log') or 
            item.get('message') or 
            item.get('payload') or 
            item.get('raw') or
            item.get('data') or
            json.dumps(item)
        )
        
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_text)
        src_ip = item.get('src_ip', item.get('source_ip', ips[0] if ips else f"10.0.0.{idx % 255}"))
        dst_ip = item.get('dst_ip', item.get('dest_ip', item.get('destination_ip', ips[1] if len(ips) > 1 else f"10.0.0.{(idx+1) % 255}")))
        
        df_data.append({
            'timestamp': item.get('timestamp', idx),
            'src_ip': str(src_ip),
            'dst_ip': str(dst_ip),
            'protocol': int(item.get('protocol', 6)),
            'length': int(item.get('length', len(log_text))),
            'src_port': int(item.get('src_port', item.get('source_port', 0))),
            'dst_port': int(item.get('dst_port', item.get('dest_port', item.get('destination_port', 80)))),
            'payload': log_text
        })
    return pd.DataFrame(df_data) if df_data else None

detector = AIThreatDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    user_msg = request.json.get('message', '')
    
    system_prompt = """You are a cybersecurity assistant built into an AI-Powered Network Intrusion Detection System. 
    You help students understand threats like SQL injection, XSS, command injection, path traversal, and network anomalies. 
    Give short, technical answers under 100 words. If asked about scan results, explain you can describe attack types but don't have access to the current uploaded file."""
    
    try:
        response = requests.post('http://localhost:11434/api/generate', 
            json={
                'model': 'llama3.2:1b',
                'prompt': f"{system_prompt}\nUser: {user_msg}\nAssistant:",
                'stream': False
            },
            timeout=30)
        ai_reply = response.json()['response'].strip()
        return jsonify({'reply': ai_reply})
    except Exception as e:
        return jsonify({'reply': f'Chatbot offline. Make sure Ollama is running with: ollama serve'})

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            ext = filename.rsplit('.', 1)[1].lower()
            
            if ext in {'pcap', 'pcapng', 'cap'}:
                df = parse_pcap_file(filepath)
            elif ext == 'json':
                df = parse_json_file(filepath)
            else:
                df = parse_log_file(filepath)
            
            if df is None or df.empty:
                flash('No valid network data found in file', 'error')
                return redirect(url_for('index'))
            
            threats = []
            
            for idx, row in df.iterrows():
                sig_threats = detector.signature_based_detection(row['payload'])
                for threat in sig_threats:
                    threats.append({
                        'src_ip': row['src_ip'],
                        'dst_ip': row['dst_ip'],
                        'threat': threat['description'],
                        'risk_level': threat['risk_level'],
                        'evidence': threat['evidence'],
                        'ai_method': threat['detection_method'],
                        'confidence': 0.95
                    })
            
            df, ml_ran = detector.ml_anomaly_detection(df)
            
            if ml_ran:
                anomalies = df[df['anomaly_score'] == -1]
                for idx, row in anomalies.iterrows():
                    threat_name, risk = detector.classify_network_threat(row)
                    threats.append({
                        'src_ip': row['src_ip'],
                        'dst_ip': row['dst_ip'],
                        'threat': threat_name,
                        'risk_level': risk,
                        'evidence': f"Port {int(row['dst_port'])}, Size {int(row['length'])} bytes",
                        'ai_method': 'ML Anomaly Detection',
                        'confidence': abs(float(row['ai_confidence']))
                    })
            
            total_records = len(df)
            critical = len([t for t in threats if t['risk_level'] == 'Critical'])
            high = len([t for t in threats if t['risk_level'] == 'High'])
            
            if len(threats) == 0:
                ai_verdict = "SECURE: No threats detected. AI models found normal traffic patterns."
            elif critical > 0:
                ai_verdict = f"CRITICAL: {critical} critical threats detected. Immediate action required."
            elif high > 0:
                ai_verdict = f"HIGH RISK: {high} high-severity threats detected. Review recommended."
            else:
                ai_verdict = f"LOW RISK: {len(threats)} minor anomalies detected."
                
            if not ml_ran and len(threats) > 0:
                ai_verdict += " Note: ML anomaly detection skipped - need 5+ records."
                
        except Exception as e:
            flash(f'AI Analysis Error: {str(e)}', 'error')
            return redirect(url_for('index'))
        finally:
            if os.path.exists(filepath): os.remove(filepath)
            
        return render_template('results.html', 
                             filename=filename, 
                             total_records=total_records,
                             threats=threats,
                             ai_verdict=ai_verdict,
                             critical_count=critical,
                             high_count=high)
    
    flash('Invalid file type. Use.pcap,.csv,.txt,.log,.json', 'error')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
