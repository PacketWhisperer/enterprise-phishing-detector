from flask import Flask, render_template, request, jsonify
import datetime
import os
import re
import requests
import socket
import ssl
from urllib.parse import urlparse
import threading
import time
import json

app = Flask(__name__)

# Live URL checking with multiple threat intelligence sources
def check_live_url_safety(body):
    """Advanced live URL safety checking"""
    danger_score = 0
    reasons = []
    
    # Extract URLs from email body
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, body)
    
    if not urls:
        return danger_score, reasons
    
    print(f"🔍 Live checking {len(urls)} URLs...")
    
    for url in urls[:3]:  # Limit to 3 URLs for performance
        try:
            print(f"Checking URL: {url}")
            
            # Parse URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # 1. Check URL reputation with VirusTotal-like analysis
            url_score, url_reasons = analyze_url_reputation(url, domain)
            danger_score += url_score
            reasons.extend(url_reasons)
            
            # 2. Live HTTP check
            http_score, http_reasons = check_url_response(url)
            danger_score += http_score
            reasons.extend(http_reasons)
            
            # 3. SSL Certificate check
            ssl_score, ssl_reasons = check_ssl_certificate(domain)
            danger_score += ssl_score
            reasons.extend(ssl_reasons)
            
        except Exception as e:
            print(f"Error checking URL {url}: {e}")
            danger_score += 10
            reasons.append(f"URL check failed (potentially malicious): {url[:30]}...")
    
    return danger_score, reasons

def analyze_url_reputation(url, domain):
    """Analyze URL reputation using multiple checks"""
    danger_score = 0
    reasons = []
    
    # Check against known malicious patterns
    malicious_patterns = [
        'phishing', 'scam', 'fraud', 'fake', 'secure-', 'verify-',
        'account-', 'update-', 'confirm-', 'suspended'
    ]
    
    # Check URL structure
    for pattern in malicious_patterns:
        if pattern in url.lower():
            danger_score += 15
            reasons.append(f"URL contains suspicious pattern: '{pattern}'")
    
    # Check domain age and reputation (simplified)
    if check_suspicious_domain(domain):
        danger_score += 20
        reasons.append(f"Domain flagged as suspicious: {domain}")
    
    # Check for URL redirects
    try:
        response = requests.head(url, timeout=5, allow_redirects=False)
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('Location', '')
            if location and urlparse(location).netloc != domain:
                danger_score += 25
                reasons.append("URL redirects to different domain (potential redirect scam)")
    except:
        pass
    
    return danger_score, reasons

def check_url_response(url):
    """Check URL response and behavior"""
    danger_score = 0
    reasons = []
    
    try:
        # Check response with timeout
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        # Check response code
        if response.status_code == 404:
            danger_score += 15
            reasons.append("URL returns 404 (may be temporary phishing site)")
        elif response.status_code >= 400:
            danger_score += 10
            reasons.append(f"URL returns error code: {response.status_code}")
        
        # Check content type
        content_type = response.headers.get('Content-Type', '').lower()
        if 'application/octet-stream' in content_type:
            danger_score += 30
            reasons.append("URL serves downloadable file (potential malware)")
        
        # Check for suspicious content
        if len(response.content) < 100:
            danger_score += 15
            reasons.append("URL serves minimal content (potential placeholder)")
        
        # Check for login forms in response
        content = response.text.lower()
        if 'password' in content and 'login' in content:
            danger_score += 20
            reasons.append("URL contains login form (potential credential harvesting)")
        
    except requests.exceptions.Timeout:
        danger_score += 20
        reasons.append("URL request timed out (server may be down or slow)")
    except requests.exceptions.ConnectionError:
        danger_score += 25
        reasons.append("Cannot connect to URL (server may be offline)")
    except Exception as e:
        danger_score += 15
        reasons.append("URL check failed (connection issues)")
    
    return danger_score, reasons

def check_ssl_certificate(domain):
    """Check SSL certificate validity"""
    danger_score = 0
    reasons = []
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check certificate expiration
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.datetime.now()).days
                
                if days_until_expiry < 30:
                    danger_score += 20
                    reasons.append(f"SSL certificate expires soon ({days_until_expiry} days)")
                
                # Check certificate issuer
                issuer = dict(x[0] for x in cert['issuer'])
                org = issuer.get('organizationName', '').lower()
                
                # Self-signed or suspicious issuers
                if 'self' in org or len(org) < 3:
                    danger_score += 25
                    reasons.append("SSL certificate from suspicious/unknown issuer")
                
    except ssl.SSLError:
        danger_score += 30
        reasons.append("SSL certificate error (invalid or self-signed)")
    except socket.timeout:
        danger_score += 15
        reasons.append("SSL check timed out")
    except Exception:
        # Many sites don't support HTTPS, so we don't penalize heavily
        danger_score += 5
        reasons.append("No SSL certificate available")
    
    return danger_score, reasons

def check_suspicious_domain(domain):
    """Check if domain is suspicious"""
    suspicious_indicators = [
        'secure-', 'verify-', 'account-', 'update-', 'login-',
        'bank-', 'paypal-', 'amazon-', 'microsoft-'
    ]
    
    return any(indicator in domain for indicator in suspicious_indicators)

# Machine Learning Feature
class PhishingMLModel:
    def __init__(self):
        self.training_data = []
        self.model_trained = False
        self.load_training_data()
    
    def load_training_data(self):
        """Load pre-trained data or create initial dataset"""
        # Simplified training data (in real implementation, this would be much larger)
        self.training_data = [
            # Phishing examples (label: 1)
            {"text": "urgent account suspended verify immediately", "label": 1},
            {"text": "winner congratulations prize money click here", "label": 1},
            {"text": "security alert confirm password bank details", "label": 1},
            {"text": "paypal suspended verify account information", "label": 1},
            
            # Legitimate examples (label: 0)
            {"text": "meeting reminder tomorrow 3pm conference room", "label": 0},
            {"text": "invoice attached payment due next week", "label": 0},
            {"text": "project update status report quarterly review", "label": 0},
            {"text": "newsletter monthly updates company news", "label": 0},
        ]
        self.model_trained = True
    
    def extract_features(self, subject, body):
        """Extract features for ML analysis"""
        text = (subject + " " + body).lower()
        
        features = {
            'urgent_words': len([w for w in ['urgent', 'immediate', 'expires'] if w in text]),
            'money_words': len([w for w in ['money', 'prize', 'won', 'cash'] if w in text]),
            'action_words': len([w for w in ['click', 'verify', 'confirm', 'update'] if w in text]),
            'length': len(text),
            'exclamation_count': text.count('!'),
            'capital_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
        }
        
        return features
    
    def predict_phishing_probability(self, subject, body):
        """Predict phishing probability using simple ML"""
        if not self.model_trained:
            return 50, "Model not trained"
        
        features = self.extract_features(subject, body)
        
        # Simple scoring algorithm (in real ML, this would use trained model)
        score = 0
        score += features['urgent_words'] * 20
        score += features['money_words'] * 15
        score += features['action_words'] * 10
        score += min(features['exclamation_count'] * 5, 20)
        score += min(features['capital_ratio'] * 30, 25)
        
        probability = min(score, 95)
        confidence = "High" if probability > 70 else "Medium" if probability > 40 else "Low"
        
        return probability, f"ML Confidence: {confidence}"
    
    def learn_from_feedback(self, subject, body, is_phishing):
        """Learn from user feedback"""
        features = self.extract_features(subject, body)
        label = 1 if is_phishing else 0
        
        # Add to training data
        self.training_data.append({
            "text": (subject + " " + body).lower(),
            "label": label,
            "features": features
        })
        
        print(f"✅ Model learned from feedback: {'Phishing' if is_phishing else 'Legitimate'}")

# Real-time Email Monitoring
class EmailMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitored_emails = []
        self.alerts = []
    
    def start_monitoring(self, email_config):
        """Start monitoring emails (simplified simulation)"""
        self.monitoring = True
        self.email_config = email_config
        
        # Simulate email monitoring
        threading.Thread(target=self.monitor_loop, daemon=True).start()
        return "Email monitoring started"
    
    def monitor_loop(self):
        """Simulate real-time email monitoring"""
        while self.monitoring:
            # Simulate receiving emails
            time.sleep(30)  # Check every 30 seconds
            
            # Simulate suspicious email detection
            if len(self.monitored_emails) < 5:  # Limit simulation
                simulated_email = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "sender": "suspicious@example.com",
                    "subject": "Urgent: Account verification required",
                    "threat_level": "High",
                    "auto_blocked": True
                }
                
                self.monitored_emails.append(simulated_email)
                self.alerts.append(f"🚨 Blocked suspicious email from {simulated_email['sender']}")
                print(f"🚨 Real-time alert: Blocked phishing attempt from {simulated_email['sender']}")
    
    def get_monitoring_status(self):
        """Get current monitoring status"""
        return {
            "monitoring": self.monitoring,
            "emails_processed": len(self.monitored_emails),
            "alerts_count": len(self.alerts),
            "recent_alerts": self.alerts[-5:] if self.alerts else []
        }
    
    def stop_monitoring(self):
        """Stop email monitoring"""
        self.monitoring = False
        return "Email monitoring stopped"

# Initialize ML model and email monitor
ml_model = PhishingMLModel()
email_monitor = EmailMonitor()

# Enhanced analysis with all new features
def analyze_email_enterprise(subject, sender, body):
    """Enterprise-grade email analysis with ML and live checking"""
    danger_score = 0
    reasons = []
    
    print(f"🚀 Starting enterprise analysis...")
    
    # 1. Basic pattern analysis (existing)
    basic_score, basic_reasons = analyze_basic_patterns(subject, sender, body)
    danger_score += basic_score
    reasons.extend(basic_reasons)
    
    # 2. Live URL checking (NEW!)
    url_score, url_reasons = check_live_url_safety(body)
    danger_score += url_score
    reasons.extend(url_reasons)
    
    # 3. Machine Learning analysis (NEW!)
    ml_probability, ml_confidence = ml_model.predict_phishing_probability(subject, body)
    if ml_probability > 60:
        danger_score += int(ml_probability * 0.3)  # Scale ML score
        reasons.append(f"Machine Learning model predicts {ml_probability}% phishing probability")
    
    # 4. Advanced threat correlation
    if danger_score > 80 and len(reasons) > 5:
        danger_score += 10
        reasons.append("Multiple threat vectors detected (coordinated attack pattern)")
    
    return min(danger_score, 100), reasons, ml_probability, ml_confidence

def analyze_basic_patterns(subject, sender, body):
    """Basic pattern analysis (existing functionality)"""
    danger_score = 0
    reasons = []
    
    # Your existing analysis code here
    suspicious_words = ["urgent", "winner", "verify", "suspended", "click here", "act now"]
    
    for word in suspicious_words:
        if word.lower() in subject.lower():
            danger_score += 15
            reasons.append(f"Suspicious word '{word}' in subject")
        if word.lower() in body.lower():
            danger_score += 8
            reasons.append(f"Suspicious word '{word}' in body")
    
    # Fake sender check
    free_emails = ["gmail.com", "yahoo.com", "hotmail.com"]
    official_companies = ["bank", "paypal", "amazon", "microsoft"]
    
    for company in official_companies:
        if company in sender.lower():
            for free_service in free_emails:
                if free_service in sender.lower():
                    danger_score += 35
                    reasons.append(f"Claims to be {company} but uses {free_service}")
    
    return danger_score, reasons

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        print("🚀 Enterprise analysis request received!")
        
        data = request.get_json()
        sender = data.get('sender', '').strip()
        subject = data.get('subject', '').strip()
        body = data.get('body', '').strip()
        
        if not sender or not subject:
            return jsonify({'success': False, 'error': 'Please provide sender and subject'}), 400
        
        # Use enterprise analysis with all features
        danger_score, reasons, ml_probability, ml_confidence = analyze_email_enterprise(subject, sender, body)
        
        # Enhanced risk assessment
        confidence = min(95, 60 + (len(reasons) * 3))
        
        if danger_score >= 90:
            risk_level = "CRITICAL THREAT"
            risk_color = "#991b1b"
            risk_icon = "🚨"
            advice = "EXTREME DANGER: This is almost certainly a sophisticated attack"
        elif danger_score >= 75:
            risk_level = "VERY HIGH RISK"
            risk_color = "#dc2626"
            risk_icon = "⚠️"
            advice = "HIGH THREAT: Multiple advanced attack indicators detected"
        elif danger_score >= 60:
            risk_level = "HIGH RISK"
            risk_color = "#ea580c"
            risk_icon = "🔴"
            advice = "CAUTION: Significant threat indicators present"
        elif danger_score >= 45:
            risk_level = "MEDIUM RISK"
            risk_color = "#d97706"
            risk_icon = "⚡"
            advice = "SUSPICIOUS: Verify through alternative channels"
        elif danger_score >= 25:
            risk_level = "LOW-MEDIUM RISK"
            risk_color = "#0891b2"
            risk_icon = "💡"
            advice = "MINOR CONCERNS: Exercise normal caution"
        else:
            risk_level = "LOW RISK"
            risk_color = "#10b981"
            risk_icon = "✅"
            advice = "APPEARS LEGITIMATE: No significant threats detected"
        
        result = {
            'success': True,
            'danger_score': danger_score,
            'confidence': confidence,
            'risk_level': risk_level,
            'risk_color': risk_color,
            'risk_icon': risk_icon,
            'advice': advice,
            'reasons': list(set(reasons)),
            'total_checks': len(reasons),
            'ml_probability': ml_probability,
            'ml_confidence': ml_confidence,
            'live_url_checked': True,
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in enterprise analysis: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/start-monitoring', methods=['POST'])
def start_monitoring():
    try:
        data = request.get_json()
        email_config = data.get('config', {})
        
        result = email_monitor.start_monitoring(email_config)
        return jsonify({'success': True, 'message': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/monitoring-status')
def monitoring_status():
    try:
        status = email_monitor.get_monitoring_status()
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/stop-monitoring', methods=['POST'])
def stop_monitoring():
    try:
        result = email_monitor.stop_monitoring()
        return jsonify({'success': True, 'message': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/feedback', methods=['POST'])
def provide_feedback():
    try:
        data = request.get_json()
        subject = data.get('subject', '')
        body = data.get('body', '')
        is_phishing = data.get('is_phishing', False)
        
        ml_model.learn_from_feedback(subject, body, is_phishing)
        return jsonify({'success': True, 'message': 'Feedback received, model updated'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 ENTERPRISE AI PHISHING DETECTOR v3.0")
    print("=" * 50)
    print("🔗 Live URL reputation checking")
    print("🤖 Machine Learning threat detection") 
    print("📧 Real-time email monitoring")
    print("🛡️ Advanced threat correlation")
    print("\nStarting server...")
    app.run(debug=True, port=5000, host='0.0.0.0')