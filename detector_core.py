# Move our detector functions to a separate file for the web app
import datetime

def check_suspicious_sender(sender):
    """Check if sender looks fake"""
    danger_score = 0
    reasons = []
    
    free_emails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
    official_companies = ["bank", "paypal", "amazon", "microsoft", "apple", "visa", "ebay", "netflix", "google"]
    
    for company in official_companies:
        if company in sender.lower():
            for free_service in free_emails:
                if free_service in sender.lower():
                    danger_score += 35
                    reasons.append(f"Claims to be {company} but uses {free_service}")
    
    return danger_score, reasons

def check_urgent_language(subject, body):
    """Check for urgent pressure tactics"""
    danger_score = 0
    reasons = []
    
    urgent_phrases = ["urgent", "immediately", "act now", "expires today", "limited time", 
                     "hurry", "final notice", "last chance", "expire soon", "within 24 hours"]
    
    urgent_count = 0
    for phrase in urgent_phrases:
        if phrase.lower() in subject.lower() or phrase.lower() in body.lower():
            urgent_count += 1
    
    if urgent_count >= 2:
        danger_score += 30
        reasons.append("Multiple urgent pressure tactics detected")
    elif urgent_count == 1:
        danger_score += 20
        reasons.append("Uses urgent pressure tactics")
    
    return danger_score, reasons

def check_money_scam_indicators(subject, body):
    """Check for money/prize scam patterns"""
    danger_score = 0
    reasons = []
    
    money_words = ["$", "money", "cash", "prize", "won", "winner", "lottery", 
                   "inheritance", "million", "billion", "reward", "jackpot"]
    
    money_count = 0
    text_to_check = (subject + " " + body).lower()
    
    for word in money_words:
        if word.lower() in text_to_check:
            money_count += 1
    
    if money_count >= 3:
        danger_score += 40
        reasons.append(f"Heavy money/prize focus ({money_count} mentions)")
    elif money_count >= 2:
        danger_score += 25
        reasons.append("Multiple money/prize mentions")
    
    return danger_score, reasons

def check_suspicious_links(body):
    """Check for suspicious links"""
    danger_score = 0
    reasons = []
    
    suspicious_patterns = ["http://", "bit.ly", "tinyurl", "t.co", "short.link", 
                          "click here", "clickhere"]
    
    for pattern in suspicious_patterns:
        if pattern in body.lower():
            danger_score += 15
            reasons.append("Contains suspicious or shortened links")
            break
    
    return danger_score, reasons

def analyze_email(subject, sender, body):
    """Complete email analysis"""
    danger_score = 0
    all_reasons = []
    
    # Basic suspicious words
    suspicious_words = ["winner", "congratulations", "verify", "suspended", "confirm", 
                       "update", "security", "account", "password", "login"]
    
    for word in suspicious_words:
        if word.lower() in subject.lower():
            danger_score += 12
            all_reasons.append(f"Suspicious word '{word}' in subject")
        if word.lower() in body.lower():
            danger_score += 6
            all_reasons.append(f"Suspicious word '{word}' in body")
    
    # Run specialized checks
    sender_score, sender_reasons = check_suspicious_sender(sender)
    urgent_score, urgent_reasons = check_urgent_language(subject, body)
    money_score, money_reasons = check_money_scam_indicators(subject, body)
    link_score, link_reasons = check_suspicious_links(body)
    
    # Combine scores
    total_score = danger_score + sender_score + urgent_score + money_score + link_score
    all_reasons.extend(sender_reasons + urgent_reasons + money_reasons + link_reasons)
    
    return min(total_score, 100), all_reasons  # Cap at 100

def save_analysis(sender, subject, body, danger_score, reasons):
    """Save analysis to file"""
    try:
        filename = "web_phishing_analysis.txt"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(filename, "a", encoding="utf-8") as file:
            file.write("=" * 60 + "\n")
            file.write(f"TIMESTAMP: {timestamp}\n")
            file.write(f"FROM: {sender}\n")
            file.write(f"SUBJECT: {subject}\n")
            file.write(f"SCORE: {danger_score}/100\n")
            if reasons:
                file.write("REASONS:\n")
                for reason in set(reasons):
                    file.write(f"  - {reason}\n")
            file.write("\n")
        return True
    except:
        return False