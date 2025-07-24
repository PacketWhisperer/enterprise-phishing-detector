import datetime
import os

def save_analysis(sender, subject, body, danger_score, reasons):
    """Save analysis results to file"""
    try:
        filename = "phishing_analysis_log.txt"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(filename, "a", encoding="utf-8") as file:
            file.write("=" * 60 + "\n")
            file.write(f"ANALYSIS TIMESTAMP: {timestamp}\n")
            file.write(f"FROM: {sender}\n")
            file.write(f"SUBJECT: {subject}\n")
            file.write(f"BODY: {body}\n")
            file.write(f"DANGER SCORE: {danger_score}/100\n")
            
            if danger_score >= 80:
                file.write("RISK LEVEL: 🚨 VERY HIGH RISK - Almost certainly phishing!\n")
            elif danger_score >= 60:
                file.write("RISK LEVEL: 🚨 HIGH RISK - Likely phishing!\n")
            elif danger_score >= 40:
                file.write("RISK LEVEL: ⚠️ MEDIUM RISK - Be very careful\n")
            elif danger_score >= 20:
                file.write("RISK LEVEL: 💡 LOW RISK - Minor concerns\n")
            else:
                file.write("RISK LEVEL: ✅ VERY LOW RISK - Looks safe\n")
            
            if reasons:
                file.write("SUSPICIOUS FACTORS:\n")
                unique_reasons = list(set(reasons))
                for i, reason in enumerate(unique_reasons, 1):
                    file.write(f"  {i}. {reason}\n")
            else:
                file.write("SUSPICIOUS FACTORS: None detected\n")
            
            file.write("\n")
        
        print(f"✅ Results saved to: {filename}")
        return True
        
    except Exception as e:
        print(f"❌ Error saving file: {e}")
        return False

def check_suspicious_sender(sender):
    """Check if sender looks fake"""
    danger_score = 0
    reasons = []
    
    free_emails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
    official_companies = ["bank", "paypal", "amazon", "microsoft", "apple", "visa", "ebay", "netflix", "google"]
    
    print("🔍 Checking sender reputation...")
    
    for company in official_companies:
        if company in sender.lower():
            for free_service in free_emails:
                if free_service in sender.lower():
                    danger_score += 35
                    reasons.append(f"Claims to be {company} but uses {free_service} (major red flag)")
                    print(f"   🚨 FAKE ALERT: Claims to be {company} but uses free email!")
    
    return danger_score, reasons

def check_urgent_language(subject, body):
    """Check for urgent pressure tactics"""
    danger_score = 0
    reasons = []
    
    urgent_phrases = ["urgent", "immediately", "act now", "expires today", "limited time", 
                     "hurry", "final notice", "last chance", "expire soon", "within 24 hours"]
    
    print("🔍 Checking for pressure tactics...")
    urgent_count = 0
    
    for phrase in urgent_phrases:
        if phrase.lower() in subject.lower() or phrase.lower() in body.lower():
            urgent_count += 1
    
    if urgent_count >= 2:
        danger_score += 30
        reasons.append("Multiple urgent pressure tactics detected")
        print(f"   ⚠️ High pressure: {urgent_count} urgent phrases found")
    elif urgent_count == 1:
        danger_score += 20
        reasons.append("Uses urgent pressure tactics")
        print(f"   ⚠️ Pressure tactic detected")
    
    return danger_score, reasons

def check_money_scam_indicators(subject, body):
    """Check for money/prize scam patterns"""
    danger_score = 0
    reasons = []
    
    money_words = ["$", "money", "cash", "prize", "won", "winner", "lottery", 
                   "inheritance", "million", "billion", "reward", "jackpot"]
    
    print("🔍 Checking for money scam indicators...")
    money_count = 0
    text_to_check = (subject + " " + body).lower()
    
    for word in money_words:
        if word.lower() in text_to_check:
            money_count += 1
    
    if money_count >= 3:
        danger_score += 40
        reasons.append(f"Heavy money/prize focus ({money_count} mentions - classic scam pattern)")
        print(f"   💰 SCAM ALERT: {money_count} money-related terms")
    elif money_count >= 2:
        danger_score += 25
        reasons.append("Multiple money/prize mentions")
        print(f"   💰 Money focus: {money_count} terms found")
    
    return danger_score, reasons

def check_suspicious_links(body):
    """Check for suspicious links"""
    danger_score = 0
    reasons = []
    
    suspicious_patterns = ["http://", "bit.ly", "tinyurl", "t.co", "short.link", 
                          "click here", "clickhere", "link.com"]
    
    print("🔍 Checking for suspicious links...")
    
    for pattern in suspicious_patterns:
        if pattern in body.lower():
            danger_score += 15
            reasons.append("Contains suspicious or shortened links")
            print(f"   🔗 Suspicious link pattern: {pattern}")
            break
    
    return danger_score, reasons

def analyze_email(subject, sender, body):
    """Complete email analysis"""
    danger_score = 0
    all_reasons = []
    
    # Basic suspicious words
    suspicious_words = ["winner", "congratulations", "verify", "suspended", "confirm", 
                       "update", "security", "account", "password", "login"]
    
    print("🔍 Checking for suspicious words...")
    for word in suspicious_words:
        if word.lower() in subject.lower():
            danger_score += 12
            all_reasons.append(f"Suspicious word '{word}' in subject")
            print(f"   ⚠️ Found: {word} (in subject)")
        if word.lower() in body.lower():
            danger_score += 6
            all_reasons.append(f"Suspicious word '{word}' in body")
    
    # Run all specialized checks
    sender_score, sender_reasons = check_suspicious_sender(sender)
    urgent_score, urgent_reasons = check_urgent_language(subject, body)
    money_score, money_reasons = check_money_scam_indicators(subject, body)
    link_score, link_reasons = check_suspicious_links(body)
    
    # Combine all scores and reasons
    total_score = danger_score + sender_score + urgent_score + money_score + link_score
    all_reasons.extend(sender_reasons + urgent_reasons + money_reasons + link_reasons)
    
    return total_score, all_reasons

def show_results(danger_score, reasons, sender, subject):
    """Display detailed analysis results"""
    print(f"\n📊 COMPREHENSIVE ANALYSIS RESULTS:")
    print("=" * 40)
    print(f"📧 From: {sender}")
    print(f"📝 Subject: {subject}")
    print(f"🔢 Danger Score: {danger_score}/100")
    
    if danger_score >= 80:
        print("🚨 VERY HIGH RISK - Almost certainly phishing!")
        print("   🛑 DO NOT click any links or provide information!")
    elif danger_score >= 60:
        print("🚨 HIGH RISK - Likely phishing!")
        print("   ⚠️ Be extremely cautious!")
    elif danger_score >= 40:
        print("⚠️ MEDIUM RISK - Be very careful")
        print("   🤔 Verify sender through other means")
    elif danger_score >= 20:
        print("💡 LOW RISK - Minor concerns")
        print("   👀 Worth double-checking")
    else:
        print("✅ VERY LOW RISK - Looks safe")
        print("   😊 Appears legitimate")
    
    if reasons:
        print(f"\n🔍 Suspicious factors detected ({len(set(reasons))}):")
        unique_reasons = list(set(reasons))
        for i, reason in enumerate(unique_reasons, 1):
            print(f"  {i}. {reason}")
    else:
        print("\n✅ No obvious red flags detected")

# Main program
print("🕵️ ADVANCED PHISHING EMAIL DETECTOR v5.0")
print("=" * 50)
print("🛡️ Comprehensive email security analysis")
print("📁 All results automatically saved to file")
print("💡 Commands: 'quit' to exit, 'stats' to see file info")
print()

analysis_count = 0

while True:
    print("📧 Enter email details for analysis:")
    print("-" * 30)
    
    sender = input("📨 Email sender: ").strip()
    if sender.lower() == 'quit':
        print(f"👋 Session complete! Analyzed {analysis_count} emails.")
        break
    elif sender.lower() == 'stats':
        try:
            filename = "phishing_analysis_log.txt"
            if os.path.exists(filename):
                size = os.path.getsize(filename)
                print(f"📊 Analysis file: {filename}")
                print(f"📈 File size: {size} bytes")
                print(f"🔢 Emails analyzed this session: {analysis_count}")
            else:
                print("📂 No analysis file created yet")
        except Exception as e:
            print(f"❌ Error checking stats: {e}")
        continue
    
    subject = input("📝 Email subject: ").strip()
    if subject.lower() == 'quit':
        break
    
    body = input("📄 Email body: ").strip()
    if body.lower() == 'quit':
        break
    
    # Perform comprehensive analysis
    print(f"\n🔍 Performing comprehensive analysis...")
    print("-" * 40)
    
    danger_score, reasons = analyze_email(subject, sender, body)
    show_results(danger_score, reasons, sender, subject)
    
    # Save results
    print(f"\n💾 Saving analysis results...")
    if save_analysis(sender, subject, body, danger_score, reasons):
        analysis_count += 1
    
    print("\n" + "=" * 60)
    print()

print("🔒 Stay safe from phishing attacks!")