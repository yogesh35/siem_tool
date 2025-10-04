from flask import Flask, jsonify, request, render_template
import psutil
import datetime
import sqlite3
import threading
import requests
import os
import time
import random
import ipaddress

# Groq API Key
try:
    from api_config import GROQ_API_KEY
except ImportError:
    GROQ_API_KEY = "your_groq_api_key_here"

GROQ_HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

app = Flask(__name__)

# Database setup
def init_db():
    try:
        conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
        
        # Create tables
        conn.execute('''CREATE TABLE IF NOT EXISTS network_requests 
                       (id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, 
                        type TEXT, country TEXT, summary TEXT, blacklisted TEXT,
                        attacks INTEGER, reports INTEGER)''')
        
        conn.execute('''CREATE TABLE IF NOT EXISTS logs 
                       (id INTEGER PRIMARY KEY, timestamp TEXT, log TEXT)''')
        
        conn.execute('''CREATE TABLE IF NOT EXISTS metrics 
                       (id INTEGER PRIMARY KEY, timestamp TEXT, cpu REAL, 
                        memory REAL, disk REAL, network INTEGER)''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized")
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

# Save functions
def save_log(message):
    try:
        conn = sqlite3.connect('system_metrics.db')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("INSERT INTO logs (timestamp, log) VALUES (?, ?)", (timestamp, message))
        conn.commit()
        conn.close()
        print(f"[{timestamp}] {message}")
    except Exception as e:
        print(f"Log error: {e}")

def save_network_request(ip, req_type, country, summary, blacklisted, attacks, reports):
    try:
        conn = sqlite3.connect('system_metrics.db')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("""INSERT INTO network_requests 
                        (timestamp, ip, type, country, summary, blacklisted, attacks, reports) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", 
                     (timestamp, ip, req_type, country, summary, blacklisted, attacks, reports))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Network request save error: {e}")

def save_metrics(cpu, memory, disk, network):
    try:
        conn = sqlite3.connect('system_metrics.db')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("INSERT INTO metrics (timestamp, cpu, memory, disk, network) VALUES (?, ?, ?, ?, ?)", 
                     (timestamp, cpu, memory, disk, network))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Metrics save error: {e}")

# Get IP country info
def get_ip_country(ip):
    try:
        if ":" in ip or ipaddress.ip_address(ip).is_private:
            return "Local Network"
        
        response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true", timeout=5)
        data = response.json()
        country = data.get("country_name", "Unknown")
        city = data.get("city", "Unknown")
        return f"{country}, {city}"
    except:
        return "Unknown"

# Check if IP is blacklisted
def check_ip_blacklisted(ip):
    try:
        if ipaddress.ip_address(ip).is_private:
            return False, 0, 0
        
        # Simple blacklist check - you can expand this
        response = requests.get(f"http://api.blocklist.de/api.php?ip={ip}&format=json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            attacks = data.get("attacks", 0)
            reports = data.get("reports", 0)
            return attacks > 0, attacks, reports
        return False, 0, 0
    except:
        return False, 0, 0

# AI notification
def notify_ai(message):
    try:
        if GROQ_API_KEY != "your_groq_api_key_here":
            payload = {
                "model": "llama3-8b-8192",
                "messages": [{"role": "user", "content": f"{message}\\nRespond briefly about this security event."}]
            }
            response = requests.post("https://api.groq.com/openai/v1/chat/completions", 
                                   headers=GROQ_HEADERS, json=payload, timeout=10)
            if response.status_code == 200:
                ai_response = response.json().get("choices", [{}])[0].get("message", {}).get("content", "No response")
                save_log(f"🤖 AI Analysis: {ai_response}")
    except Exception as e:
        save_log(f"AI notification failed: {e}")

# Network monitoring simulation
def simulate_network_activity():
    time.sleep(5)  # Wait for app to start
    
    sample_ips = [
        "192.168.1.100", "10.0.0.45", "172.16.0.88",
        "203.0.113.5", "198.51.100.23", "192.0.2.146", 
        "8.8.8.8", "1.1.1.1", "208.67.222.222"
    ]
    
    activities = [
        "HTTP Request", "DNS Query", "HTTPS Connection", 
        "FTP Transfer", "SSH Connection", "Email Traffic"
    ]
    
    print("🔄 Starting network activity simulation...")
    
    while True:
        try:
            ip = random.choice(sample_ips)
            activity = random.choice(activities)
            
            if ipaddress.ip_address(ip).is_private:
                country = "Local Network"
                blacklisted = "No"
                attacks = 0
                reports = 0
            else:
                countries = ["Germany", "United States", "United Kingdom", "France", "Canada"]
                country = random.choice(countries)
                blacklisted = "Yes" if random.random() < 0.1 else "No"  # 10% chance
                attacks = random.randint(1, 5) if blacklisted == "Yes" else 0
                reports = random.randint(1, 10) if blacklisted == "Yes" else 0
            
            save_network_request(ip, "Simulated", country, f"{activity} from {ip}", 
                               blacklisted, attacks, reports)
            
            log_msg = f"📡 {activity} detected from {ip} ({country})"
            if blacklisted == "Yes":
                log_msg += " ⚠️ THREAT DETECTED"
                notify_ai(f"Security Alert: Suspicious {activity} from blacklisted IP {ip}")
            
            save_log(log_msg)
            
        except Exception as e:
            print(f"Simulation error: {e}")
        
        time.sleep(random.randint(3, 8))  # Random interval

# Routes
@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/server-status')
def server_status():
    try:
        cpu = round(psutil.cpu_percent(interval=0.1), 1)
        memory = round(psutil.virtual_memory().percent, 1)
        
        if os.name == 'nt':
            disk = round(psutil.disk_usage('C:\\\\').percent, 1)
        else:
            disk = round(psutil.disk_usage('/').percent, 1)
        
        save_metrics(cpu, memory, disk, 0)
        
        return jsonify({
            "cpu_usage": cpu,
            "memory_usage": memory,
            "disk_usage": disk
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/system-info')
def system_info():
    try:
        cpu_cores = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else 0
        memory_total = psutil.virtual_memory().total
        
        if os.name == 'nt':
            disk_total = psutil.disk_usage('C:\\\\').total
        else:
            disk_total = psutil.disk_usage('/').total
            
        return jsonify({
            "cpu_cores": cpu_cores,
            "cpu_frequency": cpu_freq,
            "memory_total": memory_total,
            "disk_total": disk_total,
            "gpu_usage": "N/A",
            "power_usage": "N/A"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logs')
def get_logs():
    try:
        conn = sqlite3.connect('system_metrics.db')
        cursor = conn.execute("SELECT timestamp, log FROM logs ORDER BY id DESC LIMIT 20")
        logs = [{"timestamp": row[0], "log": row[1]} for row in cursor.fetchall()]
        conn.close()
        return jsonify(logs)
    except Exception as e:
        return jsonify([{"timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                        "log": f"Error loading logs: {e}"}])

@app.route('/network-requests')
def get_network_requests():
    try:
        conn = sqlite3.connect('system_metrics.db')
        cursor = conn.execute("""SELECT timestamp, ip, type, country, summary, blacklisted, attacks, reports 
                               FROM network_requests ORDER BY id DESC LIMIT 50""")
        requests_data = []
        for row in cursor.fetchall():
            requests_data.append({
                "timestamp": row[0],
                "ip": row[1],
                "type": row[2],
                "country": row[3],
                "summary": row[4],
                "blacklisted": row[5],
                "attacks": row[6],
                "reports": row[7]
            })
        conn.close()
        return jsonify(requests_data)
    except Exception as e:
        return jsonify([])

@app.route('/chat', methods=['POST'])
def chat():
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        
        if not user_message:
            return jsonify({"response": "Please provide a message."})
        
        # Get recent system data
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory().percent
        
        # Get recent logs and network activity
        conn = sqlite3.connect('system_metrics.db')
        recent_logs = conn.execute("SELECT log FROM logs ORDER BY id DESC LIMIT 5").fetchall()
        recent_network = conn.execute("SELECT ip, country, blacklisted FROM network_requests ORDER BY id DESC LIMIT 5").fetchall()
        conn.close()
        
        context = f"""User: {user_message}
System Status: CPU {cpu}%, Memory {memory}%
Recent Security Events: {[log[0] for log in recent_logs]}
Recent Network Activity: {[f"{net[0]} from {net[1]} (Blacklisted: {net[2]})" for net in recent_network]}

Respond as a security AI assistant."""
        
        if GROQ_API_KEY != "your_groq_api_key_here":
            payload = {
                "model": "llama3-8b-8192",
                "messages": [{"role": "user", "content": context}]
            }
            
            try:
                response = requests.post("https://api.groq.com/openai/v1/chat/completions", 
                                       headers=GROQ_HEADERS, json=payload, timeout=15)
                
                if response.status_code == 200:
                    ai_response = response.json().get("choices", [{}])[0].get("message", {}).get("content", "No response")
                else:
                    ai_response = f"System status: CPU {cpu}%, Memory {memory}%. Network monitoring active with {len(recent_network)} recent connections detected."
                    
            except:
                ai_response = f"I'm monitoring your system (CPU: {cpu}%, Memory: {memory}%). Network security is active. What can I help you with?"
        else:
            ai_response = f"API key not configured. System status: CPU {cpu}%, Memory {memory}%. Configure your Groq API key to enable AI features."
        
        save_log(f"💬 Chat: {user_message[:50]}...")
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"response": "I'm experiencing technical difficulties. System monitoring continues normally."})

if __name__ == '__main__':
    print("🚀 Starting AI-Driven SIEM with Network Monitoring...")
    
    if init_db():
        save_log("🚀 SIEM System Started")
        save_log("🔍 Network monitoring initialized")
        save_log("🤖 AI threat detection active")
        save_log("📊 Real-time dashboard ready")
        
        # Start background threads
        threading.Thread(target=simulate_network_activity, daemon=True).start()
        print("🔄 Network simulation started")
        
        print("🌐 SIEM Dashboard: http://localhost:5000")
        print("✅ All systems operational!")
        
        try:
            app.run(debug=False, port=5000, host='127.0.0.1', threaded=True)
        except Exception as e:
            print(f"❌ Server error: {e}")
    else:
        print("❌ Failed to initialize database")