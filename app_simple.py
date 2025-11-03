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

# Try to import scapy for real network monitoring
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy not available. Install with: pip install scapy")
    print("   Real network monitoring will be limited.")

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

# REAL Network Packet Capture
def packet_callback(packet):
    """Process captured network packets in real-time"""
    try:
        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Determine protocol and activity type
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Identify common services
            if dst_port == 80 or src_port == 80:
                activity = "HTTP Request"
            elif dst_port == 443 or src_port == 443:
                activity = "HTTPS Connection"
            elif dst_port == 22 or src_port == 22:
                activity = "SSH Connection"
            elif dst_port == 21 or src_port == 21:
                activity = "FTP Transfer"
            elif dst_port == 25 or src_port == 25:
                activity = "SMTP Email"
            elif dst_port == 3389 or src_port == 3389:
                activity = "RDP Connection"
            else:
                activity = f"TCP Connection (Port {dst_port})"
                
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            if dst_port == 53 or src_port == 53:
                activity = "DNS Query"
            elif dst_port == 123 or src_port == 123:
                activity = "NTP Sync"
            else:
                activity = f"UDP Packet (Port {dst_port})"
                
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            activity = "ICMP Ping"
        else:
            protocol = "IP"
            activity = "IP Packet"
        
        # Process the source IP (usually the one initiating the connection)
        ip_to_check = src_ip if not ipaddress.ip_address(src_ip).is_private else dst_ip
        
        # Get geolocation
        country = get_ip_country(ip_to_check)
        
        # Check if blacklisted
        is_blacklisted, attacks, reports = check_ip_blacklisted(ip_to_check)
        blacklisted = "Yes" if is_blacklisted else "No"
        
        # Save to database
        summary = f"{activity} {src_ip}:{src_port if 'src_port' in locals() else 'N/A'} → {dst_ip}:{dst_port if 'dst_port' in locals() else 'N/A'}"
        save_network_request(ip_to_check, protocol, country, summary, blacklisted, attacks, reports)
        
        # Log activity
        log_msg = f"📡 {activity}: {src_ip} → {dst_ip} ({country})"
        if is_blacklisted:
            log_msg += " ⚠️ THREAT DETECTED"
            notify_ai(f"Security Alert: {activity} from blacklisted IP {ip_to_check}")
        
        save_log(log_msg)
        
    except Exception as e:
        print(f"Packet processing error: {e}")

# Real Network Monitoring Thread
def monitor_network_traffic():
    """Capture and analyze real network traffic"""
    if not SCAPY_AVAILABLE:
        print("❌ Scapy not available. Falling back to connection monitoring...")
        monitor_network_connections()
        return
    
    time.sleep(5)  # Wait for app to start
    print("🔍 Starting REAL network packet capture...")
    save_log("🔍 Real-time network monitoring started")
    
    try:
        # Capture packets - filter for IP traffic only
        # store=0 means don't store packets in memory (better performance)
        # prn=packet_callback processes each packet as it arrives
        sniff(filter="ip", prn=packet_callback, store=0)
    except PermissionError:
        print("❌ Permission denied! Run as Administrator to capture packets.")
        save_log("⚠️ Network capture requires Administrator privileges")
        print("   Falling back to connection monitoring...")
        monitor_network_connections()
    except Exception as e:
        print(f"❌ Network monitoring error: {e}")
        save_log(f"⚠️ Network monitoring error: {e}")
        print("   Falling back to connection monitoring...")
        monitor_network_connections()

# Fallback: Monitor Active Network Connections
def monitor_network_connections():
    """Monitor active network connections using psutil"""
    time.sleep(5)
    print("🔄 Monitoring active network connections...")
    save_log("🔄 Connection monitoring active (fallback mode)")
    
    seen_connections = set()
    
    while True:
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port if conn.laddr else 0
                    
                    # Create unique connection ID
                    conn_id = f"{remote_ip}:{remote_port}"
                    
                    if conn_id not in seen_connections:
                        seen_connections.add(conn_id)
                        
                        # Determine activity type based on port
                        if remote_port == 80:
                            activity = "HTTP Connection"
                        elif remote_port == 443:
                            activity = "HTTPS Connection"
                        elif remote_port == 22:
                            activity = "SSH Connection"
                        elif remote_port == 53:
                            activity = "DNS Query"
                        elif remote_port == 25 or remote_port == 587:
                            activity = "Email Connection"
                        else:
                            activity = f"Network Connection (Port {remote_port})"
                        
                        # Get country info
                        country = get_ip_country(remote_ip)
                        
                        # Check blacklist
                        is_blacklisted, attacks, reports = check_ip_blacklisted(remote_ip)
                        blacklisted = "Yes" if is_blacklisted else "No"
                        
                        # Save to database
                        summary = f"{activity} to {remote_ip}:{remote_port}"
                        save_network_request(remote_ip, "Connection", country, summary, 
                                           blacklisted, attacks, reports)
                        
                        # Log
                        log_msg = f"🌐 {activity}: {remote_ip} ({country})"
                        if is_blacklisted:
                            log_msg += " ⚠️ THREAT DETECTED"
                            notify_ai(f"Security Alert: Connection to blacklisted IP {remote_ip}")
                        
                        save_log(log_msg)
            
            # Clean up old connections periodically
            if len(seen_connections) > 1000:
                seen_connections.clear()
                
        except Exception as e:
            print(f"Connection monitoring error: {e}")
        
        time.sleep(2)  # Check every 2 seconds

# Network monitoring simulation (backup)
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
    print("🚀 Starting AI-Driven SIEM with REAL Network Monitoring...")
    print("=" * 60)
    
    if init_db():
        save_log("🚀 SIEM System Started")
        save_log("🔍 Real-time network monitoring initialized")
        save_log("🤖 AI threat detection active")
        save_log("📊 Real-time dashboard ready")
        
        # Check if running with admin privileges (required for packet capture)
        import ctypes
        is_admin = False
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            pass
        
        if is_admin:
            print("✅ Running with Administrator privileges")
            print("🔍 Real packet capture enabled")
        else:
            print("⚠️  Not running as Administrator")
            print("   - For REAL packet capture: Run as Administrator")
            print("   - Current mode: Active connection monitoring")
        
        print("=" * 60)
        
        # Start REAL network monitoring thread
        threading.Thread(target=monitor_network_traffic, daemon=True).start()
        print("🔄 Network monitoring thread started")
        
        print("🌐 SIEM Dashboard: http://localhost:5000")
        print("✅ All systems operational!")
        print("\n📊 Monitoring:")
        print("   • Real network packets (if Administrator)")
        print("   • Active network connections")
        print("   • System performance metrics")
        print("   • Threat detection & geolocation")
        print("   • AI-powered security analysis")
        print("\n⚠️  To capture ALL network packets:")
        print("   Right-click PowerShell → Run as Administrator")
        print("   Then run: python app_simple.py\n")
        
        try:
            app.run(debug=False, port=5000, host='127.0.0.1', threaded=True)
        except Exception as e:
            print(f"❌ Server error: {e}")
    else:
        print("❌ Failed to initialize database")