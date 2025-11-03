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
import json

# Try to import scapy for real network monitoring
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy not available. Install with: pip install scapy")

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

# Global variables for real-time metrics
current_metrics = {
    'cpu': 0,
    'memory': 0,
    'disk': 0,
    'network_sent': 0,
    'network_recv': 0,
    'active_connections': 0,
    'packets_captured': 0,
    'threats_detected': 0
}

# Database setup
def init_db():
    try:
        conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
        
        # Create tables
        conn.execute('''CREATE TABLE IF NOT EXISTS network_requests 
                       (id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, 
                        type TEXT, country TEXT, summary TEXT, blacklisted TEXT,
                        attacks INTEGER, reports INTEGER, protocol TEXT, port INTEGER)''')
        
        conn.execute('''CREATE TABLE IF NOT EXISTS logs 
                       (id INTEGER PRIMARY KEY, timestamp TEXT, log TEXT, level TEXT)''')
        
        conn.execute('''CREATE TABLE IF NOT EXISTS metrics 
                       (id INTEGER PRIMARY KEY, timestamp TEXT, cpu REAL, 
                        memory REAL, disk REAL, network_sent INTEGER, network_recv INTEGER,
                        active_connections INTEGER, packets_captured INTEGER)''')
        
        conn.execute('''CREATE TABLE IF NOT EXISTS threats
                       (id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, 
                        threat_type TEXT, severity TEXT, description TEXT)''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized")
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

# Save functions
def save_log(message, level="INFO"):
    try:
        conn = sqlite3.connect('system_metrics.db')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("INSERT INTO logs (timestamp, log, level) VALUES (?, ?, ?)", 
                    (timestamp, message, level))
        conn.commit()
        conn.close()
        print(f"[{timestamp}] {message}")
    except Exception as e:
        print(f"Log error: {e}")

def save_network_request(ip, req_type, country, summary, blacklisted, attacks, reports, protocol="TCP", port=0):
    try:
        conn = sqlite3.connect('system_metrics.db')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("""INSERT INTO network_requests 
                        (timestamp, ip, type, country, summary, blacklisted, attacks, reports, protocol, port) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                     (timestamp, ip, req_type, country, summary, blacklisted, attacks, reports, protocol, port))
        conn.commit()
        conn.close()
        current_metrics['packets_captured'] += 1
    except Exception as e:
        print(f"Network request save error: {e}")

def save_threat(ip, threat_type, severity, description):
    try:
        conn = sqlite3.connect('system_metrics.db')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("""INSERT INTO threats (timestamp, ip, threat_type, severity, description) 
                        VALUES (?, ?, ?, ?, ?)""", 
                     (timestamp, ip, threat_type, severity, description))
        conn.commit()
        conn.close()
        current_metrics['threats_detected'] += 1
    except Exception as e:
        print(f"Threat save error: {e}")

def save_metrics(cpu, memory, disk, network_sent, network_recv, active_conn, packets):
    try:
        conn = sqlite3.connect('system_metrics.db')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("""INSERT INTO metrics 
                        (timestamp, cpu, memory, disk, network_sent, network_recv, 
                         active_connections, packets_captured) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", 
                     (timestamp, cpu, memory, disk, network_sent, network_recv, active_conn, packets))
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
        
        response = requests.get(f"http://api.blocklist.de/api.php?ip={ip}&format=json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            attacks = data.get("attacks", 0)
            reports = data.get("reports", 0)
            return attacks > 0, attacks, reports
        return False, 0, 0
    except:
        return False, 0, 0

# AI notification with Llama 4
def notify_ai(message):
    try:
        if GROQ_API_KEY != "your_groq_api_key_here":
            payload = {
                "model": "meta-llama/llama-4-scout-17b-16e-instruct",
                "messages": [{"role": "user", "content": f"{message}\nProvide a brief security analysis."}]
            }
            response = requests.post("https://api.groq.com/openai/v1/chat/completions", 
                                   headers=GROQ_HEADERS, json=payload, timeout=10)
            if response.status_code == 200:
                ai_response = response.json().get("choices", [{}])[0].get("message", {}).get("content", "No response")
                save_log(f"🤖 AI Analysis: {ai_response}", "AI")
                return ai_response
    except Exception as e:
        save_log(f"AI notification failed: {e}", "ERROR")
    return None

# REAL Network Packet Capture
def packet_callback(packet):
    """Process captured network packets in real-time"""
    try:
        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "IP"
        port = 0
        
        # Determine protocol and activity type
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            port = dst_port
            
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
            port = dst_port
            
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
            activity = "IP Packet"
        
        # Process the source IP
        ip_to_check = src_ip if not ipaddress.ip_address(src_ip).is_private else dst_ip
        
        # Get geolocation
        country = get_ip_country(ip_to_check)
        
        # Check if blacklisted
        is_blacklisted, attacks, reports = check_ip_blacklisted(ip_to_check)
        blacklisted = "Yes" if is_blacklisted else "No"
        
        # Save to database
        summary = f"{activity} {src_ip}:{src_port if 'src_port' in locals() else 'N/A'} → {dst_ip}:{dst_port if 'dst_port' in locals() else 'N/A'}"
        save_network_request(ip_to_check, protocol, country, summary, blacklisted, attacks, reports, protocol, port)
        
        # Log activity
        log_msg = f"📡 {activity}: {src_ip} → {dst_ip} ({country})"
        if is_blacklisted:
            log_msg += " ⚠️ THREAT DETECTED"
            save_log(log_msg, "CRITICAL")
            save_threat(ip_to_check, "Blacklisted IP", "HIGH", f"{activity} from known malicious source")
            # AI analysis for threats
            threading.Thread(target=notify_ai, args=(f"Security Alert: {activity} from blacklisted IP {ip_to_check}",), daemon=True).start()
        else:
            save_log(log_msg, "INFO")
        
    except Exception as e:
        print(f"Packet processing error: {e}")

# Real Network Monitoring Thread
def monitor_network_traffic():
    """Capture and analyze real network traffic"""
    if not SCAPY_AVAILABLE:
        print("❌ Scapy not available. Using connection monitoring...")
        monitor_network_connections()
        return
    
    time.sleep(5)  # Wait for app to start
    print("🔍 Starting REAL network packet capture...")
    save_log("🔍 Real-time network monitoring started", "INFO")
    
    try:
        # Capture packets - filter for IP traffic only
        sniff(filter="ip", prn=packet_callback, store=0)
    except PermissionError:
        print("❌ Permission denied! Run as Administrator to capture packets.")
        save_log("⚠️ Network capture requires Administrator privileges", "WARNING")
        print("   Falling back to connection monitoring...")
        monitor_network_connections()
    except Exception as e:
        print(f"❌ Network monitoring error: {e}")
        save_log(f"⚠️ Network monitoring error: {e}", "ERROR")
        print("   Falling back to connection monitoring...")
        monitor_network_connections()

# Fallback: Monitor Active Network Connections
def monitor_network_connections():
    """Monitor active network connections using psutil"""
    time.sleep(5)
    print("🔄 Monitoring active network connections...")
    save_log("🔄 Connection monitoring active (fallback mode)", "INFO")
    
    seen_connections = set()
    
    while True:
        try:
            connections = psutil.net_connections(kind='inet')
            current_metrics['active_connections'] = len([c for c in connections if c.status == 'ESTABLISHED'])
            
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
                                           blacklisted, attacks, reports, "TCP", remote_port)
                        
                        # Log
                        log_msg = f"🌐 {activity}: {remote_ip} ({country})"
                        if is_blacklisted:
                            log_msg += " ⚠️ THREAT DETECTED"
                            save_log(log_msg, "CRITICAL")
                            save_threat(remote_ip, "Blacklisted Connection", "HIGH", 
                                      f"Connection to known malicious IP")
                            threading.Thread(target=notify_ai, 
                                          args=(f"Security Alert: Connection to blacklisted IP {remote_ip}",), 
                                          daemon=True).start()
                        else:
                            save_log(log_msg, "INFO")
            
            # Clean up old connections periodically
            if len(seen_connections) > 1000:
                seen_connections.clear()
                
        except Exception as e:
            print(f"Connection monitoring error: {e}")
        
        time.sleep(2)  # Check every 2 seconds

# System metrics monitoring thread
def monitor_system_metrics():
    """Continuously monitor system metrics"""
    time.sleep(5)
    print("📊 Starting system metrics monitoring...")
    
    net_io_last = psutil.net_io_counters()
    
    while True:
        try:
            # Get system metrics
            cpu = round(psutil.cpu_percent(interval=1), 1)
            memory = round(psutil.virtual_memory().percent, 1)
            
            if os.name == 'nt':
                disk = round(psutil.disk_usage('C:\\').percent, 1)
            else:
                disk = round(psutil.disk_usage('/').percent, 1)
            
            # Network I/O
            net_io = psutil.net_io_counters()
            net_sent = net_io.bytes_sent - net_io_last.bytes_sent
            net_recv = net_io.bytes_recv - net_io_last.bytes_recv
            net_io_last = net_io
            
            # Active connections
            connections = psutil.net_connections(kind='inet')
            active_conn = len([c for c in connections if c.status == 'ESTABLISHED'])
            
            # Update global metrics
            current_metrics['cpu'] = cpu
            current_metrics['memory'] = memory
            current_metrics['disk'] = disk
            current_metrics['network_sent'] = net_sent
            current_metrics['network_recv'] = net_recv
            current_metrics['active_connections'] = active_conn
            
            # Save to database
            save_metrics(cpu, memory, disk, net_sent, net_recv, active_conn, 
                        current_metrics['packets_captured'])
            
            # Check for anomalies
            if cpu > 90:
                save_log(f"⚠️ High CPU usage: {cpu}%", "WARNING")
            if memory > 90:
                save_log(f"⚠️ High memory usage: {memory}%", "WARNING")
            if disk > 90:
                save_log(f"⚠️ High disk usage: {disk}%", "WARNING")
                
        except Exception as e:
            print(f"Metrics monitoring error: {e}")
        
        time.sleep(5)  # Update every 5 seconds

# Routes
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/live-metrics')
def live_metrics():
    """Return current live metrics"""
    try:
        return jsonify({
            "cpu_usage": current_metrics['cpu'],
            "memory_usage": current_metrics['memory'],
            "disk_usage": current_metrics['disk'],
            "network_sent": current_metrics['network_sent'],
            "network_recv": current_metrics['network_recv'],
            "active_connections": current_metrics['active_connections'],
            "packets_captured": current_metrics['packets_captured'],
            "threats_detected": current_metrics['threats_detected']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/server-status')
def server_status():
    try:
        return jsonify({
            "cpu_usage": current_metrics['cpu'],
            "memory_usage": current_metrics['memory'],
            "disk_usage": current_metrics['disk']
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
            disk_total = psutil.disk_usage('C:\\').total
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
        cursor = conn.execute("SELECT timestamp, log, level FROM logs ORDER BY id DESC LIMIT 50")
        logs = [{"timestamp": row[0], "log": row[1], "level": row[2]} for row in cursor.fetchall()]
        conn.close()
        return jsonify(logs)
    except Exception as e:
        return jsonify([{"timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
                        "log": f"Error loading logs: {e}", "level": "ERROR"}])

@app.route('/network-requests')
def get_network_requests():
    try:
        conn = sqlite3.connect('system_metrics.db')
        cursor = conn.execute("""SELECT timestamp, ip, type, country, summary, blacklisted, 
                                       attacks, reports, protocol, port 
                               FROM network_requests ORDER BY id DESC LIMIT 100""")
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
                "reports": row[7],
                "protocol": row[8],
                "port": row[9]
            })
        conn.close()
        return jsonify(requests_data)
    except Exception as e:
        return jsonify([])

@app.route('/threats')
def get_threats():
    try:
        conn = sqlite3.connect('system_metrics.db')
        cursor = conn.execute("""SELECT timestamp, ip, threat_type, severity, description 
                               FROM threats ORDER BY id DESC LIMIT 50""")
        threats = []
        for row in cursor.fetchall():
            threats.append({
                "timestamp": row[0],
                "ip": row[1],
                "threat_type": row[2],
                "severity": row[3],
                "description": row[4]
            })
        conn.close()
        return jsonify(threats)
    except Exception as e:
        return jsonify([])

@app.route('/metrics-history')
def metrics_history():
    try:
        conn = sqlite3.connect('system_metrics.db')
        cursor = conn.execute("""SELECT timestamp, cpu, memory, disk, network_sent, 
                                       network_recv, active_connections, packets_captured 
                               FROM metrics ORDER BY id DESC LIMIT 100""")
        metrics = []
        for row in cursor.fetchall():
            metrics.append({
                "timestamp": row[0],
                "cpu": row[1],
                "memory": row[2],
                "disk": row[3],
                "network_sent": row[4],
                "network_recv": row[5],
                "active_connections": row[6],
                "packets_captured": row[7]
            })
        conn.close()
        return jsonify(metrics)
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
        cpu = current_metrics['cpu']
        memory = current_metrics['memory']
        
        # Get recent threats
        conn = sqlite3.connect('system_metrics.db')
        recent_threats = conn.execute("SELECT ip, threat_type FROM threats ORDER BY id DESC LIMIT 5").fetchall()
        recent_network = conn.execute("SELECT ip, country, blacklisted FROM network_requests ORDER BY id DESC LIMIT 5").fetchall()
        conn.close()
        
        threat_summary = f"{current_metrics['threats_detected']} threats detected"
        if recent_threats:
            threat_summary += f", latest: {', '.join([f'{t[1]} from {t[0]}' for t in recent_threats[:3]])}"
        
        context = f"""User Question: {user_message}

Current System Status:
- CPU: {cpu}%, Memory: {memory}%
- Active Network Connections: {current_metrics['active_connections']}
- Packets Captured: {current_metrics['packets_captured']}
- Threats Detected: {threat_summary}

Recent Network Activity: {[f"{net[0]} from {net[1]} (Blacklisted: {net[2]})" for net in recent_network]}

You are a cybersecurity AI assistant. Provide helpful, accurate security analysis and recommendations."""
        
        if GROQ_API_KEY != "your_groq_api_key_here":
            payload = {
                "model": "meta-llama/llama-4-scout-17b-16e-instruct",
                "messages": [{"role": "user", "content": context}]
            }
            
            try:
                response = requests.post("https://api.groq.com/openai/v1/chat/completions", 
                                       headers=GROQ_HEADERS, json=payload, timeout=15)
                
                if response.status_code == 200:
                    ai_response = response.json().get("choices", [{}])[0].get("message", {}).get("content", "No response")
                else:
                    ai_response = f"System status: CPU {cpu}%, Memory {memory}%. {threat_summary}. Network monitoring active with {current_metrics['active_connections']} active connections."
                    
            except Exception as e:
                ai_response = f"I'm monitoring your system (CPU: {cpu}%, Memory: {memory}%). {threat_summary}. Network security is active. Error: {str(e)}"
        else:
            ai_response = f"API key not configured. System status: CPU {cpu}%, Memory {memory}%. {threat_summary}."
        
        save_log(f"💬 Chat: {user_message[:50]}...", "INFO")
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"response": f"I'm experiencing technical difficulties: {str(e)}"})

if __name__ == '__main__':
    print("🚀 Starting Complete AI-Driven SIEM with Live Metrics...")
    print("=" * 70)
    
    if init_db():
        save_log("🚀 Complete SIEM System Started", "INFO")
        save_log("🔍 Real-time network monitoring initialized", "INFO")
        save_log("📊 System metrics monitoring initialized", "INFO")
        save_log("🤖 AI threat detection active (Llama 4)", "INFO")
        save_log("📈 Live metrics dashboard ready", "INFO")
        
        # Check if running with admin privileges
        import ctypes
        is_admin = False
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            pass
        
        if is_admin:
            print("✅ Running with Administrator privileges")
            print("🔍 Full packet capture enabled")
        else:
            print("⚠️  Not running as Administrator")
            print("   - For FULL packet capture: Run as Administrator")
            print("   - Current mode: Connection monitoring + Live metrics")
        
        print("=" * 70)
        
        # Start monitoring threads
        threading.Thread(target=monitor_network_traffic, daemon=True).start()
        threading.Thread(target=monitor_system_metrics, daemon=True).start()
        print("🔄 Network monitoring thread started")
        print("📊 System metrics monitoring thread started")
        
        print("\n🌐 SIEM Dashboard: http://localhost:5000")
        print("✅ All systems operational!")
        print("\n📊 Live Monitoring:")
        print("   • Real network packets (if Administrator)")
        print("   • Active network connections")
        print("   • CPU, Memory, Disk metrics (real-time)")
        print("   • Network I/O statistics")
        print("   • Threat detection & geolocation")
        print("   • AI-powered security analysis (Llama 4)")
        print("\n⚠️  To capture ALL network packets:")
        print("   Right-click PowerShell → Run as Administrator")
        print("   Then run: python app_complete.py\n")
        
        try:
            app.run(debug=False, port=5000, host='127.0.0.1', threaded=True)
        except Exception as e:
            print(f"❌ Server error: {e}")
    else:
        print("❌ Failed to initialize database")
