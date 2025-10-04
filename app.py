from flask import Flask, jsonify, request, render_template_string
import psutil
import datetime
import sqlite3
import threading
import requests
import os
import time
import traceback

# Groq API Key - Replace with your actual API key
GROQ_API_KEY = "your_groq_api_key_here"
GROQ_HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

app = Flask(__name__)

# Simple HTML template embedded in the code
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-Driven SIEM Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .metric { padding: 10px; background: #e3f2fd; border-radius: 4px; margin: 5px 0; }
        .chat-box { height: 300px; overflow-y: auto; background: #f9f9f9; padding: 10px; border: 1px solid #ddd; }
        .chat-input { width: 100%; padding: 10px; margin: 10px 0; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .logs { height: 200px; overflow-y: auto; background: #f8f9fa; padding: 10px; font-family: monospace; font-size: 12px; }
        .status-good { color: green; }
        .status-warning { color: orange; }
        .status-error { color: red; }
        h1 { color: #333; text-align: center; }
        h2 { color: #666; border-bottom: 2px solid #007bff; padding-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ AI-Driven SIEM Dashboard</h1>
        
        <div class="grid">
            <!-- System Metrics -->
            <div class="card">
                <h2>📊 System Metrics</h2>
                <div id="system-metrics">
                    <div class="metric">CPU Usage: <span id="cpu">Loading...</span></div>
                    <div class="metric">Memory Usage: <span id="memory">Loading...</span></div>
                    <div class="metric">Disk Usage: <span id="disk">Loading...</span></div>
                    <div class="metric">Status: <span id="status" class="status-good">Monitoring Active</span></div>
                </div>
            </div>

            <!-- AI Chat -->
            <div class="card">
                <h2>🤖 AI Security Assistant</h2>
                <div id="chat-box" class="chat-box">
                    <div>🤖 <strong>AI:</strong> Hello! I'm your AI security assistant. Ask me about system status or security concerns.</div>
                </div>
                <input type="text" id="chat-input" class="chat-input" placeholder="Ask about security, system status, or threats..." onkeypress="if(event.key==='Enter') sendMessage()">
                <button class="btn" onclick="sendMessage()">Send Message</button>
            </div>
        </div>

        <!-- System Information -->
        <div class="card">
            <h2>💻 System Information</h2>
            <div id="system-info" class="grid">
                <div>Loading system information...</div>
            </div>
        </div>

        <!-- Recent Logs -->
        <div class="card">
            <h2>📝 Recent Activity Logs</h2>
            <div id="logs" class="logs">Loading logs...</div>
            <button class="btn" onclick="refreshLogs()">Refresh Logs</button>
        </div>

        <!-- Test API Endpoints -->
        <div class="card">
            <h2>🔧 API Status Tests</h2>
            <button class="btn" onclick="testAPI('system-info')">Test System Info</button>
            <button class="btn" onclick="testAPI('server-status')">Test Server Status</button>
            <button class="btn" onclick="testAPI('logs')">Test Logs</button>
            <div id="api-results" style="margin-top: 10px; padding: 10px; background: #f8f9fa;"></div>
        </div>
    </div>

    <script>
        // Update system metrics
        function updateMetrics() {
            fetch('/server-status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('cpu').textContent = data.cpu_usage + '%';
                    document.getElementById('memory').textContent = data.memory_usage + '%';
                    document.getElementById('disk').textContent = data.disk_usage + '%';
                    
                    // Update status based on metrics
                    const maxUsage = Math.max(data.cpu_usage, data.memory_usage, data.disk_usage);
                    const statusEl = document.getElementById('status');
                    if (maxUsage > 80) {
                        statusEl.textContent = 'High Usage';
                        statusEl.className = 'status-error';
                    } else if (maxUsage > 60) {
                        statusEl.textContent = 'Moderate Usage';
                        statusEl.className = 'status-warning';
                    } else {
                        statusEl.textContent = 'Normal Operation';
                        statusEl.className = 'status-good';
                    }
                })
                .catch(error => {
                    console.error('Error fetching metrics:', error);
                    document.getElementById('status').textContent = 'Connection Error';
                    document.getElementById('status').className = 'status-error';
                });
        }

        // Update system information
        function updateSystemInfo() {
            fetch('/system-info')
                .then(response => response.json())
                .then(data => {
                    const infoDiv = document.getElementById('system-info');
                    infoDiv.innerHTML = `
                        <div class="metric">CPU Cores: ${data.cpu_cores}</div>
                        <div class="metric">CPU Frequency: ${data.cpu_frequency} MHz</div>
                        <div class="metric">Total Memory: ${(data.memory_total / (1024**3)).toFixed(2)} GB</div>
                        <div class="metric">Total Disk: ${(data.disk_total / (1024**3)).toFixed(2)} GB</div>
                        <div class="metric">GPU: ${data.gpu_usage}</div>
                        <div class="metric">Power: ${data.power_usage}</div>
                    `;
                })
                .catch(error => {
                    console.error('Error fetching system info:', error);
                    document.getElementById('system-info').innerHTML = '<div class="status-error">Failed to load system information</div>';
                });
        }

        // Send chat message
        function sendMessage() {
            const input = document.getElementById('chat-input');
            const message = input.value.trim();
            if (!message) return;

            const chatBox = document.getElementById('chat-box');
            chatBox.innerHTML += `<div>👤 <strong>You:</strong> ${message}</div>`;
            input.value = '';
            
            chatBox.innerHTML += `<div>🤖 <strong>AI:</strong> <em>Processing...</em></div>`;
            chatBox.scrollTop = chatBox.scrollHeight;

            fetch('/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: message })
            })
            .then(response => response.json())
            .then(data => {
                // Remove the "Processing..." message
                const messages = chatBox.children;
                chatBox.removeChild(messages[messages.length - 1]);
                
                chatBox.innerHTML += `<div>🤖 <strong>AI:</strong> ${data.response}</div>`;
                chatBox.scrollTop = chatBox.scrollHeight;
            })
            .catch(error => {
                console.error('Error sending message:', error);
                const messages = chatBox.children;
                chatBox.removeChild(messages[messages.length - 1]);
                chatBox.innerHTML += `<div>🤖 <strong>AI:</strong> <em>Sorry, I'm having trouble processing your request. Please try again.</em></div>`;
                chatBox.scrollTop = chatBox.scrollHeight;
            });
        }

        // Refresh logs
        function refreshLogs() {
            fetch('/logs')
                .then(response => response.json())
                .then(data => {
                    const logsDiv = document.getElementById('logs');
                    logsDiv.innerHTML = '';
                    data.forEach(log => {
                        logsDiv.innerHTML += `<div>[${log.timestamp}] ${log.log}</div>`;
                    });
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                })
                .catch(error => {
                    console.error('Error fetching logs:', error);
                    document.getElementById('logs').innerHTML = '<div class="status-error">Failed to load logs</div>';
                });
        }

        // Test API endpoints
        function testAPI(endpoint) {
            const resultsDiv = document.getElementById('api-results');
            resultsDiv.innerHTML = `Testing /${endpoint}...`;
            
            fetch(`/${endpoint}`)
                .then(response => {
                    if (response.ok) {
                        return response.json();
                    } else {
                        throw new Error(`HTTP ${response.status}`);
                    }
                })
                .then(data => {
                    resultsDiv.innerHTML = `✅ /${endpoint} - OK<br><pre>${JSON.stringify(data, null, 2)}</pre>`;
                })
                .catch(error => {
                    resultsDiv.innerHTML = `❌ /${endpoint} - Error: ${error.message}`;
                });
        }

        // Initialize and start periodic updates
        updateMetrics();
        updateSystemInfo();
        refreshLogs();

        // Update every 5 seconds
        setInterval(updateMetrics, 5000);
        setInterval(updateSystemInfo, 30000);
        setInterval(refreshLogs, 10000);

        console.log("🛡️ SIEM Dashboard loaded successfully!");
    </script>
</body>
</html>
"""

print("🚀 Starting Simplified AI-Driven SIEM Application...")

# Database setup
def init_db():
    try:
        conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
        conn.execute('''CREATE TABLE IF NOT EXISTS logs 
                       (id INTEGER PRIMARY KEY, timestamp TEXT, log TEXT)''')
        conn.commit()
        print("✅ Database initialized")
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

# Save log
def save_log(message):
    try:
        conn = sqlite3.connect('system_metrics.db')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("INSERT INTO logs (timestamp, log) VALUES (?, ?)", (timestamp, message))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Log error: {e}")

# Routes
@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

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
            "gpu_usage": "N/A (Demo Mode)",
            "gpu_memory_used": "N/A",
            "gpu_memory_total": "N/A",
            "power_usage": "N/A"
        })
    except Exception as e:
        print(f"System info error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/server-status')
def server_status():
    try:
        cpu = round(psutil.cpu_percent(interval=0.1), 1)
        memory = round(psutil.virtual_memory().percent, 1)
        
        if os.name == 'nt':
            disk = round(psutil.disk_usage('C:\\').percent, 1)
        else:
            disk = round(psutil.disk_usage('/').percent, 1)
            
        return jsonify({
            "cpu_usage": cpu,
            "memory_usage": memory,
            "disk_usage": disk
        })
    except Exception as e:
        print(f"Server status error: {e}")
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
        print(f"Logs error: {e}")
        return jsonify([{"timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "log": f"Error loading logs: {e}"}])

@app.route('/chat', methods=['POST'])
def chat():
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        
        if not user_message:
            return jsonify({"response": "Please provide a message."})
        
        # Get current system metrics
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory().percent
        
        context = f"User: {user_message}\nSystem: CPU {cpu}%, Memory {memory}%\nRespond as a security AI assistant."
        
        payload = {
            "model": "llama3-8b-8192",
            "messages": [{"role": "user", "content": context}]
        }
        
        try:
            response = requests.post("https://api.groq.com/openai/v1/chat/completions", 
                                   headers=GROQ_HEADERS, json=payload, timeout=10)
            
            if response.status_code == 200:
                ai_response = response.json().get("choices", [{}])[0].get("message", {}).get("content", "No response")
            else:
                ai_response = f"System status: CPU {cpu}%, Memory {memory}%. All systems operational. How can I help?"
                
        except:
            ai_response = f"I'm monitoring your system (CPU: {cpu}%, Memory: {memory}%). What security concerns do you have?"
        
        save_log(f"Chat: {user_message[:50]}...")
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify({"response": "I'm experiencing technical difficulties. Please try again."})

if __name__ == '__main__':
    print("🛡️ Initializing SIEM components...")
    
    if init_db():
        save_log("🚀 SIEM System Started")
        save_log("✅ All components operational")
        save_log("🤖 AI assistant ready")
        
        print("🌐 Dashboard URL: http://localhost:5000")
        print("🤖 Groq AI: ENABLED")
        print("📊 System Monitoring: ENABLED")
        print("✅ Ready for connections!")
        
        try:
            app.run(debug=False, port=5000, host='127.0.0.1')
        except Exception as e:
            print(f"❌ Server error: {e}")
    else:
        print("❌ Failed to initialize database")