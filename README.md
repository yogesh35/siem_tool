# 🛡️ AI-Driven SIEM Tool with Real Network Monitoring

![SIEM Dashboard](https://img.shields.io/badge/SIEM-AI%20Powered-blue) ![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen) ![Flask](https://img.shields.io/badge/Flask-2.3.3-red) ![Groq](https://img.shields.io/badge/Groq-AI%20Powered-purple) ![Scapy](https://img.shields.io/badge/Scapy-Network%20Analysis-orange) ![License](https://img.shields.io/badge/License-CC0%201.0-lightgrey)

A **comprehensive AI-powered Security Information and Event Management (SIEM) system** that provides **real-time network traffic monitoring**, threat detection, and intelligent security assistance through an intuitive web dashboard.

## 🚀 Key Features

### 🌐 **REAL Network Traffic Monitoring**
- **Live packet capture** using Scapy library
- **Captures ALL network traffic** on your system (requires Admin privileges)
- **Protocol detection** (TCP, UDP, ICMP, DNS, HTTP/HTTPS, SSH, FTP, etc.)
- **Source and destination IP tracking**
- **Port-based service identification**
- **Real-time traffic analysis**

**Two Monitoring Modes:**
1. **Packet Capture Mode** (Administrator): Captures every network packet in real-time
2. **Connection Monitoring Mode** (Standard): Monitors active network connections

### 🔍 **Advanced Threat Detection**
- **IP Geolocation**: Tracks country and city of network connections
- **Blacklist Checking**: Validates IPs against known threat databases
- **Suspicious Activity Detection**: Identifies potentially malicious traffic
- **Attack Pattern Recognition**: Detects unusual port scanning, brute force attempts
- **Real-time Alerts**: Instant notifications for security threats

### 🤖 **AI Security Assistant**
- **Groq API Integration** for intelligent threat analysis
- **Context-aware responses** based on current network activity
- **Automated security recommendations**
- **Interactive chat interface** for security queries

### 📊 **Real-Time System Monitoring**
- **Live system metrics** (CPU, Memory, Disk usage)
- **Network bandwidth tracking**
- **Hardware information** display
- **Performance analytics**

### 📝 **Comprehensive Logging**
- **Network activity logs** with timestamps
- **Security event tracking**
- **SQLite database storage**
- **Searchable log history**
- **Export capabilities**

### 🌐 **Web Dashboard**
- **Responsive design** with real-time updates
- **Network activity visualization**
- **Threat status indicators**
- **Interactive charts and graphs**
- **Cross-platform compatibility**

## 🛠️ Technologies Used

- **Backend**: Flask, SQLite, psutil
- **Network Analysis**: Scapy (packet capture and analysis)
- **Frontend**: HTML5, Tailwind CSS, JavaScript
- **AI Integration**: Groq API
- **Geolocation**: IP Geolocation API
- **Threat Intelligence**: Blocklist.de API
- **Database**: SQLite for logging

## 📋 Requirements

- Python 3.8 or higher
- Windows/Linux/macOS
- **Administrator/Root privileges** (for full packet capture)
- Internet connection (for AI APIs and geolocation)

## 🔧 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yogesh35/siem_tool.git
cd siem_tool
```

### 2. Create Virtual Environment (Recommended)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

**Note**: Scapy installation on Windows may require:
- Npcap driver: https://npcap.com/#download
- Or WinPcap: https://www.winpcap.org/install/

### 4. Configure Groq API Key

**Important**: You need a Groq API key for the AI assistant feature.

1. Sign up at [Groq Cloud](https://console.groq.com/)
2. Get your API key
3. Copy `config_template.py` to `api_config.py`:
```bash
copy config_template.py api_config.py  # Windows
cp config_template.py api_config.py    # Linux/macOS
```
4. Open `api_config.py` and add your API key:
```python
GROQ_API_KEY = "gsk_your_actual_groq_api_key_here"
```

### 5. Run the Application

**For FULL Network Packet Capture (Recommended):**

Windows:
```bash
# Right-click PowerShell → Run as Administrator
python app_simple.py
```

Linux/macOS:
```bash
sudo python app_simple.py
```

**For Connection Monitoring (No Admin Required):**
```bash
python app_simple.py
```

The application will be available at `http://localhost:5000`

## 🖥️ Usage

### Network Monitoring Features

**What the SIEM Monitors:**
- ✅ **HTTP/HTTPS Traffic**: Web browsing, API calls
- ✅ **DNS Queries**: Domain name resolutions
- ✅ **SSH Connections**: Secure shell access attempts
- ✅ **FTP Transfers**: File transfer activities
- ✅ **Email Traffic**: SMTP, POP3, IMAP
- ✅ **RDP Sessions**: Remote desktop connections
- ✅ **Custom Protocols**: Any TCP/UDP traffic

**Network Activity Display:**
- Real-time packet capture with source/destination IPs
- Protocol identification (TCP, UDP, ICMP)
- Port-based service detection
- Geographic location of connections
- Blacklist status checking
- Threat severity indicators

### Dashboard Features
1. **Network Monitor**: View live network traffic and threats
2. **System Monitoring**: CPU, memory, disk usage metrics
3. **AI Security Chat**: Ask questions about detected threats
4. **Activity Logs**: Comprehensive security event logging
5. **Threat Detection**: Automatic identification of suspicious IPs

### AI Security Assistant
- Ask: "What suspicious activity have you detected?"
- Ask: "Is my network secure?"
- Get real-time threat analysis
- Receive security recommendations

### Real-Time Updates
- Network packets captured instantly (Administrator mode)
- Active connections monitored every 2 seconds
- System metrics update every 5 seconds
- Logs refresh automatically

## 📁 Project Structure

```
siem_tool/
├── app_simple.py         # Main SIEM application with real network monitoring
├── app_groq.py          # Advanced version with TensorFlow ML models
├── config_template.py   # API configuration template
├── api_config.py        # Your actual API keys (gitignored)
├── requirements.txt     # Python dependencies
├── templates/           # Web dashboard HTML
│   └── index.html      # Main dashboard interface
├── system_metrics.db   # SQLite database (auto-created)
├── .gitignore          # Git ignore rules
├── LICENSE             # License file
└── README.md           # This file
```

## 🚨 Troubleshooting

### Common Issues

**1. API Key Errors**
- Verify your Groq API key is valid and active
- Check internet connectivity
- Ensure API quotas are not exceeded

**2. Port Already in Use**
```bash
# Kill any process using port 5000
# Windows
netstat -ano | findstr :5000
taskkill /PID <process_id> /F

# Linux/macOS
lsof -ti:5000 | xargs kill -9
```

**3. Database Errors**
```bash
# Reset database (will lose existing logs)
python db_create.py
```

**4. Missing Dependencies**
```bash
# Reinstall requirements
pip install --upgrade -r requirements.txt
```

### Performance Notes

- The application is designed to be lightweight and resource-efficient
- System monitoring updates occur every 5 seconds by default
- Database logs are stored locally in SQLite format

```
AI-Driven-SIEM/
├── app_groq.py              # Main Flask application
├── db_create.py             # Database initialization
├── ollama_lib.py            # Ollama integration library
├── requirements.txt         # Python dependencies
├── templates/
│   ├── index.html          # Main dashboard
│   ├── login.html          # Login page
│   └── register.html       # Registration page
├── system_metrics.db       # SQLite database (created automatically)
├── SecIDS-CNN.h5          # AI model (downloaded automatically)
├── .gitignore             # Git ignore file
├── LICENSE                # License file
└── README.md              # This file
```

## 🔧 Configuration Options

### System Monitoring
- Adjust monitoring intervals in `app_groq.py`
- Configure alert thresholds for CPU/Memory/Disk
- Customize packet filtering rules

### AI Integration
- Switch between Groq and Ollama models
- Configure response lengths and formats
- Adjust analysis parameters

### Database Settings
- Modify retention policies
- Configure backup schedules
- Adjust pagination limits

## 🚨 Troubleshooting

### Common Issues

**1. Permission Denied for Packet Capture**
```bash
# Linux/macOS: Run with elevated privileges
sudo python app_groq.py

# Or configure capabilities (Linux):
sudo setcap cap_net_raw+ep $(which python)
```

**2. API Key Errors**
- Verify your Groq API key is valid
- Check internet connectivity
- Ensure API quotas are not exceeded

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the CC0 1.0 Universal License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Groq](https://groq.com/) for providing high-performance AI inference
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [psutil](https://psutil.readthedocs.io/) for system monitoring capabilities
- [Tailwind CSS](https://tailwindcss.com/) for styling

## 📧 Support

If you encounter any issues or have questions, please:
1. Check the troubleshooting section above
2. Search existing issues on GitHub
3. Create a new issue with detailed information about your problem

---

**🛡️ Stay secure and monitor responsibly!**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the CC0 1.0 Universal License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Original Repository**: [Keyvanhardani/AI-Driven-SIEM-Realtime-Operator-with-Groq-Integration](https://github.com/Keyvanhardani/AI-Driven-SIEM-Realtime-Operator-with-Groq-Integration)
- **Groq Cloud**: https://console.groq.com/
- **Ollama**: https://ollama.ai/
- **Hugging Face**: https://huggingface.co/

## 📞 Support

For support and questions:
- Open an issue on GitHub
- Check the troubleshooting section
- Review the configuration guide

## 🔮 Future Enhancements

- [ ] Machine learning model training interface
- [ ] Advanced threat hunting capabilities
- [ ] Integration with external SIEM platforms
- [ ] Mobile responsive dashboard
- [ ] Advanced user role management
- [ ] Automated incident response
- [ ] Custom alert rules engine
- [ ] API rate limiting and caching
- [ ] Multi-tenant support
- [ ] Enhanced visualization options

---

**⚠️ Disclaimer**: This tool is for educational and legitimate security monitoring purposes only. Ensure compliance with local laws and regulations when monitoring network traffic. The authors are not responsible for misuse of this software.