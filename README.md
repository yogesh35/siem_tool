# 🛡️ AI-Driven SIEM Tool

![SIEM Dashboard](https://img.shields.io/badge/SIEM-AI%20Powered-blue) ![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen) ![Flask](https://img.shields.io/badge/Flask-2.3.3-red) ![Groq](https://img.shields.io/badge/Groq-AI%20Powered-purple) ![License](https://img.shields.io/badge/License-CC0%201.0-lightgrey)

A **simplified, AI-powered Security Information and Event Management (SIEM) system** that provides real-time system monitoring, threat detection, and intelligent security assistance through an intuitive web dashboard.

## 🚀 Features

### � **Real-Time System Monitoring**
- **Live system metrics** (CPU, Memory, Disk usage)
- **Hardware information** display
- **Automatic status updates** every 5 seconds
- **Visual indicators** for system health

### 🤖 **AI Security Assistant**
- **Groq API Integration** for intelligent conversations
- **Context-aware responses** based on current system state
- **Security guidance** and threat analysis
- **Interactive chat interface**

### � **Activity Logging**
- **System event tracking**
- **Real-time log updates**
- **SQLite database storage**
- **Searchable log history**

### � **API Testing Tools**
- **Built-in endpoint testing** functionality
- **API status monitoring**
- **Response validation**
- **Error detection and reporting**

### 🌐 **Web Dashboard**
- **Responsive design** with Tailwind CSS
- **Real-time updates** without page refresh
- **Clean, intuitive interface**
- **Cross-platform compatibility**

## 🛠️ Technologies Used

- **Backend**: Flask, SQLite, psutil
- **Frontend**: HTML5, Tailwind CSS, JavaScript
- **AI Integration**: Groq API
- **System Monitoring**: psutil library
- **Database**: SQLite for logging

## 📋 Requirements

- Python 3.8 or higher
- Windows/Linux/macOS
- Internet connection for Groq AI features
- Administrator/Root privileges (for network packet capture)
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

### 4. Configure Groq API Key

**Important**: You need a Groq API key for the AI assistant feature.

1. Sign up at [Groq Cloud](https://console.groq.com/)
2. Get your API key
3. Open `app.py` and replace the API key on line 9:
```python
GROQ_API_KEY = "your_groq_api_key_here"  # Replace with your actual key
```

### 5. Run the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## 🖥️ Usage

### Dashboard Features
1. **System Monitoring**: View real-time CPU, memory, and disk usage
2. **AI Chat**: Ask the AI assistant about security concerns or system status
3. **Activity Logs**: Monitor system events and activities
4. **System Information**: View detailed hardware specifications
5. **API Testing**: Test endpoint functionality directly from the dashboard

### AI Security Assistant
- Ask questions like "What's my current system status?"
- Get security recommendations and threat analysis
- Receive context-aware responses based on your system metrics

### Real-Time Updates
- System metrics update automatically every 5 seconds
- Logs refresh every 10 seconds
- System information updates every 30 seconds

## � Project Structure

```
siem_tool/
├── app.py                 # Main application file
├── config.py             # Configuration settings
├── db_create.py          # Database initialization
├── ollama_lib.py         # Local AI model support
├── requirements.txt      # Python dependencies
├── templates/           # HTML templates (unused in current version)
│   ├── index.html
│   ├── login.html
│   └── register.html
├── .gitignore           # Git ignore rules
├── LICENSE              # License file
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