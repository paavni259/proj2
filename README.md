# 🔐 SecurePass - Password Security Checker

A comprehensive password security analysis tool that checks passwords against data breaches and evaluates their strength using advanced algorithms.

## ✨ Features

- **🔍 Breach Detection**: Checks passwords against HaveIBeenPwned database with over 11 billion compromised accounts
- **📊 Strength Analysis**: Comprehensive evaluation based on length, complexity, and common patterns
- **💡 Smart Suggestions**: Personalized recommendations to improve password security
- **🌐 Web Interface**: Beautiful, responsive web application built with Flask
- **⚡ CLI Tool**: Command-line interface for quick password checks
- **🔒 Privacy First**: Passwords are never stored and only hashed portions are sent to APIs

## 🚀 Quick Start

### Installation

1. **Clone or download the project**
```bash
git clone <repository-url>
cd securepass
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

### Usage Options

#### Option 1: Web Application (Recommended)
```bash
python app.py
```
Then open your browser to `http://localhost:5000`

#### Option 2: Command Line Interface
```bash
python securepass.py
```

## 🖥️ Web Application Features

### Main Interface
- **Password Input**: Secure password entry with visibility toggle
- **Real-time Analysis**: Instant security analysis with detailed feedback
- **Visual Indicators**: Color-coded strength meters and status indicators
- **Responsive Design**: Works perfectly on desktop and mobile devices

### Demo Page
- **Live Example**: See how SecurePass analyzes a sample password
- **Security Tips**: Learn best practices for password security
- **Educational Content**: Understand what makes a password secure

## 📋 CLI Usage Example

```bash
$ python securepass.py

🔐 Welcome to SecurePass - Password Security Checker
==================================================

Enter password to check (or 'quit' to exit): Password123

🔍 Analyzing password security...

============================================================
🔐 SECUREPASS - PASSWORD SECURITY REPORT
============================================================
Password: ***********
❌ Found in 3,234,567 data breaches!

🔴 Strength: Weak (Score: 25/100)

📊 Analysis Details:
  ❌ Too short (minimum 8 characters)
  ✅ Contains uppercase letters
  ✅ Contains lowercase letters
  ✅ Contains numbers
  ❌ Missing special characters
  ❌ Common password detected

💡 Security Suggestions:
  🔧 Consider using a password manager
  🔧 Add special characters
  🔧 Increase password length to 12+ characters
  🔧 Avoid dictionary words and common passwords

============================================================
```

## 🔧 API Endpoints

### Web API
- `POST /check` - Analyze password security (returns JSON)
- `POST /api/check` - REST API endpoint for external integrations

### Example API Usage
```bash
curl -X POST http://localhost:5000/api/check \
  -H "Content-Type: application/json" \
  -d '{"password": "MySecurePassword123!"}'
```

## 🛡️ Security Features

### Breach Detection
- Uses HaveIBeenPwned API with k-anonymity model
- Only first 5 characters of SHA-1 hash are sent
- No plaintext passwords are transmitted

### Strength Evaluation
- **Length Analysis**: Minimum 8 characters, recommends 12+
- **Character Variety**: Uppercase, lowercase, numbers, special characters
- **Pattern Detection**: Identifies sequential and repeated characters
- **Common Password Detection**: Checks against known weak passwords
- **Scoring System**: 0-100 scale with detailed feedback

### Privacy Protection
- Passwords are never stored or logged
- Only cryptographic hashes are used for API calls
- Local analysis with minimal external data transmission

## 📊 Scoring System

| Score Range | Strength Level | Description |
|-------------|----------------|-------------|
| 70-100 | Strong 🟢 | Meets most security requirements |
| 40-69 | Medium 🟡 | Some improvements needed |
| 0-39 | Weak 🔴 | Significant security concerns |

## 🎯 Use Cases

- **Personal Security**: Check your own passwords for breaches and weaknesses
- **Security Training**: Educate users about password security best practices
- **Development**: Integrate into applications for password policy enforcement
- **Security Audits**: Assess password security across organizations

## 🔗 Dependencies

- **Python 3.7+**
- **Flask**: Web framework for the web interface
- **Requests**: HTTP library for API calls
- **Hashlib**: Cryptographic hashing (built-in)

## 📱 Browser Compatibility

- Chrome 70+
- Firefox 65+
- Safari 12+
- Edge 79+

## 🚀 Deployment

### Local Development
```bash
python app.py
```

### Production Deployment
```bash
# Using Gunicorn (recommended)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app

# Using Flask's built-in server (development only)
export FLASK_ENV=production
python app.py
```

### Docker Deployment
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [HaveIBeenPwned](https://haveibeenpwned.com/) for providing the breach database API
- [Bootstrap](https://getbootstrap.com/) for the responsive web design
- [Font Awesome](https://fontawesome.com/) for the beautiful icons

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/your-repo/issues) page
2. Create a new issue with detailed information
3. Contact the maintainers

---

**⚠️ Important Security Note**: While SecurePass helps identify compromised passwords, it's important to use unique, strong passwords for each account and consider using a reputable password manager for the best security practices.
