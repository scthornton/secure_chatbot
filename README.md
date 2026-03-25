# 🛡️ Secure Chatbot with Palo Alto Networks AI Runtime Security

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Palo%20Alto%20Networks-orange.svg)](https://www.paloaltonetworks.com/)
[![AI Runtime Security](https://img.shields.io/badge/AI%20Runtime%20Security-API%20Intercept-red.svg)](https://pan.dev/ai-runtime-security/)

> **Secure AI chatbot implementations demonstrating real-time threat protection using Palo Alto Networks AI Runtime Security**

Two complete chatbot implementations showcasing how to integrate AI Runtime Security protection into your applications - one using the Python SDK and another using direct API calls.

## 🌟 Features

### 🔒 **Security-First Design**
- **Real-time threat scanning** for both user prompts and AI responses
- **Prompt injection detection** to prevent malicious attempts
- **Malicious code detection** in AI-generated content
- **URL security scanning** for harmful links
- **Toxic content filtering** and sensitive data protection

### 🚀 **Two Implementation Approaches**
1. **Python SDK Version** - Simplified integration with built-in error handling
2. **Direct API Version** - Full control with transparent API interactions

### 💻 **Modern UI/UX**
- Clean, intuitive Tkinter-based interface
- Real-time security status indicators
- Color-coded message types for easy monitoring
- Threaded processing to maintain responsiveness

## 📁 Project Structure

```
secure-chatbot/
├── secure_chatbot_python.py          # Python SDK implementation
├── secure_chatbot_api.py             # Direct API implementation
├── README.md               # This file
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variables template
└── docs/
    ├── setup-guide.md     # Detailed setup instructions
    └── api-reference.md   # API usage examples
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.9+** installed on your system
- **Palo Alto Networks AI Runtime Security account** with API access
- **Valid API key and security profile** configured

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/scthornton/secure_chatbot.git
cd secure-chatbot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your credentials
nano .env
```

Add your credentials to `.env`:
```env
PANW_AI_SEC_API_KEY=your_api_key_here
PANW_AI_SEC_PROFILE=your_profile_name
PANW_AI_SEC_ENDPOINT=https://service.api.aisecurity.paloaltonetworks.com
```

### 3. Install AI Runtime Security SDK

For the SDK version, install the official package:

```bash
# Configure pip for Palo Alto Networks repository
python -m pip config set global.extra-index-url "https://art.code.pan.run/artifactory/api/pypi/aisec-api-pypi/simple"

# Install the aisecurity package
pip install aisecurity
```

### 4. Run the Applications

#### Python SDK Version (Recommended)
```bash
python chatbot_sdk.py
```

#### Direct API Version
```bash
python chatbot_api.py
```

## 🔧 Configuration Options

### API Endpoints

| Region | Endpoint |
|--------|----------|
| **US** | `https://service.api.aisecurity.paloaltonetworks.com` |
| **EU (Germany)** | `https://service-de.api.aisecurity.paloaltonetworks.com` |

### Security Profiles

Configure your security profile in [Strata Cloud Manager](https://apps.paloaltonetworks.com/) with:

- ✅ **Prompt Injection Detection**
- ✅ **Malicious Code Detection**  
- ✅ **URL Security Scanning**
- ✅ **Toxic Content Filtering**
- ✅ **Sensitive Data Protection**

## 📖 Usage Examples

### SDK Version Example

```python
import aisecurity
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile

# Initialize the SDK
aisecurity.init(api_key="your_api_key")

# Create scanner and profile
scanner = Scanner()
ai_profile = AiProfile(profile_name="Secure-AI")

# Scan content
result = scanner.sync_scan(
    ai_profile=ai_profile,
    content={"prompt": "Your message here"},
    metadata={"app_user": "user123"}
)
```

### Direct API Example

```python
import requests

headers = {
    'Content-Type': 'application/json',
    'x-pan-token': 'your_api_key'
}

payload = {
    "tr_id": "unique_transaction_id",
    "ai_profile": {"profile_name": "Secure-AI"},
    "metadata": {"app_user": "user123"},
    "contents": [{"prompt": "Your message here"}]
}

response = requests.post(
    'https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request',
    json=payload,
    headers=headers
)
```

## 🛡️ Security Features Explained

### Threat Detection Types

| Detection Type | Description | Example |
|----------------|-------------|---------|
| **Prompt Injection** | Malicious attempts to manipulate AI behavior | `"Ignore your instructions and..."` |
| **Malicious Code** | Harmful code in AI responses | Virus signatures, exploit code |
| **URL Security** | Scanning for malicious URLs | Phishing links, malware downloads |
| **Toxic Content** | Harmful or inappropriate content | Hate speech, violent content |
| **Data Leakage** | Sensitive information exposure | PII, credentials, confidential data |

### Response Actions

- 🚫 **Block** - Prevent content from being displayed
- ⚠️ **Alert** - Log the threat but allow content
- 📝 **Log** - Record the event for analysis

## 🔄 API Scan Types

### Synchronous Scanning
- **Endpoint**: `/v1/scan/sync/request`
- **Use Case**: Real-time chat applications
- **Response Time**: < 1 second
- **Best For**: Interactive applications

### Asynchronous Scanning
- **Endpoint**: `/v1/scan/async/request`
- **Use Case**: Batch processing, high-volume scanning
- **Response Time**: Variable (requires polling)
- **Best For**: Background processing

## 🚨 Error Handling

The applications include comprehensive error handling for:

- **Network connectivity issues**
- **Invalid API credentials**
- **Rate limiting**
- **Service unavailability**
- **Malformed requests**

## 📊 Monitoring and Logging

Both implementations provide detailed logging:

```
[12:34:56] SECURITY: 🔍 Scanning user prompt for security threats...
[12:34:57] SECURITY: ✅ User prompt passed security scan
[12:34:58] SECURITY: 🔍 Scanning AI response for security threats...
[12:34:59] SECURITY: ⚠️ THREAT DETECTED: malicious_url (action: block)
[12:35:00] SYSTEM: AI response blocked for security reasons.
```

## 🔧 Advanced Configuration

### Custom Security Profiles

Create specialized profiles for different use cases:

```python
# High-security profile for sensitive applications
high_security_profile = AiProfile(
    profile_name="HighSecurity-Banking",
    # Additional security settings configured in SCM
)

# Balanced profile for general use
balanced_profile = AiProfile(
    profile_name="Balanced-General",
    # Standard security settings
)
```

### Metadata Enrichment

Enhance scans with contextual information:

```python
metadata = {
    "app_user": "john.doe@company.com",
    "ai_model": "GPT-4",
    "app_name": "Customer Support Bot",
    "session_id": "sess_12345",
    "user_role": "customer",
    "department": "support"
}
```

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Format code
black chatbot_*.py

# Lint code
flake8 chatbot_*.py
```

## 📚 Documentation

- 📖 [Official AI Runtime Security Documentation](https://docs.paloaltonetworks.com/ai-runtime-security)
- 🔧 [API Reference](https://pan.dev/ai-runtime-security/api/ai-runtime-security-api-intercept/)
- 🐍 [Python SDK Documentation](https://pan.dev/ai-runtime-security/api/pythonsdk/)
- 🚀 [Getting Started Guide](https://docs.paloaltonetworks.com/ai-runtime-security/activation-and-onboarding)

## ❓ Troubleshooting

### Common Issues

**🔥 API Key Authentication Failed**
```
Error: 401 Unauthorized
Solution: Verify your API key in Strata Cloud Manager
```

**🔥 Profile Not Found**
```
Error: Profile 'MyProfile' not found
Solution: Create the profile in SCM or check the name spelling
```

**🔥 Connection Timeout**
```
Error: Request timed out
Solution: Check network connectivity and firewall settings
```

**🔥 SDK Import Error**
```
Error: No module named 'aisecurity'
Solution: Install the SDK using the official repository
```

### Getting Help

- 📧 **Email**: [support@paloaltonetworks.com](mailto:support@paloaltonetworks.com)
- 💬 **Community**: [Live Community Forum](https://live.paloaltonetworks.com/)
- 📚 **Knowledge Base**: [Support Portal](https://support.paloaltonetworks.com/)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Palo Alto Networks** for providing the AI Runtime Security platform
- **Python Community** for excellent libraries and tools
- **Open Source Contributors** who make projects like this possible

## 🔗 Related Projects

- [Palo Alto Networks GitHub](https://github.com/PaloAltoNetworks)
- [AI Runtime Security Examples](https://github.com/PaloAltoNetworks/airs-examples)
- [PAN-OS Python SDK](https://github.com/PaloAltoNetworks/pan-os-python)

---

<div align="center">

**Made with ❤️ for secure AI applications**

[⭐ Star this repo](https://github.com/scthornton/secure_chatbot) • [🐛 Report Bug](https://github.com/scthornton/secure_chatbot/issues) • [💡 Request Feature](https://github.com/scthornton/secure_chatbot/issues)

</div>

---

## Contact

**Scott Thornton** — AI Security Researcher

- Website: [perfecxion.ai](https://perfecxion.ai/)
- Email: [scott@perfecxion.ai](mailto:scott@perfecxion.ai)
- LinkedIn: [linkedin.com/in/scthornton](https://www.linkedin.com/in/scthornton)
- ORCID: [0009-0008-0491-0032](https://orcid.org/0009-0008-0491-0032)
- GitHub: [@scthornton](https://github.com/scthornton)

**Security Issues**: Please report via [SECURITY.md](SECURITY.md)
