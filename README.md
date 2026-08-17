# 🛡️ Secure Chatbot with Palo Alto Networks AI Runtime Security

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Palo%20Alto%20Networks-orange.svg)](https://www.paloaltonetworks.com/)
[![AI Runtime Security](https://img.shields.io/badge/AI%20Runtime%20Security-API%20Intercept-red.svg)](https://pan.dev/prisma-airs/api/airuntimesecurity/airuntimesecurityapi)

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
secure_chatbot/
├── secure_chatbot_python.py   # Python SDK implementation
├── secure_chatbot_api.py      # Direct API implementation
├── setup_script.py            # Optional guided setup helper
├── README.md                  # This file
├── tips.md                    # Usage tips
├── requirements.txt           # Python dependencies
├── requirements_dev.txt       # Development dependencies
└── .env.example               # Environment variables template
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** installed on your system (required by `pan-aisecurity`)
- **Palo Alto Networks AI Runtime Security account** with API access
- **Valid API key and security profile** configured

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/scthornton/secure_chatbot.git
cd secure_chatbot

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
PANW_AI_SEC_PROFILE_NAME=your_profile_name

# Azure OpenAI. AZURE_PROJECT is the resource NAME, not the full URL.
AZURE_PROJECT=your_azure_openai_resource_name
AZURE_KEY=your_azure_openai_api_key
AZURE_DEPLOY=your_deployment_name
```

### 3. Run the Applications

`pip install -r requirements.txt` in step 1 already installed the AI Runtime
Security SDK from public PyPI, where it is published as `pan-aisecurity`
(the module you import is named `aisecurity`). No extra index URL is needed.

#### Python SDK Version (Recommended)
```bash
python secure_chatbot_python.py
```

#### Direct API Version
```bash
python secure_chatbot_api.py
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
pip install -r requirements_dev.txt

# Format code
black secure_chatbot_*.py

# Lint code
flake8 secure_chatbot_*.py
```

## 📚 Documentation

- 📖 [Official AI Runtime Security Documentation](https://docs.paloaltonetworks.com/ai-runtime-security)
- 🔧 [Runtime Scan API Reference](https://pan.dev/prisma-airs/api/airuntimesecurity/airuntimesecurityapi)
- 🔧 [Management API Reference](https://pan.dev/prisma-airs/api/airuntimesecurity/prismaairsmanagementapi)
- 🐍 [Python SDK on PyPI](https://pypi.org/project/pan-aisecurity/)
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
Solution: pip install pan-aisecurity
          (the PyPI package is pan-aisecurity, the module is aisecurity)
```

**🔥 Credentials Look Set But The App Says They Are Missing**
```
Cause:    A variable in .env is spelled differently from what the code reads
Solution: Use the exact names in .env.example, in particular
          PANW_AI_SEC_PROFILE_NAME, AZURE_PROJECT, AZURE_KEY, AZURE_DEPLOY
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
