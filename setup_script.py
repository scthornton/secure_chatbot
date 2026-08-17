#!/usr/bin/env python3
"""
Setup script for Secure Chatbot with Palo Alto Networks AI Runtime Security
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n🔧 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    print("🐍 Checking Python version...")
    if sys.version_info < (3, 10):
        print(f"❌ Python 3.10+ required, but you have {sys.version}")
        return False
    print(f"✅ Python {sys.version.split()[0]} is compatible")
    return True

def create_virtual_environment():
    """Create and activate virtual environment"""
    venv_path = Path("venv")
    if venv_path.exists():
        print("📁 Virtual environment already exists")
        return True
    
    return run_command(f"{sys.executable} -m venv venv", "Creating virtual environment")

def get_activation_command():
    """Get the virtual environment activation command based on OS"""
    if os.name == 'nt':  # Windows
        return "venv\\Scripts\\activate"
    else:  # Unix/Linux/macOS
        return "source venv/bin/activate"

def upgrade_pip():
    """Upgrade pip before installing requirements

    Everything this project needs is on public PyPI, including the AI Runtime
    Security SDK (published as pan-aisecurity). No extra index URL is required.
    """
    return run_command(f"{sys.executable} -m pip install --upgrade pip",
                       "Upgrading pip")

def install_requirements():
    """Install Python requirements"""
    if not run_command("pip install -r requirements.txt", "Installing requirements"):
        return False
    return True

def create_env_file():
    """Create .env file from template if it doesn't exist"""
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if env_file.exists():
        print("📄 .env file already exists")
        return True
    
    if env_example.exists():
        try:
            env_file.write_text(env_example.read_text())
            print("✅ Created .env file from template")
            print("⚠️  Please edit .env file with your actual API keys and configuration")
            return True
        except Exception as e:
            print(f"❌ Failed to create .env file: {e}")
            return False
    else:
        print("⚠️  .env.example not found, please create .env manually")
        return True

def create_gitignore():
    """Create or update .gitignore file"""
    gitignore_content = """# Secure Chatbot - Git Ignore File

# Environment variables
.env
.env.local
.env.production

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Configuration files with secrets
config.py
secrets.json

# Test coverage
.coverage
htmlcov/
.pytest_cache/

# Documentation
docs/_build/
"""
    
    gitignore_file = Path(".gitignore")
    try:
        gitignore_file.write_text(gitignore_content)
        print("✅ Created/updated .gitignore file")
        return True
    except Exception as e:
        print(f"❌ Failed to create .gitignore: {e}")
        return False

def test_installation():
    """Test if the installation was successful"""
    test_script = """
import sys
try:
    import requests
    print("✅ requests imported successfully")
    
    import openai
    print("✅ openai imported successfully")
    
    try:
        import aisecurity
        print("✅ aisecurity imported successfully")
    except ImportError:
        print("⚠️  aisecurity not available - install it with: pip install pan-aisecurity")
    
    import tkinter
    print("✅ tkinter imported successfully")
    
    from dotenv import load_dotenv
    print("✅ python-dotenv imported successfully")
    
    print("\\n🎉 All core dependencies are available!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)
"""
    
    return run_command(f'python -c "{test_script}"', "Testing installation")

def print_next_steps():
    """Print next steps for the user"""
    activation_cmd = get_activation_command()
    
    print("""
🎉 Setup completed successfully!

📋 Next Steps:

1. Activate your virtual environment:
   {}

2. Edit your .env file with your actual API keys:
   - Get Palo Alto Networks API key from Strata Cloud Manager
   - Get Azure OpenAI credentials from Azure Portal
   
3. Run the chatbots:
   python secure_chatbot_python.py   # For Python SDK version
   python secure_chatbot_api.py      # For Direct API version

📚 Documentation:
   - README.md for detailed setup instructions
   - .env.example for configuration examples

🔐 Security Notes:
   - Never commit .env file to version control
   - Keep your API keys secure
   - Use different credentials for different environments

🆘 Need Help?
   - Check the troubleshooting section in README.md
   - Review Palo Alto Networks documentation
   - Ensure your firewall allows HTTPS connections
""".format(activation_cmd))

def main():
    """Main setup function"""
    print("🚀 Setting up Secure Chatbot with Palo Alto Networks AI Runtime Security")
    print("=" * 70)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create virtual environment
    if not create_virtual_environment():
        sys.exit(1)
    
    print(f"\n⚠️  Please activate your virtual environment and run this script again:")
    print(f"   {get_activation_command()}")
    print(f"   python setup_script.py")
    
    # Check if we're in a virtual environment
    if sys.prefix == sys.base_prefix:
        print("\n⚠️  Virtual environment not activated. Please activate it first.")
        return
    
    print("\n🔧 Continuing setup in virtual environment...")
    
    # Upgrade pip
    if not upgrade_pip():
        print("⚠️  pip upgrade failed, continuing with the existing pip.")
    
    # Install requirements
    if not install_requirements():
        sys.exit(1)
    
    # Create configuration files
    create_env_file()
    create_gitignore()
    
    # Test installation
    if not test_installation():
        sys.exit(1)
    
    # Print next steps
    print_next_steps()

if __name__ == "__main__":
    main()
