# ===========================================================================
# SECURE AI CHATBOT WITH PALO ALTO NETWORKS AI RUNTIME SECURITY SCANNING
# ===========================================================================
# This script creates a chatbot that scans user prompts for security threats
# BEFORE sending them to Azure OpenAI for processing.
#
# WORKFLOW: User Input → Security Scan → AI Processing → Response
# ===========================================================================

# Import required libraries
import requests  # For making HTTP requests to web APIs
import json      # For converting Python data to/from JSON format
import os        # For reading environment variables from system
import uuid      # For generating unique transaction IDs
import getpass   # For a stable app_user value in scan metadata
from openai import AzureOpenAI  # The Azure OpenAI client library

# Load credentials from a .env file if one is present, so the documented
# "cp .env.example .env" setup actually reaches os.getenv() below. Real
# environment variables always win over .env values.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional; export the variables yourself instead

# Prisma AIRS regional endpoint. US is the default; set PANW_AI_SEC_ENDPOINT to
# the EU (service-de), India (service-in), or Singapore (service-sg) host when
# your API key was issued in that region. Keys are region-specific.
PANW_AI_SEC_ENDPOINT = os.getenv(
    "PANW_AI_SEC_ENDPOINT", "https://service.api.aisecurity.paloaltonetworks.com"
).rstrip("/")

# Azure OpenAI data-plane API version. 2024-10-21 is a GA version; override
# with AZURE_API_VERSION if your deployment needs a different one.
AZURE_API_VERSION = os.getenv("AZURE_API_VERSION", "2024-10-21")

# Metadata attached to every scan. app_name and app_user show up in the Strata
# Cloud Manager session and violation views.
APP_NAME = os.getenv("PANW_AI_SEC_APP_NAME", "secure-chatbot-azure")
APP_USER = os.getenv("PANW_AI_SEC_APP_USER", getpass.getuser())


def scan_prompt_with_paloalto_api(prompt, api_key, ai_profile_name, base_url=None, response=None, ai_model=None):
    """
    SECURITY SCANNER FUNCTION

    Sends a user prompt (and optionally the model's response) to the Palo Alto
    Networks AI Security API to check for threats. The API analyzes the text
    and returns a security assessment.

    Called twice per turn: once with the prompt alone (before the LLM sees it)
    and once with prompt + response (before the user sees the reply). Prisma
    AIRS evaluates a response only when one is sent; it does not predict what
    the model will say.

    THREAT DETECTION CAPABILITIES:
    - DLP (Data Loss Prevention): Detects sensitive data like SSNs, credit cards
    - Prompt Injection: Identifies attempts to manipulate AI behavior
    - Malicious URLs: Flags suspicious web links
    - Content Policy Violations: Checks against defined security policies

    PARAMETERS:
        prompt (str): The user's message that needs security scanning
        api_key (str): Your Palo Alto Networks API authentication key
        ai_profile_name (str): Name of your configured AI Security Profile
        base_url (str): The Palo Alto Networks API endpoint URL (defaults to
            PANW_AI_SEC_ENDPOINT, which defaults to the US region)
        response (str): Optional LLM output to scan together with the prompt
        ai_model (str): Optional model name recorded in scan metadata

    RETURNS:
        dict: Security scan results with category and action recommendations
        None: If the API request fails for any reason
    """

    # Build the complete API endpoint URL
    base_url = (base_url or PANW_AI_SEC_ENDPOINT).rstrip("/")
    url = f"{base_url}/v1/scan/sync/request"

    # Generate a unique tracking ID for this security scan
    # This helps correlate requests with responses in logs
    transaction_id = str(uuid.uuid4())
    print(f"Generated transaction ID: {transaction_id}")

    # Set up HTTP headers for the API request
    # These tell the server how to process our request
    headers = {
        "Content-Type": "application/json",  # Request body contains JSON data
        "Accept": "application/json",        # We want JSON response back
        "x-pan-token": api_key              # Authentication token
    }

    # Prepare the request payload with scan parameters
    content = {"prompt": prompt}           # The actual user message
    if response is not None:
        content["response"] = response     # The LLM reply, on the second scan of a turn

    payload = {
        "tr_id": transaction_id,           # Unique identifier for tracking
        "ai_profile": {                    # Security profile configuration
            "profile_name": ai_profile_name
        },
        "metadata": {                      # Attribution shown in SCM sessions and violations
            "app_name": APP_NAME,
            "app_user": APP_USER,
            "ai_model": ai_model or "azure-openai"
        },
        "contents": [content]              # Content to be scanned
    }

    # Display what we're about to scan
    what = "prompt + response" if response is not None else "prompt"
    print(f"\n🔍 Scanning {what} for security threats...")
    print(f"   Content: '{prompt[:50]}...' ({len(prompt)} characters)")

    try:
        # Send POST request to Palo Alto Networks API. The timeout keeps the
        # chatbot from hanging forever if the network path is broken.
        api_response = requests.post(url, headers=headers, json=payload, timeout=30)

        # Check if the HTTP request was successful (status code 200-299)
        api_response.raise_for_status()

        # Parse the JSON response from the API
        scan_result = api_response.json()

        # Display formatted security scan results
        print("\n📋 SECURITY SCAN RESULTS:")
        print("=" * 40)
        print(
            f"Overall Classification: {scan_result.get('category', 'Unknown')}")
        print(f"Recommended Action: {scan_result.get('action', 'Unknown')}")

        # Check for specific threat types detected
        # Check for specific threat types detected
        print("\n⚠️  SPECIFIC THREATS IDENTIFIED:")
        print("=" * 40)

        # Define threat category mappings for better display
        threat_categories = {
            # Prompt-based threats
            'prompt_injection': 'Prompt Injection Attack',
            'injection': 'Prompt Injection Attack',  # Alternative naming
            'jailbreak': 'Jailbreak Attempt',
            'malicious_code': 'Malicious Code Generation',
            'sensitive_data': 'Sensitive Data Exposure',
            'toxicity': 'Toxic Content',
            'bias': 'Bias Detection',
            'harmful_content': 'Harmful Content',

            # Response-based threats
            'url_cats': 'Malicious URL Detection',
            'malware': 'Malware Detection',
            'db_security': 'Database Security Threat',
            'dlp': 'Data Loss Prevention',
            'pii': 'Personal Identifiable Information',
            'financial_data': 'Financial Data Exposure',
            'intellectual_property': 'Intellectual Property Risk',
            'code_injection': 'Code Injection',
            'resource_overload': 'Resource Overload/DoS',
            'hallucination': 'AI Hallucination',
        }

        threats_found = False

        # Debug: Show the actual API response structure.
        # prompt_detected covers the user's message; response_detected is only
        # populated when a response was included in the request. AIRS does not
        # predict the model's output, it inspects what was actually sent.
        print(f"🔍 DEBUG - Raw API Response:")
        print(f"   Category: {scan_result.get('category')}")
        print(f"   Action: {scan_result.get('action')}")
        print(f"   Scan ID: {scan_result.get('scan_id')}  Report ID: {scan_result.get('report_id')}")
        print(f"   Prompt detected: {scan_result.get('prompt_detected', {})}")
        print(
            f"   Response detected: {scan_result.get('response_detected', {})}")

        # Check for prompt-based threats
        prompt_detected = scan_result.get('prompt_detected', {})
        if prompt_detected:
            for threat_type, detected in prompt_detected.items():
                if detected:
                    threat_name = threat_categories.get(
                        threat_type, threat_type.replace('_', ' ').title())
                    print(f"🔴 PROMPT THREAT: {threat_name}")
                    threats_found = True

        # Check for response-based threats
        response_detected = scan_result.get('response_detected', {})
        if response_detected:
            for threat_type, detected in response_detected.items():
                if detected:
                    threat_name = threat_categories.get(
                        threat_type, threat_type.replace('_', ' ').title())
                    print(f"🔴 RESPONSE THREAT: {threat_name}")
                    threats_found = True

                    # Show additional details for specific threat types
                    if threat_type == 'url_cats' and detected:
                        print(f"   └─ Malicious URL detected in content")
                    elif threat_type == 'db_security' and detected:
                        print(f"   └─ Database security violation detected")
                    elif threat_type == 'dlp' and detected:
                        print(f"   └─ Data loss prevention policy triggered")

        # Check for additional threat indicators
        if scan_result.get('category') == 'malicious' and not threats_found:
            print(f"🔴 GENERAL THREAT: Content classified as malicious")
            threats_found = True

        if not threats_found:
            print("✅ No specific threats detected")
        print("=" * 40)
        return scan_result

    # Handle different types of HTTP and network errors
    except requests.exceptions.HTTPError as http_err:
        # Server returned an error status code (4xx or 5xx)
        print(f"❌ HTTP Error: {http_err}")
        print(f"   Server Response: {http_err.response.text}")
        print("   This typically indicates authentication issues or server problems")
        return None

    except requests.exceptions.ConnectionError as conn_err:
        # Could not establish connection to the server
        print(f"❌ Connection Error: {conn_err}")
        print("   Check your internet connection and firewall settings")
        return None

    except requests.exceptions.Timeout as timeout_err:
        # Request took too long to complete
        print(f"❌ Timeout Error: {timeout_err}")
        print("   The API server is not responding within the expected time")
        return None

    except requests.exceptions.RequestException as req_err:
        # Any other request-related error
        print(f"❌ Request Error: {req_err}")
        print("   An unexpected network error occurred")
        return None

    except json.JSONDecodeError as json_err:
        # Server response was not valid JSON
        print(f"❌ JSON Decode Error: {json_err}")
        print(f"   Raw Response: {api_response.text}")
        print("   The server returned malformed data")
        return None


def main():
    """
    MAIN CHATBOT CONTROLLER

    Orchestrates the complete secure chatbot workflow:
    1. Validates required environment variables and credentials
    2. Initializes Azure OpenAI client
    3. Runs the interactive chat loop
    4. Processes each message through security scanning
    5. Forwards approved messages to Azure OpenAI for response generation

    SECURITY ARCHITECTURE:
    - All user inputs are scanned before AI processing
    - Messages classified as malicious are blocked
    - Only benign messages proceed to AI generation
    - No conversation history is maintained for security reasons
    """

    print("🚀 INITIALIZING SECURE AI CHATBOT")
    print("=" * 60)
    print("Security Layer: Palo Alto Networks Runtime Security API")
    print("AI Processing: Azure OpenAI GPT Models")
    print("=" * 60)
    print("\nConfiguration: Each message is independently scanned")
    print("No conversation history is stored for enhanced security")

    # CREDENTIAL VALIDATION SECTION
    # Check for required Palo Alto Networks environment variables
    print("\n🔑 VALIDATING SECURITY CREDENTIALS...")

    # Retrieve Palo Alto Networks API credentials from environment
    pan_api_key = os.getenv("PANW_AI_SEC_API_KEY")
    pan_ai_profile_name = os.getenv("PANW_AI_SEC_PROFILE_NAME")

    # Validate Palo Alto Networks credentials are present
    if not pan_api_key:
        print("❌ ERROR: Missing PANW_AI_SEC_API_KEY environment variable")
        print("   This variable must contain your Palo Alto Networks API key")
        print("   Set it using: export PANW_AI_SEC_API_KEY='your-api-key'")
        return

    if not pan_ai_profile_name:
        print("❌ ERROR: Missing PANW_AI_SEC_PROFILE_NAME environment variable")
        print("   This variable must contain your AI Security Profile name")
        print("   Set it using: export PANW_AI_SEC_PROFILE_NAME='profile-name'")
        return

    print("✅ Palo Alto Networks credentials validated")

    # Check for required Azure OpenAI environment variables
    print("\n🔑 VALIDATING AZURE OPENAI CREDENTIALS...")

    # Azure OpenAI resource name
    azure_project = os.getenv("AZURE_PROJECT")
    azure_key = os.getenv("AZURE_KEY")              # Azure OpenAI access key
    azure_deploy = os.getenv("AZURE_DEPLOY")        # Deployed model name

    # Validate all Azure credentials are present
    if not all([azure_project, azure_key, azure_deploy]):
        print("❌ ERROR: Missing Azure OpenAI environment variables")
        print("   Required variables:")
        print("   - AZURE_PROJECT: Your Azure OpenAI resource name")
        print("   - AZURE_KEY: Your Azure OpenAI access key")
        print("   - AZURE_DEPLOY: Your deployed model name (e.g., 'gpt-4')")
        print("   Set these variables before running the application")
        return

    print("✅ Azure OpenAI credentials validated")

    # AZURE OPENAI CLIENT INITIALIZATION
    print("\n🧠 INITIALIZING AZURE OPENAI CLIENT...")

    azure_client = None
    # Construct the Azure OpenAI endpoint URL
    azure_endpoint = f"https://{azure_project}.openai.azure.com/"

    try:
        # Initialize the Azure OpenAI client with configuration. TLS
        # verification is left ON (an earlier version disabled it, which
        # silently exposed the Azure key to any on-path interceptor). If your
        # network uses a TLS-inspecting proxy, point SSL_CERT_FILE at your
        # corporate CA bundle instead of turning verification off.
        azure_client = AzureOpenAI(
            azure_endpoint=azure_endpoint,
            api_key=azure_key,
            api_version=AZURE_API_VERSION,
        )
        print("✅ Azure OpenAI client initialized successfully")

    except Exception as e:
        # Handle client initialization failures
        print(f"❌ Failed to initialize Azure OpenAI client: {e}")
        print("   Azure OpenAI functionality will be unavailable")
        azure_client = None

    # INTERACTIVE CHAT LOOP INITIALIZATION
    print("\n" + "=" * 60)
    print("CHATBOT READY FOR INTERACTION")
    print("=" * 60)
    print("Commands:")
    print("• Type your message and press Enter to chat")
    print("• Type 'exit' to terminate the program")
    print("• All messages undergo security scanning before AI processing")

    # Main conversation loop - continues until user exits
    while True:
        # Get user input and remove leading/trailing whitespace
        user_input = input("\n👤 You: ").strip()

        # Check for exit command
        if user_input.lower() == 'exit':
            print("\n👋 Session terminated. Goodbye!")
            break

        # Validate input is not empty
        if not user_input:
            print("⚠️  Please enter a non-empty message.")
            continue

        # SECURITY SCANNING PHASE
        print("\n🔒 SECURITY SCANNING PHASE")
        print("=" * 50)

        # Submit user input to Palo Alto Networks for security analysis
        scan_result = scan_prompt_with_paloalto_api(
            user_input, pan_api_key, pan_ai_profile_name, ai_model=azure_deploy)

        # SECURITY DECISION PROCESSING
        if scan_result:
            # Extract security classification and recommended action
            # Expected: 'benign' or 'malicious'
            category = scan_result.get('category')
            # Expected: 'allow' or 'block'
            action = scan_result.get('action')

            print(f"\n🚦 SECURITY ASSESSMENT:")
            print(f"   Classification: {category}")
            print(f"   Recommended Action: {action}")

            # Process security decision based on scan results
            if category == "malicious" or action == "block":
                # MESSAGE BLOCKED - Security threat detected
                print("\n🚫 MESSAGE BLOCKED BY SECURITY")
                print("=" * 40)
                print(f"Security Status: {category.upper()}")
                print(f"Action Taken: {action.upper()}")
                print("\n🤖 Response: This message cannot be processed due to")
                print("   security policy violations. Please modify your")
                print("   message and try again.")
                print("=" * 40)

            elif category == "benign" and action == "allow":
                # MESSAGE APPROVED - Safe to process
                print("\n✅ SECURITY CHECK PASSED")
                print("=" * 40)
                print(f"Security Status: {category.upper()}")
                print(f"Action: {action.upper()}")
                print("Proceeding to AI processing...")
                print("=" * 40)

                # AI PROCESSING PHASE
                if azure_client:
                    print("\n🧠 AI PROCESSING PHASE")
                    print("=" * 50)
                    print("Generating AI response...")

                    try:
                        # Send approved message to Azure OpenAI for processing
                        response = azure_client.chat.completions.create(
                            model=azure_deploy,
                            messages=[
                                # System message defines AI behavior and personality
                                {
                                    "role": "system",
                                    "content": "You are a helpful, knowledgeable, and professional assistant."
                                },
                                # User message contains the actual prompt
                                {
                                    "role": "user",
                                    "content": user_input
                                },
                            ],
                            # Response generation parameters
                            # Controls randomness (0.0-1.0)
                            temperature=0.7,
                            max_tokens=800,         # Maximum response length
                            top_p=0.95,            # Nucleus sampling parameter
                            frequency_penalty=0,    # Reduces repetitive content
                            presence_penalty=0,     # Encourages topic diversity
                            stop=None              # No custom stop sequences
                        )

                        # Extract the generated response text
                        ai_response = response.choices[0].message.content or ""

                        # RESPONSE SCANNING PHASE
                        # The model output goes back to Palo Alto together with
                        # the prompt, so leaked sensitive data, malicious URLs
                        # or code, toxic content, and dangerous SQL in the reply
                        # are caught before anything is displayed.
                        print("\n🔒 RESPONSE SCANNING PHASE")
                        print("=" * 50)
                        response_scan = scan_prompt_with_paloalto_api(
                            user_input, pan_api_key, pan_ai_profile_name,
                            response=ai_response, ai_model=azure_deploy)

                        if response_scan is None:
                            # Fail closed: an unscanned reply is not shown.
                            print("\n❌ RESPONSE SCAN FAILED")
                            print("🤖 Response: The AI reply could not be security scanned,")
                            print("   so it was not displayed. Please try again.")
                        elif response_scan.get("category") == "malicious" or response_scan.get("action") == "block":
                            print("\n🚫 AI RESPONSE BLOCKED BY SECURITY")
                            print("=" * 40)
                            print(f"Security Status: {str(response_scan.get('category')).upper()}")
                            print(f"Action Taken: {str(response_scan.get('action')).upper()}")
                            print("\n🤖 Response: The AI generated a reply that violates the")
                            print("   security profile, so it was withheld.")
                            print("=" * 40)
                        else:
                            # Display the AI-generated response
                            print("\n" + "=" * 60)
                            print("🤖 AI RESPONSE:")
                            print("=" * 60)
                            print(ai_response)
                            print("=" * 60)

                    except Exception as azure_err:
                        # Handle Azure OpenAI processing errors
                        print(f"\n❌ AZURE OPENAI ERROR: {azure_err}")
                        print("🤖 Response: A technical error occurred during")
                        print("   AI processing. Please try again later.")

                else:
                    # Azure OpenAI client is not available
                    print("\n⚠️  AZURE OPENAI UNAVAILABLE")
                    print("🤖 Response: Your message passed security screening,")
                    print("   but AI processing is currently unavailable due to")
                    print("   configuration issues.")

            else:
                # UNEXPECTED SECURITY RESULT
                print(f"\n⚠️  UNEXPECTED SECURITY RESULT")
                print(f"   Category: {category}")
                print(f"   Action: {action}")
                print("🤖 Response: Received an unexpected security assessment.")
                print("   Please verify your Palo Alto Networks configuration.")

        else:
            # SECURITY SCAN FAILURE
            print("\n❌ SECURITY SCAN FAILED")
            print("🤖 Response: Unable to complete security scanning.")
            print("   Please check your Palo Alto Networks API configuration")
            print("   and network connectivity.")


# PROGRAM ENTRY POINT
if __name__ == "__main__":
    """
    Program execution starts here when script is run directly.

    This conditional ensures main() only runs when this file is executed
    directly, not when imported as a module by other Python scripts.
    """
    main()
