 Integration Overview

  - Set the Prisma AIRS credentials (PANW_AI_SEC_API_KEY, PANW_AI_SEC_PROFILE_NAME) and the LLM key in your runtime environment; the chatbot
    refuses to start until those variables are present, so matching your .env/secret manager to what secure_chatbot_api.py expects is the first
    integration step (secure_chatbot/secure_chatbot/secure_chatbot_api.py:285-317). The provided env_example.sh shows the required values and lets
    you override the regional endpoint if you’re not using the US service (secure_chatbot/secure_chatbot/env_example.sh).
  - Decide whether you’ll call the REST API directly or use the aisecurity Python SDK. The raw HTTP helper builds the Prisma AIRS request on
    your behalf, while the SDK wrapper handles retries and exposes richer metadata (secure_chatbot/secure_chatbot/secure_chatbot_api.py:68-107,
    secure_chatbot/secure_chatbot/secure_chatbot_python.py:55-149).

  Runtime Flow

  - Every user message is wrapped in a scan/sync/request call that Prisma AIRS documents at pan.dev: the payload contains a unique tr_id, the AI
    security profile name, and a contents array of prompts to inspect (secure_chatbot/secure_chatbot/secure_chatbot_api.py:68-97). Headers include
    x-pan-token with your key plus JSON content-negotiation (secure_chatbot/secure_chatbot/secure_chatbot_api.py:77-84).
  - The SDK variant internally seeds the same structure, but centralizes endpoint selection and automatically replays failed calls with
    exponential backoff before surfacing an AISecSDKException (secure_chatbot/secure_chatbot/secure_chatbot_python.py:101-149).

  Response Handling

  - Prisma AIRS responds with a categorical decision and detailed threat booleans. The sample app inspects category (benign vs malicious)
    and action (allow vs block) to gate downstream processing, then logs any specific detections from prompt_detected or response_detected
    such as prompt-injection, DLP, URL categories, or toxicity (secure_chatbot/secure_chatbot/secure_chatbot_api.py:118-195, secure_chatbot/
    secure_chatbot/secure_chatbot_python.py:200-274). If anything is flagged, the request is stopped before the LLM sees it; otherwise it passes
    through to Claude.
  - Robust error handling around HTTP failures, timeouts, and malformed responses ensures your app can surface actionable diagnostics and
    avoid silently bypassing the security layer (secure_chatbot/secure_chatbot/secure_chatbot_api.py:199-229, secure_chatbot/secure_chatbot/
    secure_chatbot_python.py:130-149).

  SDK Path

  - Initializing aisecurity with your key, profile, and optional custom endpoint centralizes configuration and supports async scanning
    via SDKSecurityScanner.async_scan, which lets you keep your main loop responsive while Prisma AIRS evaluates content (secure_chatbot/
    secure_chatbot/secure_chatbot_python.py:55-194, 299-360).
  - The SDK demo also surfaces Prisma AIRS metadata—transaction IDs, report IDs, runtime—so you can stitch results into observability pipelines or
    audit logs out of the box (secure_chatbot/secure_chatbot/secure_chatbot_python.py:200-212).

  Operational Tips

  - Generate and persist a transaction ID per scan to correlate Prisma AIRS reports with user interactions (secure_chatbot/secure_chatbot/
    secure_chatbot_api.py:71-75, secure_chatbot/secure_chatbot/secure_chatbot_python.py:90-94).
  - Prisma AIRS supports multiple regional endpoints; pass an alternate base URL to the helper or inject it through configuration to stay aligned
    with your tenancy (secure_chatbot/secure_chatbot/secure_chatbot_api.py:32-37, secure_chatbot/secure_chatbot/secure_chatbot_python.py:55-66).
  - Treat the AIRS verdict as the authoritative gate in your pipeline: only invoke your LLM, agent, or downstream workflow when the scan
    explicitly returns benign/allow, and bubble threat details back to your UI or logging so users and operators know why something was blocked
    (secure_chatbot/secure_chatbot/secure_chatbot_api.py:365-444, secure_chatbot/secure_chatbot/secure_chatbot_python.py:299-444).

  Next steps you might take: 1) reconcile the profile-name environment variable naming between your config files and runtime, 2) wrap the
  scan helper into your own middleware or message broker so every inbound/outbound turn is inspected, 3) wire the Prisma AIRS report IDs into
  monitoring to cross-reference with the detailed report described at https://pan.dev/prisma-airs/api/airuntimesecurity/scan/scan-sync-request/.
