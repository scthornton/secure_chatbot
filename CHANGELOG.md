# Changelog

## [Unreleased]

### Security
- TLS certificate verification is back on for the Azure OpenAI client. Both
  chatbots built `httpx.Client(verify=False)`, which exposed the Azure key to
  any on-path interceptor. Behind a TLS-inspecting proxy, set `SSL_CERT_FILE`
  to your corporate CA bundle instead.

### Added
- Response-side scanning: every Azure OpenAI reply is sent back to Prisma
  AIRS (prompt + response) and withheld on a block verdict. The README
  promised this; the code only scanned prompts.
- `PANW_AI_SEC_ENDPOINT` is honored, so EU, India, and Singapore keys work.
  `.env.example` previously documented that the app ignored it.
- `AZURE_API_VERSION` override; the default moved from the retired
  `2024-02-15-preview` to the GA `2024-10-21`.
- Scan metadata (`app_name`, `app_user`, `ai_model`) on every request, with
  `PANW_AI_SEC_APP_NAME` / `PANW_AI_SEC_APP_USER` overrides.

### Changed
- HTTP calls to the scan API now carry a 30 second timeout (the API variant
  had none).
- SDK variant maps scan-API errors correctly: 401 is an auth failure, 400 is a
  bad request (usually a wrong profile name), 429 and 5xx retry with backoff.
  The old code reported 404 as "profile not found", which AIRS never returns.
- `requirements.txt` no longer needs `httpx[http2]` or the `openai<3` cap,
  since the custom HTTP client that required them is gone.
- README: removed the Tkinter UI section (there is no GUI), fixed the SDK
  example to the real `Scanner.sync_scan(content=Content(...))` signature,
  added the India and Singapore endpoints, and documented the metadata
  fields the API actually accepts.
- `setup_script.py` no longer tests for `tkinter`.
- `tips.md`: corrected stale file paths and a reference to Claude.

## [1.0.0]

### Added
- Secure chatbot integrated with Palo Alto Networks Prisma AIRS
- API and SDK implementations
- Setup script for easy configuration

[Unreleased]: https://github.com/scthornton/secure_chatbot/commits/main
