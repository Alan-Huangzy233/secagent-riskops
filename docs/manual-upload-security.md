# Manual Upload Security

Manual uploads are untrusted input.

Required controls:

- MIME type allowlist
- file size limits
- content hashing
- malware scanning interface
- secret detection
- personal-data detection
- HTML and script sanitization
- parser isolation
- prompt-injection detection
- provenance and rights metadata
- reviewer audit trail
- candidate-only promotion

Uploaded text is data, not instructions. It must not override system policy, workflow policy, or approval requirements.

Uploaded scripts, macros, binaries, archives, and proof-of-concept code must never be executed automatically.

Scan for passwords, tokens, API keys, private keys, cloud credentials, session cookies, personal email addresses, phone numbers, local paths, internal hostnames, private IP addresses, and customer identifiers.
