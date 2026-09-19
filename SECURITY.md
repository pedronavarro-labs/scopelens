# Security and privacy

ScopeLens is a permission review aid, not an enforcement boundary or certification.

Offline scan/diff do not use the network or run MCP commands. The optional collector sends an existing GitHub App user token only in the Authorization header to api.github.com, refuses redirects and makes GET requests. It does not create credentials or modify permissions. Network proxies configured by the operator may apply.

Reports omit MCP aliases and raw config values. GitHub repository names and permission names remain; do not publish private inventories. Use synthetic fixtures for public issues. Keep real tokens in a secret manager, never in arguments, examples or screenshots. Files are written with the operating system's normal permissions: choose an appropriately protected output directory.

Inputs and evidence labels are untrusted. A malicious manifest can lie. The HTML renderer escapes inserted strings and uses a restrictive CSP. It has no external scripts, fonts or analytics. No claim of complete secret detection is made. The input size limit is 5 MB; collection has timeouts and pagination bounds. This is not a hostile-input sandbox.

For a vulnerability, prefer GitHub's private vulnerability reporting when available. If it is unavailable, open a minimal issue requesting a private contact without exploit details, secrets or affected private data. No response-time guarantee is provided for this alpha.
