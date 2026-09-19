# ScopeLens

**Your agent needs to read code. Why can its integration also write it?**

ScopeLens compares GitHub App permission snapshots with a defined task, reviews MCP configuration risks without starting servers, and produces an evidence-aware HTML report.

[Español](README.es.md) · [Evidence model](EVIDENCE.md) · [Security](SECURITY.md) · [Demo files](demo/) · [CI](https://github.com/pedronavarro-labs/scopelens/actions)

**0.1.0 alpha · Python 3.10+ · No runtime dependencies · Offline demo · MIT**

## Try it in a minute

```bash
git clone https://github.com/pedronavarro-labs/scopelens.git
cd scopelens
python scopelens.py scan examples/overprivileged.json --task read-code --repo demo/docs --mcp examples/mcp.json --output artifacts/before
python scopelens.py scan examples/scoped.json --task read-code --repo demo/docs --output artifacts/after
```

Open `artifacts/before/report.html` and `artifacts/after/report.html` locally. Or download the repository and open **`demo/index.html`** for the prepared before/after walkthrough. The demo contains only synthetic inputs, not an audit of any real account.

| Demo | Review findings | Evidence gaps |
| --- | ---: | ---: |
| Excessive GitHub grants + MCP config | 9 | 5 |
| Reduced GitHub grants (MCP excluded) | 0 | 2 |

Zero review findings does **not** mean verified safe access. The reduced example still has unverified effective permissions and manually declared evidence. The two reports do not demonstrate remediation of the MCP findings: the second excludes MCP.

## What it does

- Compares permission levels and repository lists with an explicit task profile.
- Flags all-repository installations, extra repositories, missing grants, incomplete scope and unknown effective access.
- Reads supported `mcpServers` JSON configurations statically: possible embedded credentials, plaintext HTTP, package runners and unknown process capabilities.
- Optionally collects GitHub App installation grants and user-visible repositories through two read-only GitHub API endpoints.
- Compares reports for permission, repository, scope and evidence changes.
- Emits standalone HTML and structured JSON, with explanations and suggested next steps.

## Three explicit task profiles

| Profile | Intended workflow | Suggested grants |
| --- | --- | --- |
| `read-code` | Read private repository contents; no PR analysis or posting | `contents:read`, `metadata:read` |
| `review-pr` | Read code and publish a pull request review | Above + `pull_requests:write` |
| `create-issue` | Create a basic issue, without assignment/labels/milestones | `issues:write`, `metadata:read` |

These are bounded starter profiles, not universal minimums. A workflow that assigns people, reads PR discussions, merges code or interacts with other services needs separate analysis. Public resources may be readable without authentication. Permission excess is relative to the selected task, not proof of an exploitable vulnerability.

## Use your own evidence

Copy `examples/scoped.json`, enter the permission levels and repository selection from your installation settings, and keep `evidence` set to `declared`. No token belongs in this file. The normalized schema is described in [EVIDENCE.md](EVIDENCE.md).

Optional installation:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
scopelens --help
```

`scopelens-lab` is the source distribution name; this release is not published on PyPI.

### Read-only GitHub collector

For operators of a GitHub App who already have a **GitHub App user access token**, make that token available as `SCOPELENS_GITHUB_TOKEN` through your local secret manager/environment, then run:

```bash
scopelens collect --installation 123456 --output artifacts/manifest.json
scopelens scan artifacts/manifest.json --task read-code --repo owner/repository
```

Replace the installation ID and repository. Ordinary PATs, OAuth tokens, installation tokens and Actions `GITHUB_TOKEN` are not supported by this collector. It only enumerates installations visible to the authenticating App user token; it does not inventory every app on your account. It does not mint tokens or prompt for them in the CLI.

The collector contacts **`https://api.github.com` only**, makes GET requests, refuses redirects, bounds pages and response size, and discards token-bearing fields from responses. Environment-configured network proxies may apply. Authentication failures produce a sanitized error, never an inferred permission result. A complete enumeration describes the collecting user's view, not the installation's full reach.

Collector transport and pagination are covered by mocked tests. **Live authenticated interoperability has not yet been verified.** Offline scanning works without credentials.

### Static MCP review

```bash
scopelens scan examples/scoped.json --task read-code --repo demo/docs --mcp /path/to/mcp.json
```

Supported format: one top-level `mcpServers` object, with each server using either `command` or `url`, plus optional `args`, `env`, `headers`. JSON only; no JSONC/TOML, includes, or automatic client discovery. Unknown optional server fields are not interpreted. No process is executed, no endpoint is contacted, and no environment reference is resolved. Tool annotations cannot establish real permissions. MCP evidence does not become GitHub permission evidence.

Credential detection is heuristic. Reports omit all MCP aliases, commands, URLs, arguments and environment/header values, even if the heuristic misses a secret. Server numbers correspond to the input order. GitHub repository identifiers and permission names remain in reports; review them before sharing.

### Diff and automation

```bash
scopelens diff artifacts/before/report.json artifacts/after/report.json
scopelens scan examples/scoped.json --task read-code --repo demo/docs --fail-on warning
```

`scan`: exit 0 by default after successful analysis, 1 when the selected gate finds issues, 2 for input/collection/output errors. `--fail-on warning` gates review findings; `--fail-on unknown` gates both warnings and evidence gaps. Expect the latter to fail in this alpha because effective authorization is unverified.

`diff`: exit 1 on **any** scope/evidence change, including reductions, or a new finding; 0 if no such changes; 2 if incompatible/invalid. Inputs must use the same engine version, task and targets. It is a snapshot comparison, not a chronological or signed audit log. Reordering MCP servers can affect finding identities.

## Verification and development

```bash
python -m unittest discover -s tests -v
python build_demo.py
```

Tests cover privilege comparisons, missing/incomplete evidence, pagination, sanitized failures, redaction, HTML escaping, non-execution of MCP commands, drift detection and CLI gates. GitHub Actions also installs the package and runs the installed command. Check the actual run status in [Actions](https://github.com/pedronavarro-labs/scopelens/actions).

## Boundaries and roadmap

No permission enforcement, automatic revocation, malware detection, prompt-injection classifier, effective-token introspection, organization-wide inventory or security certification. JSON evidence can be edited: provenance labels are descriptive, not attestations. No write probes are performed.

Next: validate the collector against a test GitHub App, add endpoint-specific task profiles with fixtures, and support additional MCP client formats. Contributions should include synthetic reproductions and official references.

Built by [Pedro Navarro](https://github.com/pedronavarro-labs). Companion project: [AgentReplay](https://github.com/pedronavarro-labs/agentreplay), for reproducible integration failures.
