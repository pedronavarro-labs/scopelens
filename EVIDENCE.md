# Evidence contract — schema 1

A manifest contains `schema_version: 1` and a `github` object:

| Field | Meaning |
| --- | --- |
| `evidence` | `declared` for manual input; `github-app-api` for collector output. Neither label is cryptographically verified. |
| `permissions` | Map from GitHub permission name to `none`, `read`, `write`, `admin`. Unknown names are retained and compared to the task; levels are ordinal, not independent capabilities. |
| `repository_selection` | `selected`, `all`, or `unknown`. An all-repository installation merits review even if the current list is small. |
| `repositories` | Listed `owner/name` identifiers, normalized case-insensitively. |
| `repositories_complete` | Whether the supplied enumeration is complete for its evidence source. For API collection this is the App user's visible list, not all repositories the installation could reach. |

Missing permission keys are treated as `none` in the supplied map, not proof of an API denial. Extra fields are not copied into reports. The collector enumerates all pages (up to 100 pages of 100 items), checks total counts, and fails rather than recording a partial success. Concurrent changes with identical counts remain possible; collection is not an atomic snapshot.

Installation permissions differ from effective user/token access. User permissions, narrower tokens, repository rules, organization controls, expiry and server behavior can restrict actions. ScopeLens does not perform any write probes, and retains an explicit effective-access evidence gap in every report. Suspended installations fail collection.

MCP config findings use `static-config` evidence. A command or URL reveals neither effective OS privileges nor tools exposed. `readOnlyHint` is a hint, not permission enforcement. Unknown optional server fields are ignored; no client-specific semantics are claimed.

## Rule families

`GH_PERMISSION_EXCESS/MISSING`, `GH_EXTRA_REPOSITORY`, `GH_TARGET_NOT_LISTED`, `GH_ALL_REPOSITORIES`, `GH_SCOPE_UNKNOWN`, `GH_EFFECTIVE_ACCESS_UNKNOWN`, `GH_DECLARED_INPUT`.

`MCP_LOCAL_EXECUTION`, `MCP_PACKAGE_RUNNER`, `MCP_PLAINTEXT_HTTP`, `MCP_CREDENTIAL_REVIEW`, `MCP_CAPABILITIES_UNKNOWN`.

Warnings call for human review; unknowns mark missing evidence. There is no numerical security score. Package runner warnings also apply to pinned packages because integrity remains a separate check. HTTP loopback warnings require context. Credential heuristics may miss secrets or flag harmless query parameters; all raw MCP values are excluded independently of those heuristics.

## Official references checked for this implementation

- [GitHub App user installations and repositories](https://docs.github.com/en/rest/apps/installations): collection endpoints and user-scoped visibility.
- [Create an issue](https://docs.github.com/en/rest/issues/issues#create-an-issue): issues write permission; additional fields can have additional access requirements.
- [Create a pull request review](https://docs.github.com/en/rest/pulls/reviews#create-a-review-for-a-pull-request): pull requests write permission.
- [Repository contents](https://docs.github.com/en/rest/repos/contents#get-repository-content): contents read permission.
- [MCP tool annotations](https://modelcontextprotocol.io/specification/2025-06-18/schema#toolannotations): annotations from untrusted servers must not drive authorization decisions.

The profiles deliberately include metadata read as baseline installation metadata access. They are not an endpoint-by-endpoint authorization proof or a substitute for testing a workflow.
