# Contributing

Start with a small reproducible permission-review case and synthetic inputs. Explain the task, supplied evidence, expected finding and official permission reference. Avoid adding generic risk scores or inferring authorization from tool names.

Run `python -m unittest discover -s tests -v` and `python build_demo.py`. Keep runtime dependencies at zero unless a concrete capability requires one. Include tests for missing evidence and redaction when changing an analyzer. Never include actual tokens or private repository identifiers in fixtures.

Good first contributions: live collector interoperability in a disposable GitHub App, narrowly scoped task profiles, MCP client format adapters, accessibility feedback on HTML reports. Public issues and pull requests are welcome.
