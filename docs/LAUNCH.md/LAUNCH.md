# ScopeLens early-feedback launch

## One-sentence pitch

ScopeLens shows when an AI agent's GitHub integration can do more than the task requires, while preserving uncertainty about what it can actually do.

## Who this is for

- Security engineers reviewing a GitHub App or agent integration.
- Platform engineers defining a narrow first integration scope.
- Agent builders who need a visible before/after permission discussion.

## The first feedback request

Use a disposable GitHub App or a fully synthetic manifest. Run the before/after demo, then answer:

1. Which first task profile is missing from `read-code`, `review-pr`, and `create-issue`?
2. Which evidence gap would stop you from using the report in a real review?
3. Does the report explain the difference between an installation grant and effective token access clearly enough?

Please do not paste credentials, private repository names, installation identifiers, or real MCP configuration. Use the supplied synthetic fixtures or redact values before opening an issue.

## Five communities to approach manually

Do not mass-post. Read each community's rules first, adapt the text, and post only where tool announcements and security research are welcome.

1. GitHub Community: GitHub Apps and integrations discussions.
2. Model Context Protocol community spaces that explicitly allow project feedback.
3. OWASP community channels focused on LLM/agent security.
4. Python security and platform-engineering meetups or forums.
5. LinkedIn posts aimed at security engineering and developer-platform practitioners.

## Draft launch post

I built ScopeLens after seeing a recurring gap in agent integrations: the task may only need to read code, but the installed app can often write code, manage issues, or reach unrelated repositories.

ScopeLens is a local, dependency-free alpha that compares a GitHub permission snapshot with a small task profile, flags scope and evidence gaps, and reviews an MCP config without starting a server. It does not change permissions or claim to prove effective access.

The repository includes a synthetic before/after walkthrough. I am looking for early feedback from people who review GitHub Apps, build AI agents, or manage developer platforms: which minimal task profile should come next, and what evidence would make this useful in a real review?

https://github.com/pedronavarro-labs/scopelens

## Metrics for the first two weeks

Track manually in `docs/FEEDBACK.md`; do not add analytics to the local report.

- Unique people who give actionable feedback.
- Reproducible synthetic examples contributed.
- Requested task profiles, grouped by workflow.
- Confusions about evidence and permission semantics.
- Follow-up users who run a second example.

The target is five useful conversations, not star count.
