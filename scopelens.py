"""ScopeLens: evidence-aware, local permission reviews. Python 3.10+."""
import argparse
import html
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener

__version__ = '0.1.0'
LEVELS = {'none': 0, 'read': 1, 'write': 2, 'admin': 3}
PROFILES = {
    'read-code': {'metadata': 'read', 'contents': 'read'},
    'review-pr': {'metadata': 'read', 'contents': 'read', 'pull_requests': 'write'},
    'create-issue': {'metadata': 'read', 'issues': 'write'},
}
LIMIT = 5_000_000
REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')

class InputError(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise InputError(message)

def obj(value, label):
    require(isinstance(value, dict), label + ' must be an object')
    return value

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON keys are not accepted')
        result[key] = value
    return result

def load(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= LIMIT, 'Input exceeds 5 MB')
    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise InputError('Invalid JSON input (details omitted to avoid leaking values)') from None

def repo_names(values):
    require(isinstance(values, list) and all(isinstance(x, str) and REPO.fullmatch(x) for x in values),
            'Repositories must be a list of owner/name identifiers')
    return sorted(set(x.lower() for x in values))

def manifest(data):
    obj(data, 'Manifest')
    require(data.get('schema_version') == 1, 'Unsupported manifest schema_version')
    g = obj(data.get('github'), 'github')
    require(g.get('evidence') in ('declared', 'github-app-api'), 'Unknown evidence type')
    require(g.get('repository_selection') in ('selected', 'all', 'unknown'), 'Invalid repository_selection')
    require(type(g.get('repositories_complete')) is bool, 'repositories_complete must be boolean')
    permissions = obj(g.get('permissions'), 'permissions')
    require(all(isinstance(k, str) and re.fullmatch(r'[a-z_]{1,80}', k) and isinstance(v, str) and v in LEVELS
                for k, v in permissions.items()), 'Invalid permission name or level')
    return {'evidence': g['evidence'], 'repository_selection': g['repository_selection'],
            'repositories_complete': g['repositories_complete'], 'repositories': repo_names(g.get('repositories')),
            'permissions': dict(sorted(permissions.items()))}

def finding(rule, subject, severity, evidence, reason, action):
    return dict(id=rule, subject=subject, severity=severity, evidence=evidence, reason=reason, recommendation=action)

def analyze(data, task, targets):
    require(task in PROFILES, 'Unknown task profile')
    targets = repo_names(targets)
    require(bool(targets), 'At least one target repository is required')
    g = manifest(data)
    required = PROFILES[task]
    findings = []
    rows = []
    for name in sorted(set(required) | set(g['permissions'])):
        actual = g['permissions'].get(name, 'none')
        needed = required.get(name, 'none')
        state = 'excess' if LEVELS[actual] > LEVELS[needed] else 'missing' if LEVELS[actual] < LEVELS[needed] else 'aligned'
        rows.append(dict(permission=name, observed=actual, needed=needed, status=state))
        if state != 'aligned':
            findings.append(finding('GH_PERMISSION_' + state.upper(), name, 'warning', g['evidence'],
                f'{actual} supplied; {needed} expected for {task}.',
                f'Review {name}: {needed}. Confirm other workflows before changing a shared installation.'))
    for repo in sorted(set(g['repositories']) - set(targets)):
        findings.append(finding('GH_EXTRA_REPOSITORY', repo, 'warning', g['evidence'],
            'Repository is outside the requested task scope.', 'Review the selected repository list.'))
    for repo in sorted(set(targets) - set(g['repositories'])):
        findings.append(finding('GH_TARGET_NOT_LISTED', repo, 'warning' if g['repositories_complete'] else 'unknown',
            g['evidence'], 'Target repository was not included in this snapshot.',
            'Verify installation selection and the collecting user access; absence is not proof of denial.'))
    if g['repository_selection'] == 'all':
        findings.append(finding('GH_ALL_REPOSITORIES', 'installation', 'warning', g['evidence'],
            'Installation selection is all repositories.', 'Consider selected repositories for this bounded task.'))
    if not g['repositories_complete'] or g['repository_selection'] == 'unknown':
        findings.append(finding('GH_SCOPE_UNKNOWN', 'installation', 'unknown', g['evidence'],
            'Repository scope is incomplete or unspecified.', 'Collect a complete snapshot before reducing scope.'))
    findings.append(finding('GH_EFFECTIVE_ACCESS_UNKNOWN', 'installation', 'unknown', g['evidence'],
        'Installation grants or declared permissions are not effective token authorization.',
        'Verify token restrictions, user access, repository rules and organization policy separately. No writes were attempted.'))
    if g['evidence'] == 'declared':
        findings.append(finding('GH_DECLARED_INPUT', 'installation', 'unknown', 'declared',
            'Input was supplied manually and has not been verified against GitHub.', 'Validate the manifest against installation settings.'))
    return {'schema_version': 1, 'engine_version': __version__, 'task': task, 'targets': targets,
            'github': g, 'permissions': rows, 'findings': findings,
            'summary': 'Review required; this is not a security certification.'}

SECRET_KEY = re.compile(r'token|secret|password|authorization|api.?key|credential', re.I)
PLACEHOLDER = re.compile(r'^\$\{[A-Za-z_][A-Za-z0-9_:.-]*\}$|^\$[A-Za-z_][A-Za-z0-9_]*$')

def mcp_findings(config):
    obj(config, 'MCP config')
    require(set(config) == {'mcpServers'}, 'MCP config must contain only mcpServers (JSON format)')
    servers = obj(config['mcpServers'], 'mcpServers')
    require(bool(servers), 'mcpServers must not be empty')
    out = []
    for number, (name, spec) in enumerate(servers.items(), 1):
        # Do not echo user-controlled aliases, commands, URLs, paths or values.
        subject = f'mcp-server-{number}'
        obj(spec, 'MCP server')
        def add(rule, severity, reason, action):
            out.append(finding(rule, subject, severity, 'static-config', reason, action))
        command, url = spec.get('command'), spec.get('url')
        require(bool(command) != bool(url), 'Each MCP server needs exactly one command or url')
        args = spec.get('args', [])
        require(isinstance(args, list) and all(isinstance(x, str) for x in args), 'MCP args must be strings')
        env = obj(spec.get('env', {}), 'MCP env')
        headers = obj(spec.get('headers', {}), 'MCP headers')
        require(all(isinstance(v, str) for v in list(env.values()) + list(headers.values())), 'MCP env and header values must be strings')
        literal = any(SECRET_KEY.search(k) and v and not PLACEHOLDER.fullmatch(v) for k,v in list(env.items()) + list(headers.items()))
        literal = literal or any(re.search(r'(?i)(?:--?(?:token|password|secret|api-key)(?:=|$)|(?:token|password|secret)=|gh[pousr]_[A-Za-z0-9]+|github_pat_)', x) for x in args)
        if command:
            require(isinstance(command, str), 'MCP command must be a string')
            add('MCP_LOCAL_EXECUTION', 'unknown', 'Configured server runs as a local process; OS access is not described here.',
                'Review the executable and isolate untrusted servers. ScopeLens never starts it.')
            if command.replace('\\', '/').split('/')[-1] in ('npx', 'uvx'):
                add('MCP_PACKAGE_RUNNER', 'warning', 'A package runner is configured; version and artifact integrity need review.',
                    'Pin an exact version and verify its origin. Pinning alone does not prove safety.')
        else:
            require(isinstance(url, str), 'MCP url must be a string')
            try:
                u = urlsplit(url)
                require(u.scheme in ('http', 'https') and bool(u.hostname), 'MCP URL must use HTTP or HTTPS')
            except ValueError:
                raise InputError('Invalid MCP URL') from None
            if u.scheme == 'http':
                add('MCP_PLAINTEXT_HTTP', 'warning', 'Remote transport uses HTTP without TLS.', 'Use HTTPS for non-local traffic; assess loopback separately.')
            literal = literal or bool(u.username or u.password or u.query or u.fragment)
        if literal:
            add('MCP_CREDENTIAL_REVIEW', 'warning', 'Possible embedded credentials or URL parameters found; values omitted.',
                'Review locally; use your client secret mechanism. Heuristic detection can miss secrets or flag harmless values.')
        add('MCP_CAPABILITIES_UNKNOWN', 'unknown', 'Configuration does not establish tool behavior or effective permissions.',
            'Review server code and runtime authorization. Tool readOnlyHint is not an enforcement boundary.')
    return out

def compare(before, after):
    for report in (before, after):
        require(report.get('schema_version') == 1 and report.get('engine_version') == __version__, 'Incompatible report version')
        obj(report.get('github'), 'Report github')
    require(before['task'] == after['task'] and before['targets'] == after['targets'], 'Reports must use the same task and targets')
    a, b = before['github'], after['github']
    changes = []
    for key in sorted(set(a['permissions']) | set(b['permissions'])):
        old, new = a['permissions'].get(key, 'none'), b['permissions'].get(key, 'none')
        require(old in LEVELS and new in LEVELS, 'Invalid permission level in report')
        if old != new:
            changes.append(dict(kind='permission', subject=key, before=old, after=new, expanded=LEVELS[new] > LEVELS[old]))
    for repo in sorted(set(b['repositories']) - set(a['repositories'])):
        changes.append(dict(kind='repository_added', subject=repo, expanded=True))
    for repo in sorted(set(a['repositories']) - set(b['repositories'])):
        changes.append(dict(kind='repository_removed', subject=repo, expanded=False))
    for key in ('repository_selection', 'repositories_complete', 'evidence'):
        if a[key] != b[key]:
            changes.append(dict(kind=key, before=a[key], after=b[key], expanded=key == 'repository_selection' and b[key] == 'all'))
    # Evidence changes (including new warnings/unknowns) are separately surfaced.
    old_findings = {(f['id'], f['subject'], f['reason']) for f in before['findings']}
    new_findings = [f for f in after['findings'] if (f['id'], f['subject'], f['reason']) not in old_findings]
    return dict(schema_version=1, changes=changes, new_findings=new_findings,
                attention=bool(changes or new_findings), note='Snapshot comparison, not proof of effective access. MCP server numbers follow config order.')

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InputError('GitHub redirect refused; credentials were not forwarded')

def github_get(path, token):
    require(path.startswith('/user/installations'), 'Unsupported GitHub endpoint')
    req = Request('https://api.github.com' + path, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'ScopeLens/0.1.0'})
    try:
        with build_opener(NoRedirect()).open(req, timeout=20) as response:
            raw = response.read(LIMIT + 1)
            require(len(raw) <= LIMIT, 'GitHub response exceeds size limit')
            return json.loads(raw)
    except HTTPError as error:
        raise InputError(f'GitHub returned HTTP {error.code}; check token type, expiry and access. Response body omitted.') from None
    except (URLError, ValueError, TimeoutError):
        raise InputError('GitHub request failed; details omitted to protect credentials') from None

def paginated(path, field, get):
    items = []
    for page in range(1, 101):
        result = obj(get(f'{path}?per_page=100&page={page}'), 'GitHub response')
        chunk = result.get(field)
        require(isinstance(chunk, list), 'Unexpected GitHub pagination response')
        items.extend(chunk)
        if len(chunk) < 100:
            require(type(result.get('total_count')) is int and result['total_count'] == len(items),
                    'Repository/installation list changed or is incomplete; collect again')
            return items
    raise InputError('Pagination limit exceeded; refusing a partial snapshot')

def collect(installation_id, token, get=None):
    require(type(installation_id) is int and installation_id > 0, 'Installation ID must be positive')
    require(isinstance(token, str) and token.strip() and '\n' not in token and '\r' not in token, 'Set SCOPELENS_GITHUB_TOKEN to a GitHub App user access token')
    get = get or (lambda p: github_get(p, token))
    installations = paginated('/user/installations', 'installations', get)
    matches = [x for x in installations if x.get('id') == installation_id]
    require(len(matches) == 1, 'Installation not visible to this GitHub App user token')
    app = matches[0]
    require(not app.get('suspended_at'), 'Installation is suspended; active grants cannot be inferred')
    repos = paginated(f'/user/installations/{installation_id}/repositories', 'repositories', get)
    result = {'schema_version': 1, 'github': {'evidence': 'github-app-api',
        'permissions': app.get('permissions'), 'repository_selection': app.get('repository_selection'),
        'repositories_complete': True, 'repositories': [x.get('full_name') for x in repos]}}
    manifest(result)
    # complete means complete user-visible enumeration, NOT all installation repositories.
    return result

def write_json(path, data):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')

STYLE = '''body{margin:0;background:#0b1220;color:#e4edf7;font:16px/1.6 system-ui,sans-serif}main{max-width:1080px;margin:auto;padding:48px 24px}a{color:#6ce5cb}h1{font-size:clamp(36px,7vw,68px);line-height:1.1;margin:12px 0}h2{margin-top:36px}.eyebrow{letter-spacing:.16em;color:#6ce5cb;font-size:13px}.muted{color:#a4b4c8}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}.card,article{background:#142035;border:1px solid #2c3d55;border-radius:14px;padding:20px;margin:12px 0}.metric{font-size:38px;font-weight:700}.warning,.excess,.missing{color:#ffcc80}.unknown{color:#bcb0ff}.aligned{color:#6ce5cb}.table{overflow:auto}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:13px;border-bottom:1px solid #2c3d55}code{overflow-wrap:anywhere}details{margin:12px 0}summary{cursor:pointer;font-weight:650}footer{margin-top:44px;color:#a4b4c8}nav{display:flex;gap:18px;flex-wrap:wrap}'''

def render(report):
    e = lambda value: html.escape(str(value), quote=True)
    warnings = sum(f['severity'] == 'warning' for f in report['findings'])
    unknown = sum(f['severity'] == 'unknown' for f in report['findings'])
    rows = ''.join('<tr>' + ''.join(f'<td>{e(r[k])}</td>' for k in ('permission','observed','needed')) + f'<td class="{e(r["status"])}">{e(r["status"])}</td></tr>' for r in report['permissions'])
    cards = ''.join(f'<article><span class="{e(f["severity"])}">{e(f["severity"].upper())} · {e(f["id"])}</span><h3>{e(f["subject"])}</h3><p>{e(f["reason"])}</p><p><strong>Next step:</strong> {e(f["recommendation"])}</p><small>Evidence: {e(f["evidence"])}</small></article>' for f in report['findings'])
    repos = ', '.join(report['github']['repositories']) or 'No repositories listed'
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>ScopeLens · Permission review</title><style>{STYLE}</style><main><div class="eyebrow">SCOPELENS / PERMISSION REVIEW / ALPHA</div><h1>Know the scope.<br>See the gaps.</h1><p class="muted">Task: <strong>{e(report['task'])}</strong> · Targets: {e(', '.join(report['targets']))}</p><div class="cards"><div class="card"><div class="metric warning">{warnings}</div>review findings</div><div class="card"><div class="metric unknown">{unknown}</div>evidence gaps</div><div class="card"><div class="metric">{len(report['github']['repositories'])}</div>listed repositories</div></div><p>{e(report['summary'])}</p><h2>Permission comparison</h2><p>Suggested profile, not a universal minimum. Effective token access remains unverified.</p><div class="table"><table><thead><tr><th>Permission</th><th>Supplied</th><th>Task profile</th><th>Comparison</th></tr></thead><tbody>{rows}</tbody></table></div><details><summary>Repository scope and evidence</summary><p>{e(repos)}</p><p>Selection: {e(report['github']['repository_selection'])} · Evidence: {e(report['github']['evidence'])} · Complete enumeration: {e(report['github']['repositories_complete'])}</p><p>API snapshots list repositories visible to the collecting app user token. They may omit repositories the installation can access as another identity. Evidence labels are not signed attestations.</p></details><h2>Findings and next steps</h2>{cards}<footer>ScopeLens {__version__} · Local analysis · No permission changes · No MCP processes started<br>Reports include repository identifiers. Review before sharing.</footer></main></html>'''

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='command', required=True)
    scan = sub.add_parser('scan', help='Compare a normalized manifest with a task profile')
    scan.add_argument('manifest')
    scan.add_argument('--task', choices=PROFILES, required=True)
    scan.add_argument('--repo', action='append', required=True)
    scan.add_argument('--mcp', help='Optional static mcpServers JSON config; never executed')
    scan.add_argument('--output', default='artifacts/review')
    scan.add_argument('--fail-on', choices=('never','warning','unknown'), default='never')
    diff = sub.add_parser('diff', help='Compare two reports, exit 1 on any scope/evidence change')
    diff.add_argument('before'); diff.add_argument('after')
    api = sub.add_parser('collect', help='Read GitHub App installation grants via a GitHub App user token')
    api.add_argument('--installation', type=int, required=True)
    api.add_argument('--output', default='artifacts/manifest.json')
    args = parser.parse_args(argv)
    try:
        if args.command == 'collect':
            write_json(args.output, collect(args.installation, os.environ.get('SCOPELENS_GITHUB_TOKEN')))
            print('Saved installation grants and user-visible repositories. Effective token permissions remain unknown.')
            return 0
        if args.command == 'diff':
            result = compare(load(args.before), load(args.after))
            print(json.dumps(result, indent=2))
            return int(result['attention'])
        report = analyze(load(args.manifest), args.task, args.repo)
        if args.mcp:
            report['findings'].extend(mcp_findings(load(args.mcp)))
        out = Path(args.output)
        write_json(out / 'report.json', report)
        (out / 'report.html').write_text(render(report), encoding='utf-8')
        counts = {s: sum(f['severity'] == s for f in report['findings']) for s in ('warning','unknown')}
        print(f"ScopeLens: {counts['warning']} review findings, {counts['unknown']} evidence gaps. Reports written.")
        return int(args.fail_on != 'never' and (counts['warning'] > 0 or args.fail_on == 'unknown' and counts['unknown'] > 0))
    except (InputError, OSError, KeyError, TypeError, RecursionError):
        # InputError messages are fixed strings or bounded HTTP codes, never supplied values.
        error = sys.exc_info()[1]
        print('ScopeLens: ' + (str(error) if isinstance(error, InputError) else 'Invalid input, response, or output path; details omitted.'), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
