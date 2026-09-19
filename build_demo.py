"""Generate the offline demo from real analyzer output; no network or secrets."""
from pathlib import Path
import scopelens as s

root=Path(__file__).resolve().parent
out=root/'demo'
out.mkdir(exist_ok=True)
a=s.analyze(s.load(root/'examples/overprivileged.json'),'read-code',['demo/docs'])
a['findings']+=s.mcp_findings(s.load(root/'examples/mcp.json'))
b=s.analyze(s.load(root/'examples/scoped.json'),'read-code',['demo/docs'])
for name, report in [('before',a),('after',b)]:
    (out/(name+'.html')).write_text(s.render(report),encoding='utf-8')
    s.write_json(out/(name+'.json'),report)
(out/'index.html').write_text('''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ScopeLens · Know your agent's scope</title><style>'''+s.STYLE+'''</style><main><div class="eyebrow">PEDRO NAVARRO LABS / SCOPELENS</div><h1>It only needs to read.<br>Why can it write?</h1><p class="muted">A local permission review for GitHub integrations and MCP configurations.</p><div class="cards"><section class="card"><h2>01 / Before</h2><p>An integration can write code, manage issues and administer repositories. Its task is to read one repository.</p><div class="metric warning">9 findings</div><p>Plus 5 evidence gaps, including MCP configuration limits.</p><a href="before.html">Explore the original scope →</a></section><section class="card"><h2>02 / Reduced scope</h2><p>A proposed GitHub manifest only declares reading access to the target. No settings were changed.</p><div class="metric aligned">0 review findings</div><p>2 evidence gaps remain. MCP is excluded here, not remediated.</p><a href="after.html">Inspect the proposed scope →</a></section></div><h2>Evidence before confidence.</h2><p>These are synthetic fixtures analyzed by ScopeLens, not a live account audit. A grant is not proof of effective token access. Tool hints are not permission controls.</p><nav><a href="https://github.com/pedronavarro-labs/scopelens">Source & quick start</a><a href="https://github.com/pedronavarro-labs/agentreplay">Explore AgentReplay</a></nav><footer>Alpha 0.1.0 · MIT · Works offline after download · No tracking<br>Generated with python build_demo.py</footer></main></html>''',encoding='utf-8')
print('Generated demo/index.html and before/after HTML + JSON reports')
