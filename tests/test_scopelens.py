import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
import scopelens as s

ROOT = Path(__file__).resolve().parents[1]

def fixture(name='scoped'):
    return s.load(ROOT / 'examples' / (name + '.json'))

def run(data=None, task='read-code'):
    return s.analyze(data or fixture(), task, ['demo/docs'])

class AnalysisTests(unittest.TestCase):
    def test_demo_excess(self):
        r = run(fixture('overprivileged'))
        self.assertEqual(sum(f['severity'] == 'warning' for f in r['findings']), 6)
        self.assertEqual(sum(f['severity'] == 'unknown' for f in r['findings']), 2)
    def test_scoped_is_not_security_certificate(self):
        r = run()
        self.assertFalse(any(f['severity'] == 'warning' for f in r['findings']))
        self.assertIn('GH_EFFECTIVE_ACCESS_UNKNOWN', [f['id'] for f in r['findings']])
    def test_review_requires_pull_request_write(self):
        r = run(task='review-pr')
        self.assertTrue(any(f['id']=='GH_PERMISSION_MISSING' and f['subject']=='pull_requests' for f in r['findings']))
    def test_issue_profile_does_not_require_contents(self):
        d = fixture(); d['github']['permissions']={'metadata':'read','issues':'write'}
        self.assertFalse(any(f['severity']=='warning' for f in run(d,'create-issue')['findings']))
    def test_case_insensitive_repositories(self):
        r = s.analyze(fixture(), 'read-code', ['DEMO/DOCS'])
        self.assertEqual(r['targets'], ['demo/docs'])
    def test_incomplete_missing_target_is_unknown(self):
        d=fixture(); d['github']['repositories']=[]; d['github']['repositories_complete']=False
        self.assertTrue(any(f['id']=='GH_TARGET_NOT_LISTED' and f['severity']=='unknown' for f in run(d)['findings']))
    def test_future_permission_flagged_against_profile(self):
        d=fixture(); d['github']['permissions']['future_permission']='write'
        self.assertTrue(any(f['subject']=='future_permission' and f['id']=='GH_PERMISSION_EXCESS' for f in run(d)['findings']))
    def test_invalid_level_rejected(self):
        d=fixture(); d['github']['permissions']['contents']='superuser'
        with self.assertRaises(s.InputError): run(d)
    def test_invalid_repository_rejected(self):
        d=fixture(); d['github']['repositories']=['https://evil.example/x?token=secret']
        with self.assertRaises(s.InputError): run(d)
    def test_bool_completion_strict(self):
        d=fixture(); d['github']['repositories_complete']='true'
        with self.assertRaises(s.InputError): run(d)
    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'x.json'; p.write_text('{"github":1,"github":2}')
            with self.assertRaises(s.InputError): s.load(p)
    def test_report_html_escapes_untrusted_content(self):
        r=run(); r['findings'][0]['reason']='<script>alert(1)</script>'
        page=s.render(r)
        self.assertNotIn('<script>',page)
        self.assertIn('&lt;script&gt;',page)
        self.assertIn("default-src 'none'",page)

class MCPTests(unittest.TestCase):
    def scan(self,spec): return s.mcp_findings({'mcpServers':{'secret-alias':spec}})
    def test_credential_values_never_echoed(self):
        f=self.scan({'command':'npx','args':['private-package','--token','SECRET-123'], 'env':{'TOKEN':'SECRET-456'}})
        output=json.dumps(f)
        for value in ('secret-alias','SECRET-123','SECRET-456','private-package'):
            self.assertNotIn(value,output)
        self.assertIn('MCP_CREDENTIAL_REVIEW',output)
    def test_http_and_unknown(self):
        ids=[f['id'] for f in self.scan({'url':'http://localhost:123/mcp'})]
        self.assertIn('MCP_PLAINTEXT_HTTP',ids)
        self.assertIn('MCP_CAPABILITIES_UNKNOWN',ids)
    def test_url_secrets_are_omitted(self):
        result=json.dumps(self.scan({'url':'https://user:secret@host/mcp?key=hidden'}))
        self.assertNotIn('hidden',result); self.assertNotIn('user:secret',result)
        self.assertIn('MCP_CREDENTIAL_REVIEW',result)
    def test_hints_cannot_remove_unknown(self):
        self.assertTrue(any(f['severity']=='unknown' for f in self.scan({'command':'python','readOnlyHint':True})))
    def test_env_reference_is_not_literal_secret(self):
        self.assertFalse(any(f['id']=='MCP_CREDENTIAL_REVIEW' for f in self.scan({'command':'python','env':{'TOKEN':'${GITHUB_TOKEN}'}})))
    def test_never_executes_or_connects(self):
        with patch('subprocess.Popen',side_effect=AssertionError('executed')), patch.object(s,'build_opener',side_effect=AssertionError('network')):
            self.scan({'command':'sh','args':['-c','touch /tmp/should-not-run']})
    def test_ambiguous_transport_rejected(self):
        with self.assertRaises(s.InputError): self.scan({'command':'python','url':'https://host/mcp'})
    def test_empty_configuration_rejected(self):
        with self.assertRaises(s.InputError): s.mcp_findings({'mcpServers':{}})

class DiffTests(unittest.TestCase):
    def test_new_write_detected(self):
        result=s.compare(run(),run(fixture('overprivileged')))
        self.assertTrue(result['attention'])
        self.assertTrue(any(x['kind']=='permission' and x['expanded'] for x in result['changes']))
    def test_scope_reduction_is_still_reported(self):
        result=s.compare(run(fixture('overprivileged')),run())
        self.assertTrue(result['attention'])
        self.assertFalse(any(x['expanded'] for x in result['changes']))
    def test_identical_reports(self): self.assertFalse(s.compare(run(),run())['attention'])
    def test_different_task_rejected(self):
        with self.assertRaises(s.InputError): s.compare(run(),run(task='review-pr'))
    def test_incomplete_evidence_detected(self):
        after=run(); after['github']['repositories_complete']=False
        self.assertTrue(s.compare(run(),after)['attention'])
    def test_new_mcp_warning_detected(self):
        after=run(); after['findings']+=s.mcp_findings({'mcpServers':{'x':{'command':'npx'}}})
        self.assertTrue(s.compare(run(),after)['new_findings'])

class CollectorTests(unittest.TestCase):
    def test_collector_sanitizes_and_paginates(self):
        calls=[]
        def get(path):
            calls.append(path)
            if '/7/repositories' not in path:
                return {'total_count':1,'installations':[{'id':7,'permissions':{'metadata':'read','contents':'read'},'repository_selection':'selected','access_tokens_url':'secret'}]}
            return {'total_count':1,'repositories':[{'full_name':'demo/docs','temp_clone_token':'DO_NOT_STORE'}]}
        data=s.collect(7,'TEST_ONLY',get)
        self.assertEqual(data['github']['repositories'],['demo/docs'])
        self.assertNotIn('DO_NOT_STORE',json.dumps(data))
        self.assertEqual(len(calls),2)
        self.assertTrue(all('?per_page=100&page=1' in p for p in calls))
    def test_full_page_fetches_next(self):
        pages=[]
        def get(path):
            pages.append(path)
            return {'total_count':101,'repositories':list(range(100)) if path.endswith('=1') else [100]}
        self.assertEqual(len(s.paginated('/user/installations/7/repositories','repositories',get)),101)
        self.assertEqual(len(pages),2)
    def test_incomplete_api_result_fails(self):
        with self.assertRaises(s.InputError): s.paginated('/user/installations','installations',lambda _: {'total_count':2,'installations':[]})
    def test_missing_token(self):
        with self.assertRaises(s.InputError): s.collect(7,None)
    def test_redirect_refused(self):
        with self.assertRaises(s.InputError): s.NoRedirect().redirect_request(None,None,302,'',{},'https://attacker.example')
    def test_http_error_does_not_echo_body(self):
        opener=unittest.mock.MagicMock()
        opener.open.side_effect=s.HTTPError('https://api.github.com',403,'SECRET',{},None)
        with patch.object(s,'build_opener',return_value=opener):
            with self.assertRaises(s.InputError) as error: s.github_get('/user/installations','HIDDEN')
        self.assertNotIn('SECRET',str(error.exception)); self.assertIn('403',str(error.exception))

class CLITests(unittest.TestCase):
    def test_scan_output_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            args=['scan',str(ROOT/'examples/overprivileged.json'),'--task','read-code','--repo','demo/docs','--output',tmp]
            self.assertEqual(s.main(args),0)
            self.assertEqual(s.main(args+['--fail-on','warning']),1)
            self.assertTrue((Path(tmp)/'report.html').exists())
            self.assertEqual(s.load(Path(tmp)/'report.json')['task'],'read-code')
    def test_invalid_json_error_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'secret.json'; path.write_text('SECRET_INVALID')
            err=io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(s.main(['scan',str(path),'--task','read-code','--repo','demo/docs']),2)
            self.assertNotIn('SECRET_INVALID',err.getvalue())

if __name__=='__main__': unittest.main()
