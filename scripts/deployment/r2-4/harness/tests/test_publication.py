from __future__ import annotations
import json,pathlib,re,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class PublicationSafetyTests(unittest.TestCase):
 def test_no_private_infrastructure_markers(self):
  forbidden=[r"192"+r"\.168\.",r"mind"+r"seye73",r"piyush"+r"daiya",r"/"+r"Users/",r"openwatchlist"+r"-evidence"]
  for f in ROOT.rglob("*"):
   if not f.is_file() or f.name=="SHA256SUMS":continue
   text=f.read_text(errors="ignore")
   for pattern in forbidden:self.assertIsNone(re.search(pattern,text),(f,pattern))
 def test_default_entrypoint_fails_before_network(self):
  with tempfile.TemporaryDirectory() as td:
   out=pathlib.Path(td)/"evidence"
   cp=subprocess.run([str(ROOT/"scripts/run-activation-readiness.sh"),"--staging-evidence",str(pathlib.Path(td)/"missing"),"--output",str(out)],capture_output=True,text=True)
   self.assertNotEqual(cp.returncode,0)
   failure=json.loads((out/"failure.json").read_text())
   self.assertEqual(failure["phase"],"operational-policy-validation")
   self.assertIn("public template is non-operational",cp.stderr)
