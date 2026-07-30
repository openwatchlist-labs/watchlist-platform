#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
[ -f SHA256SUMS ]
shasum -a 256 -c SHA256SUMS
python3 - <<'PY'
import ast,pathlib,sys
root=pathlib.Path('.')
for f in sorted(list((root/'scripts').glob('*.py'))+list((root/'tests').glob('*.py'))):
 ast.parse(f.read_text(encoding='utf-8'),filename=str(f))
for f in sorted((root/'scripts').glob('*.sh')):
 if not (f.stat().st_mode&0o111):raise SystemExit(f'non-executable shell entrypoint: {f}')
for f in sorted((root/'scripts').glob('*.py')):
 if not (f.stat().st_mode&0o111):raise SystemExit(f'non-executable Python entrypoint: {f}')
if list(root.rglob('__pycache__')) or list(root.rglob('*.pyc')):raise SystemExit('compiled Python artifacts are prohibited')
print('PASS: Python syntax and executable-mode validation')
PY
for f in scripts/*.sh;do /bin/bash -n "$f";done
echo 'PASS: shell syntax validation'
TMP=$(mktemp -d);trap 'rm -rf "$TMP"' EXIT
python3 - <<'PY2'
import json
p=json.load(open('config/policy.json',encoding='utf-8'))
if p.get('public_template') is not True:raise SystemExit('public policy must remain a non-operational template')
raw=json.dumps(p)
for forbidden in ('192'+'.168.','mind'+'seye73','piyush'+'daiya','/home/'):
 if forbidden in raw:raise SystemExit(f'private infrastructure marker in public policy: {forbidden}')
for h in p['hosts']:
 if '.example.invalid' not in h['ssh'] or '.example.invalid' not in h['hostname']:raise SystemExit('public hosts must use example.invalid')
print('PASS: public policy is sanitized and non-operational')
PY2
python3 scripts/validate_inputs.py --policy config/policy.json --root . --output "$TMP/input-validation.json" >/dev/null
[ "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$TMP/input-validation.json")" = PASS ]
echo 'PASS: exact activation-input, governed-corpus, passage-checksum, and local source-lock metadata validation'
