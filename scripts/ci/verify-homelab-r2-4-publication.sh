#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

required=(
  README.md
  docs/homelab/README.md
  docs/homelab/r2-4/README.md
  docs/homelab/r2-4/architecture.md
  docs/homelab/r2-4/deployment-runbook.md
  docs/homelab/r2-4/rollback-and-recovery.md
  docs/homelab/r2-4/qualification-results.md
  docs/homelab/r2-4/qualification-results.json
  docs/homelab/r2-4/defect-closure.md
  docs/homelab/r2-4/publication-boundary.md
  docs/release-engineering-r2-4.md
  docs/governance/public-release-lineage.md
  scripts/deployment/r2-4/README.md
  scripts/deployment/r2-4/harness/config/policy.json
  scripts/deployment/r2-4/harness/SHA256SUMS
)
for path in "${required[@]}"; do
  [[ -f "$path" ]] || { echo "FAIL: missing R2.4 publication file: $path" >&2; exit 1; }
done

python3 - <<'PY'
from __future__ import annotations
import json
import pathlib
import re

root = pathlib.Path('.')
scan_roots = [root / 'docs/homelab', root / 'scripts/deployment/r2-4']
patterns = {
    'private-rfc1918-prefix': re.compile(r'192' + r'\.168\.'),
    'private-ssh-user': re.compile(r'mind' + r'seye73', re.I),
    'private-workstation-user': re.compile(r'piyush' + r'daiya', re.I),
    'macos-user-home': re.compile(r'/Users/[A-Za-z0-9._-]+/'),
    'private-evidence-root': re.compile(r'openwatchlist' + r'-evidence', re.I),
    'tailscale-ip': re.compile(r'(?<![0-9])100\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}(?![0-9])'),
}
problems = []
for base in scan_roots:
    for path in sorted(base.rglob('*')):
        if not path.is_file() or path.name == 'SHA256SUMS':
            continue
        text = path.read_text(encoding='utf-8', errors='ignore')
        for name, pattern in patterns.items():
            if pattern.search(text):
                problems.append(f'{name}: {path}')

policy = json.loads((root / 'scripts/deployment/r2-4/harness/config/policy.json').read_text())
if policy.get('public_template') is not True:
    problems.append('committed harness policy is operational')
if not policy.get('runtime_root', '').startswith('/srv/openwatchlist/'):
    problems.append('public runtime root is not generic')
if not policy.get('stage_root', '').startswith('/srv/openwatchlist/'):
    problems.append('public stage root is not generic')
for host in policy.get('hosts', []):
    if '.example.invalid' not in host.get('hostname', ''):
        problems.append(f'non-example hostname: {host.get("name")}')
    if '.example.invalid' not in host.get('ssh', ''):
        problems.append(f'non-example SSH target: {host.get("name")}')

result = json.loads((root / 'docs/homelab/r2-4/qualification-results.json').read_text())
if result.get('schema') != 'openwatchlist.public-homelab-r2-4-closure.v1':
    problems.append('qualification result schema mismatch')
if result.get('status') != 'DEPLOYED_AND_ROLLBACK_QUALIFIED_R2_4_CONTROLLED_RUNTIME':
    problems.append('qualification result status mismatch')
if result.get('release', {}).get('tag') != 'v0.1.0-rc.4':
    problems.append('qualification release tag mismatch')
if result.get('opt2', {}).get('fixture_kind') != 'synthetic_nonproduction_conformance':
    problems.append('catalog limitation missing')
if any(result.get('publication', {}).get(k) for k in result.get('publication', {})):
    problems.append('sanitized publication flags must all be false')

readme = (root / 'README.md').read_text()
for link in ('docs/homelab/r2-4/README.md', 'scripts/deployment/r2-4/README.md'):
    if link not in readme:
        problems.append(f'root README missing publication link: {link}')

if problems:
    raise SystemExit('FAIL: R2.4 publication boundary:\n' + '\n'.join(f'- {x}' for x in problems))
print('PASS: sanitized R2.4 documentation and policy boundary')
PY

./scripts/deployment/r2-4/harness/scripts/validate-package.sh
./scripts/deployment/r2-4/harness/scripts/self-test.sh

printf 'PASS: OpenWatchlist R2.4 public homelab documentation and sanitized harness\n'
