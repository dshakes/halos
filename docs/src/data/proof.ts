// Proof numbers for the landing page, read at build time from the reports in
// the repo. A pattern that stops matching fails the build instead of showing a
// stale or invented number.
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const repo = resolve(process.cwd(), '..');
const read = (p: string) => readFileSync(join(repo, p), 'utf8');
function must(s: string, re: RegExp, what: string): RegExpMatchArray {
  const m = s.match(re);
  if (!m) throw new Error(`landing proof: ${what} not found (pattern ${re})`);
  return m;
}

export function proof() {
  const k8s = read('test/uat/REPORT.md');
  const [, pass, fail] = must(k8s, /\*\*(\d+) PASS, (\d+) FAIL\*\*/, 'k8s UAT totals');
  const [, kdate] = must(k8s, /on (\d{4}-\d{2}-\d{2})T/, 'k8s UAT date');
  const [, hok, hfail] = must(k8s, /helm upgrade rolls both proxy replicas[^|]*\| PASS \| (\d+) ok \/ (\d+) failed/, 'helm upgrade line');

  const cli = read('test/uat/CLI-REPORT.md');
  const [, cpass, cfail, cunv] = must(cli, /\*\*(\d+) PASS, (\d+) FAIL[^*]*?, (\d+) UNVERIFIED/, 'CLI UAT totals');
  const [, cdate] = must(cli, /Latest run: (\d{4}-\d{2}-\d{2})/, 'CLI UAT date');
  const versions = [...cli.matchAll(/^\| (Claude Code|Codex CLI|Gemini CLI|Copilot CLI) \| `([^`]+)`/gm)].map(
    (m) => `${m[1]} ${m[2]}`
  );
  if (versions.length !== 4) throw new Error('landing proof: CLI version table changed');

  const tut = read('docs/src/content/docs/tutorials/kill-a-bad-change.md');
  const [, secs] = must(tut, /real\s+0m(\d+\.\d+)s/, 'toggle kill timing');

  const e2e = readdirSync(join(repo, 'test/e2e'))
    .filter((f) => f.endsWith('_test.go'))
    .reduce((n, f) => n + (read(`test/e2e/${f}`).match(/^func Test\w+\(t \*testing\.T\)/gm)?.length ?? 0), 0);

  return {
    k8s: { pass: +pass, total: +pass + +fail, date: kdate },
    helm: { ok: +hok, failed: +hfail },
    clis: { pass: +cpass, fail: +cfail, unverified: +cunv, date: cdate, versions: versions.join(', ') },
    kill: `${(+secs).toFixed(1)} s`,
    e2e,
  };
}
