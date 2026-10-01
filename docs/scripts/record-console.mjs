// Records the console walkthrough on the landing page from a live `make demo`
// stack: sign in as alice, open experiments, kill one, open a feature toggle and
// kill it too, then see the kills in the audit log. Drives headless Chrome over CDP (Node 22's WebSocket, no deps),
// captures a screencast and encodes WebM + MP4 + GIF + a JPEG poster into
// docs/public/media/console.*. Never hand-edit those.
//
//   make demo && node docs/scripts/record-console.mjs && make demo-down
// Needs Chrome (CHROME=path to override) and ffmpeg on PATH.
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const W = 1280, H = 800, PORT = 9336;
const BASE = process.env.HALO_DEMO_CONSOLE_URL || 'http://localhost:18080';
const out = resolve(dirname(fileURLToPath(import.meta.url)), '../public/media');
const tmp = mkdtempSync(join(tmpdir(), 'halos-console-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const proc = spawn(chrome, ['--headless=new', '--disable-gpu', '--hide-scrollbars', `--remote-debugging-port=${PORT}`,
  `--user-data-dir=${join(tmp, 'profile')}`, `--window-size=${W},${H}`, '--force-device-scale-factor=1', '--no-first-run', 'about:blank'], { stdio: 'ignore' });

let tgt;
for (let i = 0; i < 100 && !tgt; i++) {
  await sleep(100);
  try { tgt = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === 'page'); } catch {}
}
if (!tgt) throw new Error('chrome did not start');
const ws = new WebSocket(tgt.webSocketDebuggerUrl);
await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
let id = 0;
const pend = new Map();
const frames = [];
const send = (method, params = {}) => new Promise((r, j) => { const i = ++id; pend.set(i, { r, j }); ws.send(JSON.stringify({ id: i, method, params })); });
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pend.has(m.id)) { const p = pend.get(m.id); pend.delete(m.id); m.error ? p.j(new Error(JSON.stringify(m.error))) : p.r(m.result); return; }
  if (m.method === 'Page.screencastFrame') {
    frames.push({ t: m.params.metadata.timestamp, data: m.params.data });
    send('Page.screencastFrameAck', { sessionId: m.params.sessionId });
  }
  // The console asks window.confirm before a kill; accept it as a person would.
  if (m.method === 'Page.javascriptDialogOpening') send('Page.handleJavaScriptDialog', { accept: true });
};
const js = async (expr) => (await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result.value;
const until = async (expr, ms = 15000) => { for (let t = 0; t < ms; t += 100) { if (await js(expr)) return; await sleep(100); } throw new Error('timeout waiting for ' + expr + '\npage: ' + (await js('document.body.innerText')).slice(0, 1500)); };

// A visible cursor (recording overlay only) so viewers can follow the clicks.
const overlay = `(() => { if (document.getElementById('rc-cur')) return true;
  const d = document.createElement('div'); d.id = 'rc-cur';
  d.style.cssText = 'position:fixed;z-index:2147483647;left:${W / 2}px;top:${H / 2}px;width:24px;height:24px;margin:-12px 0 0 -12px;border-radius:50%;' +
    'border:2px solid #ffb547;background:rgba(255,181,71,.18);box-shadow:0 0 18px rgba(255,106,61,.55);pointer-events:none;' +
    'transition:left .65s cubic-bezier(.4,0,.2,1),top .65s cubic-bezier(.4,0,.2,1),transform .14s';
  document.body.appendChild(d);
  window.__find = (sel, txt) => [...document.querySelectorAll(sel)].find((e) => (e.innerText || e.getAttribute('aria-label') || '').trim().startsWith(txt));
  return true; })()`;
async function click(sel, txt) {
  await until(`(${overlay}) && !!__find(${JSON.stringify(sel)}, ${JSON.stringify(txt)})`);
  await js(`(() => { const e = __find(${JSON.stringify(sel)}, ${JSON.stringify(txt)}); e.scrollIntoView({ block: 'nearest' });
    const r = e.getBoundingClientRect(), c = document.getElementById('rc-cur');
    c.style.left = (r.left + Math.min(r.width / 2, 60)) + 'px'; c.style.top = (r.top + r.height / 2) + 'px'; })()`);
  await sleep(800);
  await js(`document.getElementById('rc-cur').style.transform = 'scale(.7)'`);
  await sleep(160);
  await js(`document.getElementById('rc-cur').style.transform = ''; { const e = __find(${JSON.stringify(sel)}, ${JSON.stringify(txt)}); e.focus(); e.click(); }`);
}
async function type(text) {
  for (const ch of text) { await send('Input.insertText', { text: ch }); await sleep(55); }
}

let posterIdx = -1;
try {
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: BASE + '/' });
  await until(`document.readyState === 'complete' && !!document.querySelector('a[href="/auth/login"]')`);
  await send('Page.startScreencast', { format: 'jpeg', quality: 88, maxWidth: W, maxHeight: H, everyNthFrame: 1 });
  await sleep(1200);
  await click('a', 'Continue');                       // -> demo IdP (DEV ONLY, no passwords)
  await until(`location.port === '18081' || location.href.includes('/authorize')`);
  await sleep(900);
  await click('a', 'alice@acme.com');                 // -> back to the console as alice
  await until(`location.port !== '18081' && document.body.innerText.includes('Running experiments')`);
  await sleep(1800);
  await click('a', 'Experiments');
  await until(`document.body.innerText.includes('KILL SWITCH') || document.body.innerText.includes('Kill switch')`);
  await sleep(1400);
  await click('a', 'opus-5-5-canary');
  await until(`location.hash.includes('opus-5-5-canary')`);
  await sleep(1500);
  await click('input', 'Kill switch reason');
  await type('p95 latency spike on the canary');
  await sleep(400);
  await click('button', 'Kill switch');
  await until(`document.body.innerText.includes('Kill switch engaged')`);
  await sleep(1300);
  await js(`window.scrollTo({ top: 0, behavior: 'smooth' })`);
  await until(`document.body.innerText.includes('p95 latency spike on the canary')`);
  await sleep(2600);
  posterIdx = frames.length - 1;
  // Feature toggles: open one, read its rules, kill it with a reason (no release, no PR).
  await click('a', 'Toggles');
  await until(`document.body.innerText.includes('Feature toggles') && document.body.innerText.includes('github-mcp')`);
  await sleep(1600);
  await click('a', 'github-mcp');
  await until(`location.hash.includes('github-mcp') && document.body.innerText.toLowerCase().includes('who gets it?')`);
  await sleep(2200);
  await click('aside button', 'Propose change');     // ramp it to 25%: a validated policy PR (a local branch in the demo)
  await sleep(900);
  await click('input', 'Rollout percent');
  await type('25');
  await click('input', 'Proposal reason');
  await type('ramp the canary slice to 25 percent');
  await sleep(400);
  await click('button', 'Open PR');
  await until(`document.body.innerText.includes('PR opened')`);
  await sleep(2400);
  await click('aside button', 'Kill');                // opens the reason dialog
  await until(`!!document.querySelector('[role="dialog"][aria-modal="true"] input')`);
  await sleep(600);
  await type('GitHub MCP is returning 5xx');
  await sleep(500);
  await click('button', 'Kill toggle');
  await until(`document.body.innerText.includes('Killed by')`);
  await sleep(2600);
  await click('aside button', 'Close');
  await sleep(900);
  await click('a', 'Audit log');
  await until(`document.body.innerText.includes('opus-5-5-canary')`);
  await sleep(3000);
  await send('Page.stopScreencast');
} finally {
  try { ws.close(); } catch {}
  proc.kill('SIGKILL');
}

// Frames arrive only when the page paints; hold each until the next one.
if (frames.length < 10) throw new Error(`only ${frames.length} frames captured`);
let list = '';
frames.forEach((f, i) => {
  const name = join(tmp, `f${String(i).padStart(5, '0')}.jpg`);
  writeFileSync(name, Buffer.from(f.data, 'base64'));
  const dur = i + 1 < frames.length ? Math.max(frames[i + 1].t - f.t, 0.01) : 2.5;
  list += `file '${name}'\nduration ${dur.toFixed(3)}\n`;
  if (i + 1 === frames.length) list += `file '${name}'\n`;
});
writeFileSync(join(tmp, 'list.txt'), list);
const ff = (...a) => execFileSync('ffmpeg', ['-loglevel', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', join(tmp, 'list.txt'), ...a], { stdio: 'inherit' });
const cfr = 'fps=24,scale=1280:-2:flags=lanczos,format=yuv420p';
ff('-an', '-vf', cfr, '-c:v', 'libvpx-vp9', '-b:v', '0', '-crf', '38', '-row-mt', '1', join(out, 'console.webm'));
ff('-an', '-vf', cfr, '-c:v', 'libx264', '-crf', '28', '-preset', 'slow', '-movflags', '+faststart', join(out, 'console.mp4'));
ff('-vf', 'fps=8,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle', join(out, 'console.gif'));
// Poster: the kill switch panel showing the active kill.
writeFileSync(join(out, 'console.jpg'), Buffer.from(frames[posterIdx].data, 'base64'));
rmSync(tmp, { recursive: true, force: true });
console.log(`recorded ${frames.length} frames -> ${out}/console.{webm,mp4,gif,jpg}`);
