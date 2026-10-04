// The latest released version, read at build time from CHANGELOG.md so the
// site's version badge cannot drift from what was actually tagged.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const log = readFileSync(resolve(process.cwd(), '..', 'CHANGELOG.md'), 'utf8');
const m = log.match(/^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}/m);
if (!m) throw new Error('release: no "## [x.y.z] - date" heading in CHANGELOG.md');

export const release = `v${m[1]}`;
export const releaseUrl = `https://github.com/dshakes/halos/releases/tag/${release}`;
// The site documents main; this is the same docs tree frozen at the tag.
export const releaseDocsUrl = `https://github.com/dshakes/halos/tree/${release}/docs/src/content/docs`;
