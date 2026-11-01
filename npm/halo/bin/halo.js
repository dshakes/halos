#!/usr/bin/env node
// Launcher for `npx @dshakes/halo`. npm installs only the optional dependency that
// matches this OS and CPU (see package.json); this runs the halo binary inside it.
"use strict";
const { spawnSync } = require("node:child_process");

const os = { darwin: "darwin", linux: "linux", win32: "windows" }[process.platform];
const cpu = { x64: "amd64", arm64: "arm64" }[process.arch];
const pkg = `@dshakes/halo-${os}-${cpu}`;
let bin;
try {
  bin = require.resolve(`${pkg}/bin/halo${process.platform === "win32" ? ".exe" : ""}`);
} catch {
  console.error(
    `halo: no prebuilt binary for ${process.platform}/${process.arch} (${pkg}).\n` +
      "Supported: macOS, Linux and Windows on x64 or arm64. If you installed with\n" +
      "--no-optional or --omit=optional, reinstall without it, or use another install\n" +
      "method: https://github.com/dshakes/halos#install",
  );
  process.exit(1);
}
const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (r.error) {
  console.error(`halo: ${r.error.message}`);
  process.exit(1);
}
process.exit(r.status ?? 1);
