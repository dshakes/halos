#!/bin/sh
# One-shot (runs in the halo-server demo image, which has git): a local bare repo as the
# policy remote plus the writer clone halo-server proposes from, so the console's
# "Propose change" opens a real branch. DEV ONLY; lives on the policy-repo volume.
set -eu
base=main # portal.json policyBase
if [ -d /repo/writer/.git ]; then echo "policy-repo: already initialised"; exit 0; fi
git config --global user.name "Halos demo"
git config --global user.email "demo@halos.invalid"
git init -q --bare -b "$base" /repo/remote.git
tmp=$(mktemp -d)
cp -R /demo/policy/. "$tmp"/
cd "$tmp"
git init -q -b "$base"
git add -A
git commit -qm "demo policy"
git remote add origin /repo/remote.git
git push -q origin "$base" # seeds the local remote only
git clone -q /repo/remote.git /repo/writer
echo "policy-repo: done"
