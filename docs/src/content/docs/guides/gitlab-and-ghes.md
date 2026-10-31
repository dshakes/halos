---
title: GitLab and GitHub Enterprise Server
description: Open Halos promotion, rollback, rollout and upgrade changes as GitLab merge requests or through the GitHub API, with a human merging every one.
---

Every Halos change that reaches your policy repo is a review request: a pull request on GitHub or a merge request on GitLab. Halos pushes a `halos/...` branch with `git` and then opens the request. **It never merges, never enables auto-merge and never approves.** A human does all three, under your branch protection.

## Choose a forge

`--forge` picks how the request is opened. It exists on `halo exp promote`, `halo rollout advance|pause|rollback`, `halo controller run`, `halo upgrade check|watch` and `halo mcp serve`, and on `halo-server`.

| `--forge` | Opens the request with | Token |
|---|---|---|
| (empty) | Autodetect from the `origin` remote: `gitlab` if the host name contains `gitlab`, otherwise `gh` | per the result |
| `gh` | `gh pr create` (the default; unchanged) | the `gh` login |
| `github` | GitHub REST API (github.com or GitHub Enterprise Server) | `GITHUB_TOKEN`, else `GH_TOKEN` |
| `gitlab` | GitLab REST API v4 (gitlab.com or self-managed) | `GITLAB_TOKEN` |

GitHub users who set nothing see no change: a `github.com` remote autodetects to `gh`. A self-managed GitLab whose host name does not contain `gitlab` needs `--forge gitlab`.

`--forge-base-url` overrides the API root. By default Halos derives it from the remote: `https://api.github.com` for `github.com`, `https://<host>/api/v3` for any other GitHub host (Enterprise Server), `https://<host>/api/v4` for GitLab. Set it when the API sits behind a different host or path. It must be `https`, or `http` to a loopback host.

The project is read from the `origin` URL (`https://`, `ssh://` or `git@host:path`). A nested GitLab path such as `group/sub/repo` is sent as one URL-encoded segment (`group%2Fsub%2Frepo`).

If the forge is served under a URL prefix, give the full API root: `--forge-base-url https://host/gitlab/api/v4` with the remote `https://host/gitlab/group/sub/repo.git` (or `git@host:gitlab/group/sub/repo.git`). Halos strips the base URL's path before `/api/v4` (or `/api/v3`) from the remote path, so the project is `group/sub/repo`. A remote that does not start with that prefix is used as is.

If the token variable is unset the command stops before pushing anything and names the variable (`no API token: set GITLAB_TOKEN`). Halos never prints a token.

## GitLab

```bash
export GITLAB_TOKEN=...      # from your secret store; never commit it
halo exp promote checkout-model --ring ring1 --release sha256:... --forge gitlab
```

What Halos does:

1. Commits the change on a unique `halos/promote-<name>-<suffix>` branch in a temporary worktree (your checkout is untouched) and `git push`es it. Push credentials are whatever `git` already uses for `origin` (SSH key, credential helper, or a CI job token).
2. `POST /projects/:id/merge_requests` with the source branch, target branch, title and description. The description carries a hidden marker so a restarted controller finds its own request (`GET /projects/:id/merge_requests?search=...&state=all`, paginated) instead of opening a second one.
3. Prints the `web_url`.

**Token scopes.** A personal, project or group access token with the **`api`** scope; merge requests cannot be created with `read_api` or `write_repository` alone. The token's user needs at least the **Developer** role on the project. Use a project access token for a service identity, not a person's.

**Protected branches.** The token's user must be allowed to push `halos/*` branches (allow Developers to push on non-default branches, or add a `halos/*` wildcard rule) and must **not** be allowed to push to or merge into the default branch. Keep the default branch protected with "Allowed to merge: Maintainers" and "Allowed to push: No one".

**Approvals and merge stay human.** Halos sends no `merge_when_pipeline_succeeds`, no auto-merge flag, and never calls the merge or approve endpoints; the tests assert it. Require approvals with a merge request approval rule or `CODEOWNERS` approvals on the default branch, and enable "Prevent approval by author" so the Halos token cannot approve its own request. Add `halo validate` (and `halo freeze check`) as a required pipeline job; the [GitLab CI include](/halos/getting-started/install/) installs a pinned, checksum-verified `halo` for it.

## GitHub through the API

`--forge github` is for hosts without the `gh` binary (a slim container, GitHub Enterprise Server behind a proxy):

```bash
export GITHUB_TOKEN=...
halo controller run --forge github --forge-base-url https://ghe.example.com/api/v3 ...
```

A fine-grained token needs **Pull requests: write** and **Contents: write** on the policy repo; a classic token needs `repo`. Authorise it for SSO if your organisation enforces it. Idempotency scans pull requests of any state, newest first, up to 1,000 per lookup, for the exact marker.

## halo-server and Helm

```bash
halo-server --controller --policy-repo-dir /policy-writer/repo --forge gitlab --forge-base-url https://gitlab.example.com/api/v4
```

`--forge` and `--forge-base-url` apply to the controller's clone. The self-service portal writer takes `policyForge` and `policyForgeBaseURL` in the portal config JSON and falls back to the flags when they are empty.

In the Helm chart:

```yaml
server:
  controller:
    policyRepo:
      enabled: true
      forge: gitlab                       # --forge
      forgeBaseURL: https://gitlab.example.com/api/v4   # --forge-base-url
      gitlabToken: {existingSecret: halos-gitlab, key: token}   # exported as GITLAB_TOKEN
```

With `forge: gitlab` or `github` the halo-server image needs `git` but not `gh`. Open egress to the GitLab host on 443 (API) and 22 or 443 (git) with `networkPolicy.controllerEgress.git`.

## Not verified against a real server

The GitLab and GitHub REST paths are tested against `httptest` fakes of the documented v4 and REST APIs (create, idempotent find, pagination, 401/403/404/409/422/429, self-managed base URLs, nested project paths, and that no merge endpoint or auto-merge field is ever sent). They have not been run against a real GitLab or GitHub Enterprise Server. Try `--forge gitlab` with a throwaway project first.
