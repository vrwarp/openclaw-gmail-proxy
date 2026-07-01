# CI/CD supply-chain hardening

**The workflow file is not the security boundary.** A pull request can edit
`.github/workflows/*.yml`, and GitHub runs the *edited* file for that PR's
checks. So a guard like "publish only on `main`" written in the file does not,
by itself, stop a PR from removing it. The protections below live **outside**
the file and are what actually stop a malicious PR from publishing an image or
stealing secrets.

## What GitHub already enforces

- **Fork PRs get no secrets and a read-only `GITHUB_TOKEN`.** These workflows use
  the plain `pull_request` event (never `pull_request_target`), so a PR from a
  fork that edits the workflow to push still cannot access `DOCKERHUB_TOKEN` /
  `DOCKERHUB_USERNAME` or write packages — the credentials simply are not there.
- **First-time / outside contributors need maintainer approval** before their PR
  workflows run at all (GitHub default).

The remaining risk is a PR from a **branch inside this repo** (a collaborator),
which *does* receive secrets. Harden that with the settings below.

## Settings to enable (repo → Settings)

1. **Branch protection on `main`** (Settings → Branches → Add rule):
   - Require a pull request before merging, with **≥1 approving review**.
   - **Require review from Code Owners** (activates `.github/CODEOWNERS`, so any
     change under `.github/`, the `Dockerfile`, or `docker-compose.yml` needs the
     owner's approval).
   - Require status checks to pass (CI, Docker dry-run).
   - Do not allow direct pushes / force-pushes to `main`.

2. **Actions → General → Fork pull request workflows**:
   - **Require approval for all external contributors** (or all fork PRs) before
     any workflow runs on their PR.

3. **Actions → General → Workflow permissions**: default `GITHUB_TOKEN` to
   **read-only**; grant elevated scopes per-workflow (this repo's workflows set
   `permissions:` explicitly — least privilege).

4. **Environment-scoped publish secret (strongest):**
   - Create an environment named `release` (Settings → Environments) with a
     **required reviewer** and a **deployment branch rule** limiting it to `main`
     (and/or tags).
   - Store `DOCKERHUB_TOKEN` / `DOCKERHUB_USERNAME` as **environment** secrets on
     `release` (not repo secrets). Then only a job that declares
     `environment: release` — and passes its protection rules — can read them, so
     a PR-triggered job cannot. (To use this, move the publish into a job with
     `environment: release`; ask and it can be wired up.)

## In-repo guardrails already in place

- Docker publish is triggered only on `push` to `main` + `v*` tags; PRs are
  build-only dry runs. A redundant explicit ref pin (`PUBLISH` env) gates the
  login/push steps.
- `.github/CODEOWNERS` marks CI/CD/Docker files as owner-reviewed (needs setting
  #1.b to be enforced).
- Least-privilege `permissions:` in each workflow.
