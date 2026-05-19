# CI-Safe Vulnerability Discovery Harness

A lightweight vulnerability discovery harness for GitHub Actions and GitLab CI, inspired by the staged architecture described in Cloudflare's Project Glasswing write-up.

This repository is intentionally **defensive and CI-safe**. It does not generate exploit payloads, weaponized proof-of-concept code, or offensive instructions. The proof stage emits safe verification and regression-test plans only.

## Repo layout

```text
harness/
  vuln_discovery_harness.py        # standalone CI harness
skill/
  ci-safe-vuln-discovery/          # AgentSkill package
    SKILL.md
    scripts/vuln_discovery_harness.py
    references/
.github/workflows/
  vulnerability-discovery.yml      # GitHub Actions workflow
.gitlab-ci.yml                     # GitLab CI job
```

## What it does

The harness runs these stages:

1. **Recon** — inventory files, manifests, extensions, and likely security-boundary areas.
2. **Hunt** — scan for command injection, SQL construction, path traversal, unsafe deserialization, SSRF, and hardcoded secrets.
3. **Validate** — suppress obvious test/fixture noise and raise confidence for stronger signals.
4. **Gapfill** — create follow-up tasks for missing coverage areas and suspicious boundaries.
5. **Dedupe** — collapse likely duplicate root causes.
6. **Trace** — lightweight source-to-sink reachability hints.
7. **Feedback** — create fix-or-dismiss and deeper-review tasks.
8. **Proof** — safe regression-test guidance only.
9. **Report** — structured JSON and Markdown artifacts.

## Outputs

By default, reports are written to `reports/vuln-harness/`:

- `report.json`
- `report.md`
- `findings.json`
- `sources.json`
- `gapfill.json`
- `traces.json`
- `feedback.json`
- `proof_plans.json`

Secret-like evidence is redacted in generated reports.

## Local usage

```bash
python harness/vuln_discovery_harness.py --root . --out reports/vuln-harness --fail-on none
```

Failure policies:

- `none` — always exit 0 after writing reports
- `critical` — fail if unsuppressed critical findings exist
- `validated` — fail if validated candidates exist
- `reachable` — fail if possibly reachable findings exist

## GitHub Actions

Use `.github/workflows/vulnerability-discovery.yml` as-is in this repo, or copy it into another repo with `harness/vuln_discovery_harness.py`.

## GitLab CI

Use `.gitlab-ci.yml` as-is, or merge the job into an existing GitLab pipeline.

## AgentSkill

The `skill/ci-safe-vuln-discovery/` folder is a packaged AgentSkill version of this workflow. Copy or install that folder into an agent skills directory when you want assistants to know how to add, run, tune, and interpret the harness.

## Optional Semgrep pass

If `semgrep` is installed in the CI image, enable an additional Semgrep security-audit pass:

```bash
VULN_HARNESS_RUN_SEMGREP=1 python harness/vuln_discovery_harness.py --root . --out reports/vuln-harness
```

## Important limits

This is a practical CI harness, not a replacement for expert review, CodeQL, SAST/DAST suites, threat modeling, or manual security engineering.

The trace stage is intentionally lightweight. Treat `possibly_reachable` as a review queue signal, not proof of exploitability.

## Safety boundary

The harness is designed for repositories you own or are authorized to assess. Do not use it to target third-party systems without permission.
