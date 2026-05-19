---
name: ci-safe-vuln-discovery
description: Use when asked to add, run, package, or customize a CI-safe staged vulnerability discovery harness for GitHub Actions or GitLab CI. Applies to defensive security review, source-to-sink triage, gapfill/requeue task generation, safe proof/regression planning, and structured vulnerability reports. Trigger for requests mentioning Project Glasswing-style harnesses, vulnerability discovery in CI, security scan workflows, GitHub Actions security harnesses, GitLab CI security jobs, source-to-sink tracing, gapfill, validation/dedupe/report stages, or safe vulnerability research automation.
---

# CI-Safe Vulnerability Discovery

Use this skill to add or operate the bundled staged vulnerability discovery harness in repositories the user owns or is authorized to assess.

Safety boundary: keep this defensive and CI-safe. Do not generate exploit payloads, weaponized PoCs, third-party targeting instructions, or production attack steps. The bundled proof stage creates safe verification and regression-test plans only.

## Core workflow

1. Identify the target repo and CI system:
   - GitHub Actions: add or adapt `.github/workflows/vulnerability-discovery.yml`.
   - GitLab CI: add or adapt `.gitlab-ci.yml` / a `security` stage job.
   - Local/manual: run the script directly.
2. Copy the bundled harness script from `scripts/vuln_discovery_harness.py` into the target repo, usually as `scripts/vuln_discovery_harness.py` or `harness/vuln_discovery_harness.py`.
3. Run a local smoke test before claiming success:
   ```bash
   python scripts/vuln_discovery_harness.py --root . --out reports/vuln-harness --fail-on none
   ```
4. Inspect `reports/vuln-harness/report.md` and `report.json`.
5. Tune CI failure policy:
   - `none` for initial adoption / artifact-only mode.
   - `critical` to block on unsuppressed critical findings.
   - `validated` to block on validated candidates.
   - `reachable` to block on possibly reachable findings.
6. Upload/store all JSON and Markdown artifacts in CI.

## Harness stages

The script emits `schema: vuln-discovery-harness/v2` and runs:

- **Recon**: inventory files, manifests, extensions, and security-boundary hints.
- **Hunt**: find candidate sinks and secrets.
- **Validate**: reduce obvious noise and raise stronger signals.
- **Gapfill**: create follow-up tasks for missing classes and uncovered boundaries.
- **Dedupe**: collapse duplicate/root-cause-like candidates.
- **Trace**: lightweight source-to-sink reachability hints.
- **Feedback**: fix-or-dismiss and deeper review tasks.
- **Proof**: safe regression plan only, never exploit code.
- **Report**: JSON and Markdown outputs.

## Outputs

Default output directory: `reports/vuln-harness/`

Expected files:

- `report.json`
- `report.md`
- `findings.json`
- `sources.json`
- `gapfill.json`
- `traces.json`
- `feedback.json`
- `proof_plans.json`

Never paste raw secret values from source files or reports. The harness redacts report evidence, but source files may still contain sensitive values.

## GitHub Actions pattern

Use this job pattern, adjusting the script path if needed:

```yaml
name: Vulnerability Discovery Harness

on:
  pull_request:
  push:
    branches: [main, master]
  workflow_dispatch:
    inputs:
      fail_on:
        description: "Failure policy: none, critical, validated, or reachable"
        required: false
        default: "none"

permissions:
  contents: read

jobs:
  vuln-discovery:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    env:
      VULN_HARNESS_FAIL_ON: ${{ github.event.inputs.fail_on || 'none' }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: |
          python scripts/vuln_discovery_harness.py \
            --root . \
            --out reports/vuln-harness \
            --fail-on "${VULN_HARNESS_FAIL_ON}"
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vulnerability-discovery-report
          path: reports/vuln-harness/
          if-no-files-found: error
```

## GitLab CI pattern

```yaml
stages:
  - security

vulnerability_discovery_harness:
  stage: security
  image: python:3.11-slim
  timeout: 20m
  variables:
    VULN_HARNESS_FAIL_ON: "none"
  script:
    - python scripts/vuln_discovery_harness.py --root . --out reports/vuln-harness --fail-on "$VULN_HARNESS_FAIL_ON"
  artifacts:
    when: always
    expire_in: 14 days
    paths:
      - reports/vuln-harness/
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
    - if: '$CI_PIPELINE_SOURCE == "web"'
```

## When to read references

- For interpreting report fields and stage semantics, read `references/report-schema.md`.
- For tuning CI rollout, suppression strategy, and failure policy, read `references/ci-rollout.md`.

## Review guidance

Treat results as triage signals, not proof of exploitability. Prioritize:

1. Unsuppressed `critical` findings, especially secret exposure.
2. `validated_candidate` findings.
3. `possibly_reachable` source-to-sink traces.
4. Gapfill tasks that point to uncovered security boundaries.

For low-confidence findings, prefer adding targeted allowlists/suppressions or improving validation logic rather than disabling the whole harness.
