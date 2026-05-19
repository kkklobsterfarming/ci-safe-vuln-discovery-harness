# CI Rollout Reference

## Recommended rollout

1. Start with `--fail-on none` and upload artifacts.
2. Review reports for 1-2 pipeline runs.
3. Add suppressions/tuning for clear test fixtures or expected safe sinks.
4. Move to `--fail-on critical` once reports are stable.
5. Consider `validated` or `reachable` only after the team accepts the noise profile.

## Failure policies

- `none`: artifact-only mode, best for adoption.
- `critical`: blocks obvious high-impact issues like unsuppressed secrets.
- `validated`: blocks findings where validation heuristics increased confidence.
- `reachable`: strictest built-in mode; blocks possible reachability signals.

## Artifact handling

Always upload the whole report directory:

- `reports/vuln-harness/`

Do not upload source workspaces or environment dumps. Do not print secrets in CI logs.

## Optional Semgrep

If the CI image has Semgrep installed:

```bash
VULN_HARNESS_RUN_SEMGREP=1 python scripts/vuln_discovery_harness.py --root . --out reports/vuln-harness
```

This writes `semgrep.json` and adds metadata to `report.json`.

## Tuning ideas

- Add repo-specific excludes with repeated `--exclude` flags.
- Keep generated directories, vendored dependencies, and large build artifacts excluded.
- For monorepos, run one job per high-risk component to reduce noise and improve artifact readability.
- For security-sensitive repos, treat `feedback.json` as the review queue input.
