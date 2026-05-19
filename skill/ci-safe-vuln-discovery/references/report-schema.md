# Report Schema Reference

The harness writes `schema: vuln-discovery-harness/v2` in `report.json`.

## Top-level fields

- `recon`: file inventory, manifests, extensions, boundary hints, stage list.
- `summary`: counts grouped by severity, attack class, and trace status.
- `semgrep`: optional Semgrep result metadata when `VULN_HARNESS_RUN_SEMGREP=1`.
- `sources`: input-like source candidates such as HTTP query/body/params, env, argv, uploads.
- `gapfill`: follow-up tasks for blind spots and uncovered boundaries.
- `findings`: candidate vulnerability records.
- `traces`: lightweight source-to-sink reachability records.
- `feedback`: review/fix/requeue tasks produced from trace and gapfill results.
- `proof_plans`: safe regression-test plans for findings.

## Finding fields

- `id`: stable-ish fingerprint.
- `check_id`: rule identifier.
- `attack_class`: e.g. command injection, SSRF, path traversal, secret exposure.
- `severity`: critical/high/medium/low.
- `file`, `line`, `evidence`: location and redacted snippet.
- `status`: candidate, candidate_low_confidence, validated_candidate, suppressed_test_or_fixture.
- `confidence`: low, needs_review, medium.
- `reachable`: trace status copied onto the finding.
- `trace_ids`: related trace record IDs.
- `proof_plan_id`: related safe proof/regression plan.

## Trace statuses

- `possibly_reachable`: input-like source appears near the sink in the same file.
- `source_same_file_unproven`: source exists in the same file but not near the sink.
- `no_source_observed`: no lightweight source was found in the same file.
- `reachable_not_required`: finding does not need source-to-sink proof, e.g. hardcoded secret.
- `not_applicable`: suppressed finding or trace not applicable.

## Proof plans

Proof plans are deliberately non-offensive. They should guide safe reproduction with synthetic fixtures and regression tests only.
