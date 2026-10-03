# Test results and benchmark report

**Project:** Sentry-AI v0.1.0  
**Report date:** 2026-10-03  
**Source lineage:** SigSentinel commit `161fa478d372726a0c192f3a7b481dbb55a7a232` (see [ATTRIBUTION.md](../ATTRIBUTION.md))

## Scope of validation

This report covers the **prototype subset** only: online statistics, windowing, seasonal baselines, two streaming detectors (`brute_force`, `ddos`), noisy-OR risk fusion, hysteresis decision levels, and JSONL replay. It does **not** validate live Zeek ingestion, the full detector suite, SOAR response, or production API parity with SigSentinel.

## Test environment

| Item | Value |
|------|--------|
| OS | macOS (darwin) |
| Python | 3.12.8 |
| Test runner | pytest 9.1.1 |
| Install | `pip install -e ".[dev]"` in project virtualenv |

## Automated test suite

**Command:** `pytest -v`

**Result:** **7 passed**, 0 failed, 0 skipped (0.34s)

| Test | Module under test | Assertion |
|------|-------------------|-----------|
| `test_welford_matches_numpy` | `conditioning.filters.Welford` | Mean/std match NumPy on 1000 samples |
| `test_ewma_tracks_level_shift` | `conditioning.filters.EWMA` | Tracks step change 1.0 → 10.0 |
| `test_robust_statistics_ignore_outliers` | MAD, robust z-score, robust threshold | Outlier yields high z; empty history respects floor |
| `test_windows` | `TumblingSum`, `SlidingWindow` | Window close and horizon pruning |
| `test_hour_of_week_baseline_uses_slot_then_fallback` | `HourOfWeekBaseline` | Slot vs entity-wide fallback |
| `test_bruteforce_fixture_alerts_and_level` | Pipeline + `BruteForceDetector` | `brute_force` alert; peak level ≥ ALERT |
| `test_ddos_fixture_alerts_and_level` | Pipeline + `DDoSDetector` | `ddos` alert; peak level ≥ ALERT |

## Scenario benchmarks (fixture replay)

Synthetic JSONL fixtures replay through the full default pipeline (`BruteForceDetector` + `DDoSDetector` + `RiskFusion` + `DecisionEngine`).

**Command:** `sentry-ai demo`

### Scenario A — Credential brute force (`fixtures/scenario_bruteforce.jsonl`)

| Metric | Result |
|--------|--------|
| Events | 15 HTTP POST login failures from one source |
| Alerts | 2 (`brute_force`) |
| Peak level | **ALERT** on `203.0.113.10` (risk 0.60) |
| Detection time (event clock) | First escalation at `ts=1009.0` (10 failures in 5 min window) |
| Technique | T1110.001 (source threshold), T1110 (account `?`) |

### Scenario B — Distributed connection flood (`fixtures/scenario_ddos.jsonl`)

| Metric | Result |
|--------|--------|
| Events | 1250 `conn` records toward `203.0.113.99` within one 60s window |
| Alerts | 1 (`ddos`) |
| Peak level | **ALERT** on `203.0.113.99` (risk 0.63) |
| Detection time (event clock) | Escalation at `ts=2000.47` (~1187 flows when incremental check crosses unseen threshold) |
| Technique | T1498 (distributed flood, no baseline yet) |

## Limitations (explicit non-goals)

- No labelled CTU-13 / CIC-IDS2017 replay or precision/recall tables (those live under SigSentinel EXP-002).
- No AI-agent intrusion scenarios (SigSentinel EXP-003).
- DDoS fixture tuned to SigSentinel’s incremental `_next_check` behaviour (`unseen_min_flows=1000`); fewer than ~1200 events in-window may not alert.
- Brute-force fixture exercises HTTP login path only; network auth-port session flood paths in the copied detector are not covered by fixtures.

## Reproduction

```bash
cd Projects/GitHub_Experiments/Sentry-AI
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
sentry-ai demo
```

To refresh this report, re-run the commands above and update the **Report date** and result tables if outputs change.
