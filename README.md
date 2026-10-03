# Sentry-AI

**Sentry-AI** is a compact, standalone demonstration of cybersecurity **signal processing** code taken from [SigSentinel](../../sigsentinel). It replays synthetic telemetry through streaming detectors, fuses evidence into a risk score, and maps risk to analyst-facing decision levels—without requiring a live network sensor.

Use this repository for **learning, prototypes, and demos**. For live Zeek deployment, the full detector set, and production response workflows, use SigSentinel.

## What is included

| Layer | Components |
|-------|------------|
| Signal conditioning | EWMA, Welford, MAD, robust z-scores, tumbling/sliding windows |
| Baselines | Hour-of-week seasonal baselines |
| Detectors (sample) | `brute_force`, `ddos` (full SigSentinel modules, repackaged) |
| Fusion & decision | Time-decayed noisy-OR risk, kill-chain bonus, hysteresis levels |
| Runtime | Sync replay pipeline, CLI, optional Streamlit demo UI |

## What is not included

Live Zeek/netflow ingestion, remaining SigSentinel detectors, campaign/intrusion correlators, incidents, SOAR actions, advisor/LLM, and the **production** FastAPI + analyst dashboard stack. Those remain in the main SigSentinel project.

## Quick start

See **[START.md](START.md)** for install, tests, CLI demo, and demo UI steps.

```bash
pip install -e ".[dev]"
pytest
sentry-ai demo
```

## Demo (recommended UI)

For demos, use the **Streamlit replay dashboard** (fixture-based, works offline):

```bash
pip install -e ".[dashboard]"
streamlit run src/sentry_ai/serving/demo_dashboard.py
```

Pick a scenario, click **Run replay**, and walk through metrics, level transitions, and alert tables.

| Mode | Best for |
|------|----------|
| **Streamlit dashboard** | Audience-facing demo; visual tables and metrics |
| **`sentry-ai demo` (CLI)** | Terminal-only or CI; JSON summary |
| **SigSentinel API + dashboard** | Live agent, approvals, and full analyst console (main repo) |

## Test results

Formal scope, test matrix, and scenario benchmarks: **[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)**.

## Architecture

```
JSONL fixtures → Pipeline → Detectors → Alerts → RiskFusion → DecisionEngine → levels / JSON
```

## Provenance

Module-level mapping to SigSentinel sources: [ATTRIBUTION.md](ATTRIBUTION.md).

## License

MIT — see [LICENSE](LICENSE).
