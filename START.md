# Getting started with Sentry-AI

This guide installs the project, runs validation, demos signal processing, and prepares a **demo** session.

## Prerequisites

- Python **3.10+** (3.12 recommended)
- macOS or Linux (Windows should work; commands use bash)

## 1. Install

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Optional, for the demo UI:

```bash
pip install -e ".[dashboard]"
```

## 2. Verify tests

```bash
pytest -v
```

Expected: **7 passed**. Details and benchmark tables: [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md).

## 3. CLI demo

Run both bundled scenarios:

```bash
sentry-ai demo
```

Or one fixture:

```bash
sentry-ai run fixtures/scenario_bruteforce.jsonl
sentry-ai run fixtures/scenario_ddos.jsonl
```

Output is JSON: events processed, alerts, peak decision levels, and level transitions.

## 4. Demo UI (recommended)

**Why Streamlit here:** Sentry-AI does not ship the full SigSentinel FastAPI agent or live analyst dashboard—they depend on a running Zeek-backed agent. For this subset, a **fixture replay dashboard** gives a clear visual story without external services.

**Steps:**

1. `pip install -e ".[dashboard]"`
2. `streamlit run src/sentry_ai/serving/demo_dashboard.py`
3. In the browser, select **Brute force** or **Distributed flood**
4. Click **Run replay**
5. Present: metrics row → peak levels → transitions → alert table → optional raw JSON

**Talking points:**

- *Signal processing:* baselines and robust thresholds (brute force) vs seasonal z-scores (flood)
- *Fusion:* multiple alerts combine into risk (noisy-OR)
- *Governance:* strong single-detector scores cap at RECOMMEND unless corroborated (SigSentinel policy)

**Backup:** If Streamlit is unavailable, run `sentry-ai demo` and share the JSON in a terminal or slides.

**Live production UI:** Deploy [SigSentinel](../../sigsentinel) with its HTTP API and Streamlit analyst console for real incidents and approvals.

## 5. Project layout (essentials)

| Path | Purpose |
|------|---------|
| `src/sentry_ai/` | Copied SigSentinel signal-processing modules + pipeline |
| `fixtures/` | Synthetic JSONL scenarios |
| `tests/` | Unit and integration tests |
| `docs/TEST_RESULTS.md` | Formal test and scenario results |

## 6. Troubleshooting

| Issue | Action |
|-------|--------|
| `pytest` not found | Activate `.venv` and `pip install -e ".[dev]"` |
| DDoS scenario no alert in custom fixture | Need enough connections in one window; see TEST_RESULTS limitations |
| Streamlit import error | `pip install -e ".[dashboard]"` |

## Next steps

- Extend fixtures with your own JSONL (fields match `Event` in `core/signal.py`)
- Compare behaviour against full SigSentinel for the same detectors
- Read [ATTRIBUTION.md](ATTRIBUTION.md) before publishing forks
