# Attribution

Code in this repository is copied from [SigSentinel](../../../Projects/sigsentinel) at commit `161fa478d372726a0c192f3a7b481dbb55a7a232`, then repackaged as `sentry_ai` with import renames and a minimal replay pipeline.

| Sentry-AI path | SigSentinel source |
|----------------|-------------------|
| `src/sentry_ai/core/signal.py` | `src/sigsentinel/core/signal.py` |
| `src/sentry_ai/core/net.py` | `src/sigsentinel/core/net.py` |
| `src/sentry_ai/core/registry.py` | `src/sigsentinel/core/registry.py` (register only) |
| `src/sentry_ai/conditioning/filters.py` | `src/sigsentinel/conditioning/filters.py` |
| `src/sentry_ai/conditioning/windowing.py` | `src/sigsentinel/conditioning/windowing.py` |
| `src/sentry_ai/features/baseline.py` | `src/sigsentinel/features/baseline.py` |
| `src/sentry_ai/detectors/base.py` | `src/sigsentinel/detectors/base.py` |
| `src/sentry_ai/detectors/brute_force.py` | `src/sigsentinel/detectors/brute_force.py` |
| `src/sentry_ai/detectors/ddos.py` | `src/sigsentinel/detectors/ddos.py` |
| `src/sentry_ai/detectors/failed_states.py` | `FAILED_STATES` from `src/sigsentinel/detectors/port_scan.py` |
| `src/sentry_ai/fusion/evidence.py` | `src/sigsentinel/fusion/evidence.py` |
| `src/sentry_ai/agent/decision/engine.py` | `src/sigsentinel/agent/decision/engine.py` |
| `src/sentry_ai/agent/pipeline.py` | Extract of `_detect`, `_ingest`, `_assess` from `src/sigsentinel/agent/orchestrator.py` |
