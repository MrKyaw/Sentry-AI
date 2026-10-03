"""Streamlit replay console for demo (fixture-driven, no live sensor required)."""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from sentry_ai.agent.decision.engine import Level
from sentry_ai.agent.pipeline import Pipeline
from sentry_ai.cli import load_events
from sentry_ai.detectors.brute_force import BruteForceDetector
from sentry_ai.detectors.ddos import DDoSDetector

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "fixtures"


def _run_fixture(path: Path, detector_names: tuple[str, ...]) -> dict[str, object]:
    mapping = {"brute_force": BruteForceDetector(), "ddos": DDoSDetector()}
    pipeline = Pipeline(detectors=[mapping[n] for n in detector_names])
    pipeline.run(load_events(path))
    summary = pipeline.summary()
    summary["fixture"] = path.name
    summary["detectors"] = list(detector_names)
    return summary


def main() -> None:
    st.set_page_config(page_title="Sentry-AI Demo", layout="wide")
    st.title("Sentry-AI — Signal processing demo")
    st.caption(
        "Replay synthetic telemetry through SigSentinel-derived detectors, "
        "risk fusion, and decision levels."
    )

    options = [
        ("Brute force (HTTP logins)", "scenario_bruteforce.jsonl", ("brute_force",)),
        ("Distributed flood (connections)", "scenario_ddos.jsonl", ("ddos",)),
    ]
    labels = [o[0] for o in options]
    choice = st.selectbox("Scenario", range(len(labels)), format_func=lambda i: labels[i])

    _, filename, detectors = options[choice]
    path = FIXTURES / filename

    if st.button("Run replay", type="primary"):
        with st.spinner("Processing events…"):
            result = _run_fixture(path, detectors)

        col1, col2, col3 = st.columns(3)
        col1.metric("Events processed", result.get("events_processed", 0))
        col2.metric("Alerts", result.get("alerts", 0))
        peaks = result.get("peak_levels", {})
        col3.metric("Entities escalated", len(peaks))

        st.subheader("Peak decision levels")
        if peaks:
            st.table([{"Entity": e, "Level": lvl} for e, lvl in peaks.items()])
        else:
            st.info("No entity reached Alert or above.")

        st.subheader("Level transitions")
        changes = result.get("level_changes", [])
        st.dataframe(changes, use_container_width=True) if changes else st.write("None")

        st.subheader("Recent alerts")
        alerts = result.get("top_alerts", [])
        if alerts:
            st.dataframe(
                [
                    {
                        "Time": a["ts"],
                        "Detector": a["detector"],
                        "Entity": a["entity"],
                        "Score": a["score"],
                        "Tactic": a["tactic"],
                        "Summary": a["summary"],
                    }
                    for a in alerts
                ],
                use_container_width=True,
            )
        else:
            st.write("None")

        with st.expander("Raw JSON"):
            st.code(json.dumps(result, indent=2), language="json")


if __name__ == "__main__":
    main()
