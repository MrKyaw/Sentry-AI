from pathlib import Path

from sentry_ai.agent.decision.engine import Level
from sentry_ai.agent.pipeline import Pipeline
from sentry_ai.cli import load_events
from sentry_ai.detectors.brute_force import BruteForceDetector
from sentry_ai.detectors.ddos import DDoSDetector


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def _detectors(*names: str):
    mapping = {"brute_force": BruteForceDetector(), "ddos": DDoSDetector()}
    return [mapping[n] for n in names]


def test_bruteforce_fixture_alerts_and_level():
    events = load_events(FIXTURES / "scenario_bruteforce.jsonl")
    result = Pipeline(detectors=_detectors("brute_force")).run(events)
    assert any(a.detector == "brute_force" for a in result.alerts)
    peaks = result.peak_levels()
    assert peaks.get("203.0.113.10", Level.OBSERVE) >= Level.ALERT


def test_ddos_fixture_alerts_and_level():
    events = load_events(FIXTURES / "scenario_ddos.jsonl")
    result = Pipeline(detectors=_detectors("ddos")).run(events)
    assert any(a.detector == "ddos" for a in result.alerts)
    peaks = result.peak_levels()
    assert any(lvl >= Level.ALERT for lvl in peaks.values())
