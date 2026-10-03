"""CLI: replay JSONL fixtures through the signal-processing pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentry_ai.agent.pipeline import Pipeline
from sentry_ai.core.signal import Event, EventKind


def _event_from_dict(data: dict[str, object]) -> Event:
    kind = data.pop("kind")
    if not isinstance(kind, str):
        raise ValueError("event kind must be a string")
    return Event(kind=EventKind(kind), **data)  # type: ignore[arg-type]


def load_events(path: Path) -> list[Event]:
    events: list[Event] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        events.append(_event_from_dict(dict(json.loads(line))))
    return events


def cmd_run(path: Path) -> int:
    events = load_events(path)
    if not events:
        print(f"No events in {path}", file=sys.stderr)
        return 1
    pipeline = Pipeline()
    pipeline.run(events)
    result = pipeline.summary()
    print(json.dumps(result, indent=2))
    return 0


def cmd_demo() -> int:
    root = Path(__file__).resolve().parents[2]
    fixtures = root / "fixtures"
    code = 0
    for name in ("scenario_bruteforce.jsonl", "scenario_ddos.jsonl"):
        path = fixtures / name
        print(f"=== {name} ===")
        code = max(code, cmd_run(path))
        print()
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sentry-AI signal-processing demo")
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="Replay a JSONL fixture")
    run_p.add_argument("fixture", type=Path)
    sub.add_parser("demo", help="Run bundled bruteforce and ddos fixtures")
    args = parser.parse_args(argv)
    if args.command == "run":
        return cmd_run(args.fixture)
    if args.command == "demo":
        return cmd_demo()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
