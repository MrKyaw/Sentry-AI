"""Credential attack detection: brute force, password spraying, and success after failures."""

from __future__ import annotations

import re
import statistics
from collections import deque
from collections.abc import Iterable
from dataclasses import replace

from sentry_ai.conditioning.filters import robust_threshold
from sentry_ai.conditioning.windowing import window_index
from sentry_ai.core.registry import register
from sentry_ai.core.signal import Alert, Event, EventKind, Tactic
from sentry_ai.detectors.base import Cooldown, Detector, ratio_score

# FTP, SSH, Telnet, POP3, IMAP, IMAPS, POP3S, RDP, VNC.
AUTH_PORTS: tuple[int, ...] = (21, 22, 23, 110, 143, 993, 995, 3389, 5900)
DEFAULT_LOGIN_PATHS = (
    r"/(login|log-in|signin|sign-in|logon|auth|authenticate|session|sessions|token"
    r"|oauth2?/token|wp-login\.php|j_security_check)/?($|\?)"
)
UNKNOWN_USER = "?"


def _accounts(users: Iterable[str]) -> tuple[str, ...]:
    """Accounts to name as related entities; an unlogged account is not one."""
    return tuple(u for u in users if u != UNKNOWN_USER)


def http_login_event(event: Event, login_paths: re.Pattern[str]) -> Event | None:
    """The authentication event behind a web login request, or None.

    A ``POST`` to a path matching ``login_paths`` fails with 401 or 403 and
    succeeds with any other status below 400; other errors are not logins.
    """
    if event.method != "POST" or not login_paths.search(event.uri):
        return None
    if event.status >= 400 and event.status not in (401, 403):
        return None
    return replace(
        event, kind=EventKind.AUTH, dst=event.query or event.dst, success=event.status < 400
    )


@register
class BruteForceDetector(Detector):
    """Sliding-window authentication failure analysis per source and per account.

    - Brute force: failures from one source exceed a robust per-source threshold
      (median + k * MAD-sigma of its past window counts, floored at ``min_failures``).
    - Password spraying: one source fails against ``spray_users`` distinct accounts.
    - Account targeting: one account fails from ``min_failures`` attempts across sources.
    - Success after failures: a success for (source, account) after repeated
      failures, which indicates a likely compromised credential.
    - Session flood (network only): at least ``flow_min_sessions`` short
      connections (median ``bytes_out`` at most ``flow_max_bytes``) from one
      source to one authentication service in the window, for sensors that see
      connections but not the login results.

    Web logins count as authentication: an HTTP ``POST`` to a path matching
    ``http_login_paths`` fails with 401 or 403 and succeeds with any other
    status below 400. The account is the logged user, or ``?`` when the log has
    none (never named as a related entity, so never a disable_user target).
    """

    name = "brute_force"
    tactic = Tactic.CREDENTIAL_ACCESS
    technique = "T1110"
    kinds = frozenset({EventKind.AUTH, EventKind.CONN, EventKind.HTTP})

    def __init__(
        self,
        window_s: float = 300.0,
        min_failures: int = 10,
        spray_users: int = 8,
        mad_k: float = 5.0,
        success_after: int = 5,
        history_windows: int = 288,
        cooldown_s: float = 1800.0,
        auth_ports: Iterable[int] = AUTH_PORTS,
        flow_min_sessions: int = 30,
        flow_max_bytes: float = 10_000.0,
        http_login_paths: str = DEFAULT_LOGIN_PATHS,
    ) -> None:
        self.http_login_paths = re.compile(http_login_paths, re.IGNORECASE)
        self.auth_ports = frozenset(auth_ports)
        self.flow_min_sessions = flow_min_sessions
        self.flow_max_bytes = flow_max_bytes
        self._sessions: dict[tuple[str, str, int], deque[tuple[float, int]]] = {}
        self.window_s = window_s
        self.min_failures = min_failures
        self.spray_users = spray_users
        self.mad_k = mad_k
        self.success_after = success_after
        self.history_windows = history_windows
        self._src_fail: dict[str, deque[tuple[float, str]]] = {}
        self._user_fail: dict[str, deque[tuple[float, str]]] = {}
        self._history: dict[str, deque[int]] = {}
        self._bucket: dict[str, tuple[int, int]] = {}
        self._cooldown = Cooldown(cooldown_s)

    def _prune(self, window: deque[tuple[float, str]], now: float) -> None:
        while window and window[0][0] < now - self.window_s:
            window.popleft()

    def _record_bucket(self, src: str, ts: float) -> None:
        idx = window_index(ts, self.window_s)
        bucket = self._bucket.get(src)
        if bucket is None or bucket[0] != idx:
            if bucket is not None:
                self._history.setdefault(src, deque(maxlen=self.history_windows)).append(bucket[1])
            self._bucket[src] = (idx, 1)
        else:
            self._bucket[src] = (idx, bucket[1] + 1)

    def _session_flood(self, event: Event) -> list[Alert]:
        if event.dst_port not in self.auth_ports:
            return []
        key = (event.src, event.dst, event.dst_port)
        window = self._sessions.setdefault(key, deque())
        window.append((event.ts, event.bytes_out))
        while window and window[0][0] < event.ts - self.window_s:
            window.popleft()
        sessions = len(window)
        if sessions < self.flow_min_sessions:
            return []
        typical = statistics.median(b for _, b in window)
        cooldown_key = ("flow", event.src, event.dst)
        if typical > self.flow_max_bytes or not self._cooldown.ready(cooldown_key, event.ts):
            return []
        self._cooldown.mark(cooldown_key, event.ts)
        return [
            self._alert(
                event.ts,
                event.src,
                ratio_score(sessions / self.flow_min_sessions, base=0.55),
                f"{sessions} short sessions to {event.dst}:{event.dst_port} "
                f"in {self.window_s / 60:.0f} min",
                related=(event.dst,),
                technique="T1110",
                evidence={
                    "sessions": sessions,
                    "target": event.dst,
                    "port": event.dst_port,
                    "median_bytes_out": typical,
                },
            )
        ]

    def process(self, event: Event) -> list[Alert]:
        if event.kind is EventKind.CONN:
            return self._session_flood(event)
        if event.kind is EventKind.HTTP:
            login = http_login_event(event, self.http_login_paths)
            if login is None:
                return []
            event = login
        user = event.user or UNKNOWN_USER
        src_window = self._src_fail.setdefault(event.src, deque())
        self._prune(src_window, event.ts)
        if event.success:
            prior = sum(1 for _, u in src_window if u == user)
            key = ("success", event.src, user)
            if prior >= self.success_after and self._cooldown.ready(key, event.ts):
                self._cooldown.mark(key, event.ts)
                return [
                    self._alert(
                        event.ts,
                        event.src,
                        0.9,
                        f"Successful login as "
                        f"{'an unlogged account' if user == UNKNOWN_USER else user} "
                        f"after {prior} failures",
                        related=_accounts((user,)) + (event.dst,),
                        technique="T1110,T1078",
                        evidence={"failures": prior, "user": user, "target": event.dst},
                    )
                ]
            return []

        src_window.append((event.ts, user))
        self._record_bucket(event.src, event.ts)
        user_window = self._user_fail.setdefault(user, deque())
        user_window.append((event.ts, event.src))
        self._prune(user_window, event.ts)
        alerts: list[Alert] = []

        threshold = robust_threshold(
            list(self._history.get(event.src, ())), self.mad_k, float(self.min_failures)
        )
        failures = len(src_window)
        users = {u for _, u in src_window}
        if failures >= threshold and self._cooldown.ready(("src", event.src), event.ts):
            self._cooldown.mark(("src", event.src), event.ts)
            alerts.append(
                self._alert(
                    event.ts,
                    event.src,
                    ratio_score(failures / threshold),
                    f"{failures} authentication failures in {self.window_s / 60:.0f} min "
                    f"(threshold {threshold:.0f})",
                    related=_accounts(sorted(users))[:10],
                    technique="T1110.001",
                    evidence={
                        "failures": failures,
                        "threshold": round(threshold, 1),
                        "users": len(users),
                    },
                )
            )
        if len(users) >= self.spray_users and self._cooldown.ready(("spray", event.src), event.ts):
            self._cooldown.mark(("spray", event.src), event.ts)
            alerts.append(
                self._alert(
                    event.ts,
                    event.src,
                    ratio_score(len(users) / self.spray_users, base=0.7),
                    f"Password spraying: failures against {len(users)} accounts",
                    related=_accounts(sorted(users))[:10],
                    technique="T1110.003",
                    evidence={"users": len(users), "failures": failures},
                )
            )
        if len(user_window) >= self.min_failures and self._cooldown.ready(("user", user), event.ts):
            self._cooldown.mark(("user", user), event.ts)
            sources = {s for _, s in user_window}
            alerts.append(
                self._alert(
                    event.ts,
                    user,
                    ratio_score(len(user_window) / self.min_failures, base=0.55),
                    f"Account {user} failed {len(user_window)} logins from {len(sources)} sources",
                    related=sorted(sources)[:10],
                    technique="T1110",
                    evidence={"failures": len(user_window), "sources": len(sources)},
                )
            )
        return alerts
