"""Zeek conn_state values for failed connection attempts (from sigsentinel port_scan)."""

from __future__ import annotations

FAILED_STATES: tuple[str, ...] = ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH")
