#!/usr/bin/env python3
"""Measurement-window cohort accounting for cap_* capacity runs.

The authoritative capacity population is the MEASUREMENT COHORT:
iterations whose ENTRY time falls in [window_start_ms, window_end_ms)
on the scenario clock (contract cap-scenario-window-v1). Whole-run k6
counters (iterations, dropped_iterations, http_req_duration) describe a
different population and must never be mixed into the formal gate.

scheduled_measure is derived exactly from the constant-arrival-rate
schedule: k6 emits arrival k at scenario_start + k*period with
period = time_unit / rate (rational arithmetic — never rate*window_s
floating math). Inputs that cannot be interpreted exactly return None;
callers mark the point INVALID rather than rounding to something
plausible.
"""
from __future__ import annotations

import math
import re
from fractions import Fraction

_UNIT_MS = {"ms": 1, "s": 1000, "m": 60000, "h": 3600000}


def parse_time_unit_ms(value) -> Fraction | None:
    """'1s' / '500ms' / '2m' / '1h' -> milliseconds as exact Fraction.
    Numeric input is treated as already-milliseconds (int ms only —
    fractional floats must carry an explicit unit to be exact)."""
    if value is None:
        return None
    if isinstance(value, int):
        return Fraction(value)
    if isinstance(value, Fraction):
        return value
    if isinstance(value, float):
        return Fraction(value) if value.is_integer() else None
    s = str(value).strip()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s|m|h)", s)
    if not m:
        return None
    return Fraction(m.group(1)) * _UNIT_MS[m.group(2)]


def scheduled_arrivals_in_window(scenario_start_ms, window_start_ms,
                                 window_end_ms, rate, time_unit_ms,
                                 duration_ms=None) -> int | None:
    """Exact count of constant-arrival-rate iterations whose scheduled
    entry time lands in [window_start_ms, window_end_ms).

    Arrival k is scheduled at scenario_start + k*period, k = 0,1,2,...
    with period = time_unit_ms / rate (ms). Window bounds are
    half-open: an arrival exactly at window_start counts, one exactly
    at window_end does not. When duration_ms is known, arrivals past
    scenario_start + duration_ms do not exist (the scenario stops).

    Returns None for any input that cannot be interpreted exactly:
    missing/non-numeric fields, rate <= 0, non-positive time unit,
    window starting before the scenario, or an empty/inverted window.
    """
    try:
        ss = Fraction(scenario_start_ms)
        ws = Fraction(window_start_ms)
        we = Fraction(window_end_ms)
        r = Fraction(rate)
        tu = Fraction(time_unit_ms)
    except (TypeError, ValueError, ZeroDivisionError, OverflowError):
        return None
    if r <= 0 or tu <= 0:
        return None
    if ws < ss or we <= ws:
        return None
    hi = we
    if duration_ms is not None:
        try:
            dur = Fraction(duration_ms)
        except (TypeError, ValueError, ZeroDivisionError, OverflowError):
            return None
        if dur <= 0:
            return None
        hi = min(we, ss + dur)
    if hi <= ws:
        return 0
    period = tu / r
    # smallest k with k*period >= ws-ss  (window start inclusive)
    k_min = math.ceil((ws - ss) / period)
    # smallest k with k*period >= hi-ss  (window end exclusive)
    k_max = math.ceil((hi - ss) / period)
    return max(0, int(k_max - k_min))


def _count(metrics: dict, name: str) -> float:
    entry = metrics.get(name, {})
    values = entry.get("values", entry) if isinstance(entry, dict) else {}
    return float(values.get("count", 0) or 0)


def _trend(metrics: dict, name: str) -> dict:
    entry = metrics.get(name, {})
    values = entry.get("values", entry) if isinstance(entry, dict) else {}
    return {
        "p50": float(values.get("med", 0) or 0),
        "p95": float(values.get("p(95)", 0) or 0),
        "p99": float(values.get("p(99)", 0) or 0),
    }


OUTCOME_NAMES = ("success", "expected_rejection", "local_no_request",
                 "unexpected", "prepare_failed", "prepare_local_failed",
                 "prepare_sut_failed")

# DEPRECATED / NON-GATING (harness-repair): legacy counter-path
# accounting only. Real runs showed the executor's observed schedule
# exceeds the rational plan by more than this bound (+1 at 10min, +5 at
# 30min), so the rational grid can no longer be the authority for drops:
# the formal gate consumes exact stream-measured drops instead. Kept for
# historical/legacy evaluations where no stream evidence exists — it is
# an observed tolerance, never a claim about k6 internals, and must not
# be widened.
BOUNDARY_JITTER_MS = 1


def cohort_accounting(metrics_raw: dict, contract: dict,
                      rate, time_unit_ms) -> dict:
    """Measurement-cohort accounting from raw k6 summary metrics and a
    valid cap-scenario-window-v1 contract. The caller has already run
    contract validity checks; this layer adds population-consistency
    checks and derives scheduled/started/completed/dropped.

    valid=False whenever any required counter is absent or the
    populations are inconsistent — never clamps or guesses."""
    problems: list[str] = []
    out: dict = {"valid": False, "problems": problems}

    ops = _count(metrics_raw, "cap_measure_ops")
    outcomes = {n: int(_count(metrics_raw, f"cap_measure_{n}"))
                for n in OUTCOME_NAMES}
    completed = sum(outcomes.values())
    started = int(_count(metrics_raw, "cap_iter_begin_measure"))
    begins_total = int(_count(metrics_raw, "cap_iter_begin"))
    ends_total = int(_count(metrics_raw, "cap_iter_end"))

    if "cap_iter_begin_measure" not in metrics_raw:
        problems.append("missing:cap_iter_begin_measure")
    if "cap_measure_ops" not in metrics_raw:
        problems.append("missing:cap_measure_ops")

    ws = contract.get("window_start_ms")
    we = contract.get("window_end_ms")
    ss = contract.get("scenario_start_ms")
    dur = contract.get("duration_ms")
    scheduled = scheduled_arrivals_in_window(ss, ws, we, rate,
                                           time_unit_ms, dur)
    schedule_delta = None
    boundary_overshoot = 0
    if scheduled is None:
        problems.append("schedule_not_exactly_interpretable")
    else:
        # Observed bounded schedule/clock boundary uncertainty: the
        # arrival stream runs on a wall-clock executor clock, so up to
        # BOUNDARY_JITTER_MS worth of arrivals may legitimately land on
        # either side of a half-open window edge. Beyond the allowance
        # the counter stream or the contract is lying — never clamped.
        r_per_ms = Fraction(rate) / Fraction(time_unit_ms)
        allowance = max(
            2, int(math.ceil(r_per_ms * BOUNDARY_JITTER_MS)))
        schedule_delta = started - scheduled
        if schedule_delta > allowance:
            problems.append(
                f"scheduled_less_than_started:{schedule_delta}"
                f">{allowance}")
            boundary_overshoot = schedule_delta
        elif schedule_delta > 0:
            boundary_overshoot = schedule_delta
    unfinished = started - completed
    if unfinished != 0:
        # A clean run after gracefulStop has every begin matched by an
        # end. Unfinished iterations are not drops and not successes —
        # the window evidence is incomplete.
        problems.append(f"unfinished_measure:{unfinished}")
    if completed != int(ops):
        problems.append(
            f"outcomes_sum_mismatch:{completed}!={int(ops)}")
    if scheduled == 0:
        problems.append("scheduled_zero")

    # Drop accounting is always non-negative:
    #   schedule_delta     = started - scheduled (raw signed delta)
    #   boundary_overshoot = max(schedule_delta, 0)
    #   drop_lower_bound   = max(scheduled - started, 0) == `dropped`
    #   drop_upper_bound   = |schedule_delta| inside the boundary
    #                        allowance (an overshoot of `o` can mask up
    #                        to `o` real drops), else the plain
    #                        scheduled - started deficit.
    # The formal gate reads drop_upper_bound / scheduled.
    if schedule_delta is None or scheduled is None:
        drop_lower_bound = None
        drop_upper_bound = None
    else:
        drop_lower_bound = max(-schedule_delta, 0)
        drop_upper_bound = (abs(schedule_delta)
                            if abs(schedule_delta) <= allowance
                            else max(-schedule_delta,
                                     boundary_overshoot))
    dropped = drop_lower_bound
    drop_fraction = (drop_lower_bound / scheduled
                     if drop_lower_bound is not None and scheduled
                     else None)
    drop_fraction_upper = (drop_upper_bound / scheduled
                           if drop_upper_bound is not None and scheduled
                           else None)
    # Pre-window drop estimate: strictly derivable only when the window
    # begins inside the scenario (pre cohort exists) and whole-run
    # begins are fully accounted (post cohort empty, i.e. the window
    # ends at scenario end). Labelled estimate, never a gate input.
    pre_drops_est = None
    if (scheduled is not None and dur is not None and we == ss +
            Fraction(dur) and begins_total >= started):
        pre_scheduled = scheduled_arrivals_in_window(
            ss, ss, ws, rate, time_unit_ms, dur)
        pre_started = begins_total - started
        if pre_scheduled is not None:
            pre_drops_est = pre_scheduled - pre_started

    out.update({
        "scheduled": scheduled,
        "started": started,
        "completed": completed,
        "unfinished": unfinished,
        "dropped": dropped,
        "drop_fraction": (round(drop_fraction, 6)
                          if drop_fraction is not None else None),
        "schedule_delta": schedule_delta,
        "drop_lower_bound": drop_lower_bound,
        "drop_upper_bound": drop_upper_bound,
        "drop_fraction_upper": (round(drop_fraction_upper, 6)
                                if drop_fraction_upper is not None
                                else None),
        "boundary_overshoot": boundary_overshoot,
        "ops": int(ops),
        "outcomes": outcomes,
        "unexpected": outcomes["unexpected"],
        "begins_total": begins_total,
        "ends_total": ends_total,
        # informational: pre/post-cohort stragglers interrupted by
        # gracefulStop are legitimate; only measure-cohort unfinished
        # (above) invalidates the window.
        "unfinished_total": begins_total - ends_total,
        "pre_measure_drops_estimate": pre_drops_est,
        "iter_latency_ms": _trend(metrics_raw, "cap_iter_ms"),
        "op_latency_ms": _trend(metrics_raw, "cap_measure_ms"),
        "valid": not problems,
    })
    return out
