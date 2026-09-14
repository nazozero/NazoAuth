#!/usr/bin/env python3
"""Dependency-free executable case-registry contract for the real HTTP gate."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


CaseRegistry = tuple[tuple[str, str, dict[str, object]], ...]
CaseHandler = Callable[[str, dict[str, object]], None]


class RuntimeCaseEvidence:
    def __init__(self, required: frozenset[str]) -> None:
        self.required = required
        self.active_case: str | None = None
        self._asserted = False

    def begin(self, case: str) -> None:
        if self.active_case is not None:
            raise AssertionError(
                f"nested runtime case execution: active={self.active_case}, next={case}"
            )
        self.active_case = case
        self._asserted = False

    def observe(self, name: str, condition: bool) -> None:
        if name not in self.required:
            return
        if self.active_case is None:
            raise AssertionError(f"runtime case assertion outside active case: {name}")
        if name != self.active_case:
            raise AssertionError(
                f"runtime case assertion for wrong active case: active={self.active_case}, asserted={name}"
            )
        if not condition:
            raise AssertionError(f"runtime case assertion failed: {name}")
        if self._asserted:
            raise AssertionError(f"duplicate runtime case assertion: {name}")
        self._asserted = True

    def finish(self) -> None:
        active = self.active_case
        asserted = self._asserted
        self.abort()
        if not asserted:
            raise AssertionError(f"runtime case handler did not assert its active case: {active}")

    def abort(self) -> None:
        self.active_case = None
        self._asserted = False


def validate_case_registry(registry: CaseRegistry) -> None:
    """The loaded registry is authoritative: names must be unique and each case
    must name a handler. Case count or membership is not frozen."""
    names = [name for name, _, _ in registry]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    unnamed = [name for name, handler, _ in registry if not handler]
    if duplicates or not names or unnamed:
        raise AssertionError(
            f"invalid case registry: empty={not names}, duplicates={duplicates}, "
            f"missing_handler={unnamed}"
        )


def execute_case_registry(
    registry: CaseRegistry,
    handlers: Mapping[str, Any],
    *,
    evidence: RuntimeCaseEvidence,
) -> tuple[str, ...]:
    validate_case_registry(registry)
    required = frozenset(name for name, _, _ in registry)
    if set(handlers) != {handler for _, handler, _ in registry}:
        raise AssertionError("runtime case handler map does not match the registry")
    if evidence.required != required:
        raise AssertionError("runtime evidence does not cover the registry")

    executed: list[str] = []
    for name, handler_name, parameters in registry:
        handler = handlers[handler_name]
        if not callable(handler):
            raise AssertionError(f"runtime case handler is not callable: {handler_name}")
        evidence.begin(name)
        try:
            handler(name, dict(parameters))
        except BaseException:
            evidence.abort()
            raise
        evidence.finish()
        executed.append(name)

    if frozenset(executed) != required or len(executed) != len(required):
        raise AssertionError("executed runtime cases are not exact")
    return tuple(executed)
