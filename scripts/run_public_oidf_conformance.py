#!/usr/bin/env python3
"""Run the public OIDC/FAPI/FAPI-CIBA matrix as one reversible operation."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oidf_evidence import sanitize_evidence_tree  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ENV = (
    "OIDF_APPLICANT_EMAIL",
    "OIDF_APPLICANT_PASSWORD",
    "OIDF_ADMIN_EMAIL",
    "OIDF_ADMIN_PASSWORD",
    "OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN",
    "OIDF_CIBA_AUTOMATED_DECISION_TOKEN",
)
OFFICIAL_INGRESS_ONLY_WARNING_CONDITIONS = frozenset({"EnsureIncomingTls13"})
class PublicRunError(RuntimeError):
    pass


def origin(value: str, option: str) -> str:
    parsed = urllib.parse.urlsplit(value.rstrip("/"))
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
        raise PublicRunError(f"{option} must be an HTTPS origin without a path")
    return parsed._replace(path="", query="", fragment="").geturl()


def command(args: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=ROOT, env=env, check=True)


def output(args: list[str], *, cwd: Path = ROOT) -> str:
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def verify_source(deployed_sha: str) -> None:
    head = output(["git", "rev-parse", "HEAD"])
    if head != deployed_sha:
        raise PublicRunError(f"checked-out commit {head} does not match --deployed-sha")
    if output(["git", "status", "--porcelain"]):
        raise PublicRunError("product source tree must be clean")


def verify_suite(suite_dir: Path, suite_revision: str) -> None:
    if output(["git", "rev-parse", "HEAD"], cwd=suite_dir) != suite_revision:
        raise PublicRunError(f"suite must be checked out at {suite_revision}")
    if output(["git", "status", "--porcelain"], cwd=suite_dir):
        raise PublicRunError("official conformance-suite source tree must be clean")


def required_environment(token_env: str) -> dict[str, str]:
    names = (*REQUIRED_ENV, token_env)
    missing = [name for name in names if not os.environ.get(name, "").strip()]
    if missing:
        raise PublicRunError(f"missing required environment variables: {', '.join(missing)}")
    return os.environ.copy()


def suite_request(server: str, token: str | None) -> int:
    url = f"{server}/api/plan?start=0&length=1"
    headers = {"Accept": "application/json", "User-Agent": "nazo-public-oidf-runner/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read(1024 * 1024 + 1)
            return response.status
    except urllib.error.HTTPError as error:
        error.read(1024 * 1024 + 1)
        return error.code


def verify_suite_boundary(server: str, token: str) -> None:
    if suite_request(server, None) != 401:
        raise PublicRunError("unauthenticated conformance-suite API request must return 401")
    if suite_request(server, token) != 200:
        raise PublicRunError("authenticated conformance-suite API request must return 200")


def protect_directory(path: Path) -> None:
    if not path.exists():
        return
    path.chmod(0o700)
    for item in path.rglob("*"):
        item.chmod(0o700 if item.is_dir() else 0o600)


def validate_output_paths(work_dir: Path, export_dir: Path, suite_dir: Path) -> None:
    for path, name in ((work_dir, "--work-dir"), (export_dir, "--export-dir")):
        if path == ROOT or path.is_relative_to(ROOT):
            raise PublicRunError(f"{name} must be outside the product source tree")
        if path == suite_dir or path.is_relative_to(suite_dir):
            raise PublicRunError(f"{name} must be outside the conformance-suite source tree")
    paths_overlap = (
        work_dir == export_dir
        or work_dir.is_relative_to(export_dir)
        or export_dir.is_relative_to(work_dir)
    )
    if paths_overlap:
        raise PublicRunError("--work-dir and --export-dir must not contain one another")


class ProxyTrust:
    def __init__(self, target: Path, executable: Path, work_dir: Path) -> None:
        self.target = target.resolve()
        self.executable = executable.resolve()
        self.backup = work_dir / "proxy-trust-bundle.before.pem"
        self.installed = False

    def _validate_and_reload(self) -> None:
        command([str(self.executable), "-t"])
        command([str(self.executable), "-s", "reload"])

    def install(self, approved_bundle: Path) -> None:
        if not self.target.is_file() or not self.executable.is_file():
            raise PublicRunError("proxy trust target and executable must already exist")
        shutil.copyfile(self.target, self.backup)
        self.backup.chmod(0o600)
        trust_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trust_context.load_verify_locations(cafile=str(approved_bundle))
        self.target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=self.target.parent, delete=False) as temporary:
            temporary_path = Path(temporary.name)
            with approved_bundle.open("rb") as source:
                shutil.copyfileobj(source, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.chmod(0o644)
        os.replace(temporary_path, self.target)
        try:
            self._validate_and_reload()
        except BaseException:
            os.replace(self.backup, self.target)
            self._validate_and_reload()
            raise
        self.installed = True

    def restore(self) -> None:
        if not self.installed:
            return
        os.replace(self.backup, self.target)
        self._validate_and_reload()
        self.installed = False


def onboarding_args(action: str, work_dir: Path, issuer: str) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "scripts" / "apply_public_conformance_onboarding.py"),
        action,
        "--target-issuer",
        issuer,
        "--manifest",
        str(work_dir / "oidf-onboarding-manifest.json"),
        "--plan-configs",
        str(work_dir / "oidf-plan-configs.json"),
        "--plan-set",
        str(work_dir / "oidf-plan-set.json"),
        "--plan-manifest",
        str(work_dir / "oidf-plan-set-manifest.json"),
        "--runner-env",
        str(work_dir / "oidf-runner.env"),
        "--delivered-client-material",
        str(work_dir / "oidf-delivered-client-material.json"),
        "--state-file",
        str(work_dir / "oidf-onboarding-state.json"),
        "--trust-bundle",
        str(work_dir / "approved-mtls-trust-anchors.pem"),
    ]


def filter_problem_records(
    source: Path,
    plan_set: Path,
    destination: Path,
    *,
    excluded_conditions: frozenset[str] = frozenset(),
) -> None:
    plans = json.loads(plan_set.read_text(encoding="utf-8"))
    if not isinstance(plans, list) or not all(isinstance(item, str) for item in plans):
        raise PublicRunError(f"{plan_set} must contain a JSON array of plan expressions")
    configs = {expression.rsplit(" ", 1)[-1] for expression in plans}
    records = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
        raise PublicRunError(f"{source} must contain a JSON array of problem records")
    selected = [
        record
        for record in records
        if record.get("configuration-filename") in configs
        and record.get("condition") not in excluded_conditions
    ]
    destination.write_text(json.dumps(selected, indent=2) + "\n", encoding="utf-8")


def split_plan_groups(work_dir: Path) -> tuple[tuple[str, Path, bool], ...]:
    source_files = (
        "oidf-plan-set-concurrent.json",
        "oidf-plan-set-ciba.json",
        "oidf-plan-set-rp-initiated.json",
        "oidf-plan-set-backchannel.json",
        "oidf-plan-set-frontchannel.json",
        "oidf-plan-set-session.json",
    )
    source_plans: dict[str, list[str]] = {}
    for filename in source_files:
        path = work_dir / filename
        plans = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(plans, list) or not all(isinstance(item, str) for item in plans):
            raise PublicRunError(f"{path} must contain a JSON array of plan expressions")
        source_plans[filename] = plans

    concurrent = source_plans["oidf-plan-set-concurrent.json"]

    def matches(*needles: str) -> list[str]:
        return [plan for plan in concurrent if all(needle in plan for needle in needles)]

    grouped: list[tuple[str, list[str], bool]] = [
        ("01-oidc-core", matches("oidcc-basic-certification-test-plan"), False),
        (
            "02-oidc-formpost-thirdparty-config",
            [
                *matches("oidcc-formpost-basic-certification-test-plan"),
                *matches("oidcc-3rdparty-init-login-certification-test-plan"),
                *matches("oidcc-config-certification-test-plan"),
            ],
            False,
        ),
    ]

    ciba = source_plans["oidf-plan-set-ciba.json"]
    for name, client_auth_type, mode in (
        ("03a-fapi-ciba-private-key-jwt-poll", "private_key_jwt", "poll"),
        ("03b-fapi-ciba-mtls-poll", "mtls", "poll"),
        ("03c-fapi-ciba-private-key-jwt-ping", "private_key_jwt", "ping"),
        ("03d-fapi-ciba-mtls-ping", "mtls", "ping"),
    ):
        grouped.append(
            (
                name,
                [
                    plan
                    for plan in ciba
                    if f"client_auth_type={client_auth_type}" in plan
                    and f"ciba_mode={mode}" in plan
                ],
                True,
            )
        )

    grouped.extend(
        (
            (
                "04-fapi-message-and-mtls-dpop",
                [
                    *matches("fapi2-message-signing-final-test-plan"),
                    *matches(
                        "fapi2-security-profile-final-test-plan",
                        "client_auth_type=mtls",
                        "sender_constrain=dpop",
                    ),
                ],
                False,
            ),
            (
                "05-fapi-mtls-mtls",
                matches(
                    "fapi2-security-profile-final-test-plan",
                    "client_auth_type=mtls",
                    "sender_constrain=mtls",
                ),
                False,
            ),
            (
                "06-fapi-private-dpop",
                matches(
                    "fapi2-security-profile-final-test-plan",
                    "client_auth_type=private_key_jwt",
                    "sender_constrain=dpop",
                ),
                False,
            ),
            (
                "07-fapi-private-mtls",
                matches(
                    "fapi2-security-profile-final-test-plan",
                    "client_auth_type=private_key_jwt",
                    "sender_constrain=mtls",
                ),
                False,
            ),
            (
                "08-rp-initiated",
                source_plans["oidf-plan-set-rp-initiated.json"],
                True,
            ),
            (
                "09-backchannel",
                source_plans["oidf-plan-set-backchannel.json"],
                True,
            ),
            (
                "10-frontchannel",
                source_plans["oidf-plan-set-frontchannel.json"],
                True,
            ),
            ("11-session", source_plans["oidf-plan-set-session.json"], True),
        )
    )

    assigned = [plan for _, plans, _ in grouped for plan in plans]
    expected = [plan for plans in source_plans.values() for plan in plans]
    if any(not plans for _, plans, _ in grouped) or sorted(assigned) != sorted(expected):
        raise PublicRunError("bounded OIDF plan groups must exactly cover every source plan")

    result = []
    for name, plans, isolated in grouped:
        destination = work_dir / f"oidf-plan-set-{name}.json"
        destination.write_text(json.dumps(plans, indent=2) + "\n", encoding="utf-8")
        result.append((name, destination, isolated))
    return tuple(result)


def run_plan_groups(args: argparse.Namespace, work_dir: Path, env: dict[str, str]) -> None:
    for name, plan_set_file, isolated in split_plan_groups(work_dir):
        expected_skips_file = work_dir / f"oidf-expected-skips-{name}.json"
        expected_warnings_file = work_dir / f"oidf-expected-warnings-{name}.json"
        filter_problem_records(
            work_dir / "oidf-expected-skips.json",
            plan_set_file,
            expected_skips_file,
        )
        filter_problem_records(
            ROOT / "tests" / "contracts" / "oidf-official-expected-warnings.json",
            plan_set_file,
            expected_warnings_file,
            excluded_conditions=OFFICIAL_INGRESS_ONLY_WARNING_CONDITIONS,
        )
        invocation = [
            sys.executable,
            str(ROOT / "scripts" / "run_oidf_conformance.py"),
            "--suite-dir",
            str(args.suite_dir),
            "--suite-revision",
            args.suite_revision,
            "--conformance-server",
            args.conformance_server,
            "--plan-set-json-file",
            str(plan_set_file),
            "--config-json-file",
            str(work_dir / "oidf-plan-configs.json"),
            "--target-issuer",
            args.target_issuer,
            "--token-env",
            args.token_env,
            "--export-dir",
            str(args.export_dir / name),
            "--expected-skips-file",
            str(expected_skips_file),
            "--expected-failures-file",
            str(expected_warnings_file),
            "--timeout-seconds",
            str(args.timeout_seconds),
            "--monitor-interval-seconds",
            str(args.monitor_interval_seconds),
            "--verbose",
        ]
        if isolated:
            invocation.append("--no-parallel")
        command(invocation, env=env)


def run(args: argparse.Namespace) -> None:
    args.target_issuer = origin(args.target_issuer, "--target-issuer")
    args.conformance_server = origin(args.conformance_server, "--conformance-server")
    args.work_dir = args.work_dir.resolve()
    args.export_dir = args.export_dir.resolve()
    args.suite_dir = args.suite_dir.resolve()
    if args.work_dir.exists() or args.export_dir.exists():
        raise PublicRunError("--work-dir and --export-dir must not already exist")
    validate_output_paths(args.work_dir, args.export_dir, args.suite_dir)
    verify_source(args.deployed_sha)
    verify_suite(args.suite_dir, args.suite_revision)
    env = required_environment(args.token_env)
    env.update(
        {
            "OIDF_TARGET_ISSUER": args.target_issuer,
            "OIDF_MTLS_TARGET_ISSUER": args.target_issuer,
            "OIDF_SUITE_BASE_URL": args.conformance_server,
            "OIDF_RUN_NAMESPACE": args.run_namespace,
            "OIDF_RUNTIME_DIR": str(args.work_dir),
        }
    )
    args.work_dir.parent.mkdir(parents=True, exist_ok=True)
    args.export_dir.parent.mkdir(parents=True, exist_ok=True)
    proxy = ProxyTrust(args.proxy_trust_bundle, args.proxy_executable, args.work_dir)
    state_file = args.work_dir / "oidf-onboarding-state.json"
    failure: BaseException | None = None
    try:
        command([sys.executable, str(ROOT / "scripts" / "prepare_oidf_black_box.py")], env=env)
        protect_directory(args.work_dir)
        command(onboarding_args("apply", args.work_dir, args.target_issuer), env=env)
        proxy.install(args.work_dir / "approved-mtls-trust-anchors.pem")
        verify_suite_boundary(args.conformance_server, env[args.token_env])
        run_plan_groups(args, args.work_dir, env)
    except BaseException as error:
        failure = error
    finally:
        cleanup_errors: list[BaseException] = []
        if state_file.exists():
            try:
                command(onboarding_args("cleanup", args.work_dir, args.target_issuer), env=env)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            proxy.restore()
        except BaseException as error:
            cleanup_errors.append(error)
        try:
            sanitize_evidence_tree(args.export_dir)
        except BaseException as error:
            cleanup_errors.append(error)
        protect_directory(args.work_dir)
        protect_directory(args.export_dir)
        if cleanup_errors:
            raise ExceptionGroup("public OIDF cleanup failed", cleanup_errors) from failure
    if failure is not None:
        raise failure


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployed-sha", required=True)
    parser.add_argument("--target-issuer", required=True)
    parser.add_argument("--conformance-server", required=True)
    parser.add_argument("--suite-dir", type=Path, required=True)
    parser.add_argument("--suite-revision", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--run-namespace", required=True)
    parser.add_argument("--proxy-trust-bundle", type=Path, required=True)
    parser.add_argument("--proxy-executable", type=Path, required=True)
    parser.add_argument("--token-env", default="OIDF_CONFORMANCE_TOKEN")
    parser.add_argument("--timeout-seconds", type=int, default=14400)
    parser.add_argument("--monitor-interval-seconds", type=int, default=30)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        run(parse_args(argv))
    except (PublicRunError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
