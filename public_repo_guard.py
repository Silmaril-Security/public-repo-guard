# Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
"""Block infrastructure endpoints, internal identifiers and customer names in public repositories."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

ZERO_SHA = "0" * 40
DEPENDABOT = "dependabot[bot]"
ALLOWLIST_PATH = ".github/public-repo-guard-allowlist"
CUSTOMER_PATTERN_ENV = "PUBLIC_REPO_GUARD_CUSTOMER_PATTERN"
PLACEHOLDER_ACCOUNT_IDS = frozenset(
    {
        "012345678901",
        "098765432109",
        "123456789012",
        "111122223333",
        "210987654321",
        "444455556666",
        "777788889999",
    }
)
STAGE = r"(?:dev|alpha|beta|gamma|staging|prod)"
REGION = (
    r"(?:us|eu|ap|ca|sa|me|af|il|mx)-(?:gov-)?"
    r"(?:north|south|east|west|central|northeast|southeast|northwest|southwest)-\d"
)
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    placeholder: re.Pattern[str] | None = None
    redacted: bool = False

    def matches(self, text: str) -> list[str]:
        return [
            match.group(0)
            for match in self.pattern.finditer(text)
            if not self.is_placeholder(match)
        ]

    def is_placeholder(self, match: re.Match[str]) -> bool:
        account = match.groupdict().get("account")
        if account is not None and (account in PLACEHOLDER_ACCOUNT_IDS or len(set(account)) == 1):
            return True
        return self.placeholder is not None and self.placeholder.match(match.group(0)) is not None


@dataclass(frozen=True)
class Text:
    source: str
    content: str
    path: str | None = None
    line: int | None = None

    @property
    def location(self) -> str:
        return f"{self.path or ''}{'' if self.line is None else f':{self.line}'}"


@dataclass(frozen=True)
class Finding:
    rule: Rule
    text: Text
    match: str

    @property
    def shown(self) -> str:
        return "[redacted]" if self.rule.redacted else self.match

    def annotation(self) -> str:
        properties = {"title": f"public-repo-guard: {self.rule.name}"}
        if self.text.path is not None:
            properties["file"] = self.text.path
        if self.text.line is not None:
            properties["line"] = str(self.text.line)
        rendered = ",".join(f"{key}={escape_property(value)}" for key, value in properties.items())
        message = f"{self.rule.name} in {self.text.source}: {self.shown}"
        return f"::error {rendered}::{escape_data(message)}"


@dataclass(frozen=True)
class Scope:
    head: str
    exclude: tuple[str, ...]
    texts: tuple[Text, ...]
    secrets_available: bool


PUBLIC_RULES = (
    Rule(
        "aws-api-gateway-endpoint",
        re.compile(r"\b[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com\b", re.I),
    ),
    Rule(
        "aws-lambda-function-url",
        re.compile(r"\b[a-z0-9]{32}\.lambda-url\.[a-z0-9-]+\.on\.aws\b", re.I),
    ),
    Rule(
        "aws-appsync-endpoint",
        re.compile(r"\b[a-z0-9]{26}\.appsync-api\.[a-z0-9-]+\.amazonaws\.com\b", re.I),
    ),
    Rule(
        "aws-load-balancer-host",
        re.compile(r"\b[a-z0-9-]+\.(?:[a-z0-9-]+\.)?elb\.(?:[a-z0-9-]+\.)?amazonaws\.com\b", re.I),
    ),
    Rule(
        "aws-global-accelerator-host",
        re.compile(r"\b[a-z0-9]+\.awsglobalaccelerator\.com\b", re.I),
    ),
    Rule(
        "aws-cloudfront-host",
        re.compile(r"\b[a-z0-9]{13,14}\.cloudfront\.net\b", re.I),
    ),
    Rule(
        "aws-ecr-registry",
        re.compile(
            r"\b(?P<account>\d{12})\.dkr\.ecr(?:-fips)?\.[a-z0-9-]+\.amazonaws\.com\b", re.I
        ),
    ),
    Rule(
        "aws-account-arn",
        re.compile(r"\barn:aws(?:-[a-z]+)*:[a-z0-9-]+:[a-z0-9-]*:(?P<account>\d{12}):", re.I),
    ),
    Rule(
        "deployment-identifier",
        re.compile(rf"\b[a-z0-9]+(?:-[a-z0-9]+)*-{STAGE}-{REGION}\b", re.I),
        re.compile(r"(?:tenant-[a-z0-9]|example|sample|placeholder|forbidden|my|your)-", re.I),
    ),
    Rule(
        "silmaril-staged-host",
        re.compile(rf"\b(?:[a-z0-9-]+\.)+{STAGE}\.silmaril\.dev\b", re.I),
    ),
)


def escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(value: str) -> str:
    return escape_data(value).replace(":", "%3A").replace(",", "%2C")


def customer_rule(pattern: str) -> Rule:
    return Rule("customer-name", re.compile(pattern, re.I), redacted=True)


def fingerprint(path: str, content: str) -> str:
    return hashlib.sha256(f"{path}\0{content.strip()}".encode()).hexdigest()


def load_allowlist(path: Path) -> frozenset[str]:
    if not path.is_file():
        return frozenset()
    return frozenset(
        line.split()[0]
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    )


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-c", "core.quotepath=false", *args],
        check=True,
        capture_output=True,
    ).stdout.decode(errors="replace")


def commit_exists(sha: str) -> bool:
    return (
        subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True
        ).returncode
        == 0
    )


def diff_path(header: str) -> str | None:
    raw = header.strip('"')
    if raw == "/dev/null":
        return None
    return raw.removeprefix("b/")


def patch_texts(sha: str, patch: str) -> Iterator[Text]:
    path: str | None = None
    line = 0
    in_hunk = False
    for raw in patch.splitlines():
        if raw.startswith("diff --git "):
            path, in_hunk = None, False
        elif not in_hunk and raw.startswith("+++ "):
            path = diff_path(raw[4:])
            if path is not None:
                yield Text(f"commit {sha[:12]} path", path, path)
        elif not in_hunk and raw.startswith("rename to "):
            path = raw.removeprefix("rename to ")
            yield Text(f"commit {sha[:12]} path", path, path)
        elif hunk := HUNK_HEADER.match(raw):
            line, in_hunk = int(hunk[1]), True
        elif in_hunk and raw.startswith("+") and path is not None:
            yield Text(f"commit {sha[:12]}", raw[1:], path, line)
            line += 1


def commit_texts(head: str, exclude: Iterable[str]) -> Iterator[Text]:
    log = git(
        "log",
        "--reverse",
        "--patch",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--format=%x1e%H%n%B%x1f",
        head,
        "--not",
        *exclude,
        "--",
    )
    for record in log.split("\x1e")[1:]:
        header, _, patch = record.partition("\x1f")
        sha, _, message = header.partition("\n")
        for content in message.splitlines():
            yield Text(f"commit {sha[:12]} message", content)
        yield from patch_texts(sha, patch)


def pull_request_texts(pull_request: dict) -> tuple[Text, ...]:
    body = (pull_request.get("body") or "").splitlines()
    return (
        Text("pull request title", pull_request.get("title") or ""),
        *(Text("pull request body", content) for content in body),
    )


def resolve_scope(event_name: str, event: dict, repository: str, actor: str) -> Scope | None:
    if event_name == "pull_request":
        pull_request = event["pull_request"]
        head_repository = (pull_request["head"].get("repo") or {}).get("full_name")
        return Scope(
            head=pull_request["head"]["sha"],
            exclude=(pull_request["base"]["sha"],),
            texts=pull_request_texts(pull_request),
            secrets_available=head_repository == repository and actor != DEPENDABOT,
        )
    if event_name == "push":
        if event.get("deleted"):
            return None
        default_branch = event["repository"]["default_branch"]
        before = event["before"]
        exclude = (
            *((before,) if before != ZERO_SHA and commit_exists(before) else ()),
            *(
                ()
                if event["ref"] == f"refs/heads/{default_branch}"
                else (f"origin/{default_branch}",)
            ),
        )
        return Scope(
            head=event["after"], exclude=exclude, texts=(), secrets_available=actor != DEPENDABOT
        )
    raise SystemExit(f"public-repo-guard does not support {event_name} events")


def scan(texts: Iterable[Text], rules: Iterable[Rule], allowlist: frozenset[str]) -> list[Finding]:
    active = tuple(rules)
    return [
        Finding(rule, text, match)
        for text in texts
        if text.line is None or fingerprint(text.path or "", text.content) not in allowlist
        for rule in active
        for match in rule.matches(text.content)
    ]


def write_summary(findings: list[Finding], notices: list[str]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    rows = [
        f"| {finding.rule.name} | {finding.text.source} | {finding.text.location} | `{finding.shown}` |"
        for finding in findings
    ]
    lines = [
        "## Public repo guard",
        "",
        *notices,
        "",
        f"{len(findings)} finding(s).",
        *(
            ["", "| Rule | Source | Location | Match |", "| --- | --- | --- | --- |", *rows]
            if rows
            else []
        ),
    ]
    with open(summary_path, "a") as summary:
        summary.write("\n".join(lines) + "\n")


def write_output(name: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a") as output:
            output.write(f"{name}={value}\n")


def run_scan(workspace: Path) -> int:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    scope = resolve_scope(
        os.environ["GITHUB_EVENT_NAME"],
        event,
        os.environ["GITHUB_REPOSITORY"],
        os.environ.get("GITHUB_ACTOR", ""),
    )
    if scope is None:
        print("Nothing to scan for a deleted ref.")
        return 0
    write_output("log-opts", " ".join((scope.head, "--not", *scope.exclude)))
    customer_pattern = os.environ.get(CUSTOMER_PATTERN_ENV, "").strip()
    notices: list[str] = []
    if customer_pattern:
        rules = (*PUBLIC_RULES, customer_rule(customer_pattern))
    elif scope.secrets_available:
        print(
            f"::error title=public-repo-guard::{CUSTOMER_PATTERN_ENV} is not available to this repository."
        )
        return 1
    else:
        rules = PUBLIC_RULES
        notices.append(
            "Customer-name rule skipped: secrets are unavailable to fork and Dependabot runs."
        )
        print(f"::notice title=public-repo-guard::{notices[-1]}")
    texts = (*scope.texts, *commit_texts(scope.head, scope.exclude))
    findings = scan(texts, rules, load_allowlist(workspace / ALLOWLIST_PATH))
    for finding in findings:
        print(finding.annotation())
    write_summary(findings, notices)
    print(
        f"Scanned {scope.head} excluding {', '.join(scope.exclude) or 'nothing'}: {len(findings)} finding(s)."
    )
    return 1 if findings else 0


def print_fingerprint(workspace: Path, path: str, line: int) -> int:
    content = (workspace / path).read_text().splitlines()[line - 1]
    print(f"{fingerprint(path, content)} {path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("scan", help="Scan the commits and pull request text of the current event.")
    allow = commands.add_parser("fingerprint", help="Print the allowlist entry for a file line.")
    allow.add_argument("path")
    allow.add_argument("line", type=int)
    args = parser.parse_args()
    if args.command == "scan":
        return run_scan(args.workspace)
    return print_fingerprint(args.workspace, args.path, args.line)


if __name__ == "__main__":
    sys.exit(main())
