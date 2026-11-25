# Copyright (c) 2024-2025 Silmaril Security Inc. All rights reserved.
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import public_repo_guard as guard

CANARY = "-".join(["guard", "canary", "test"])
API_HOST = ".".join(["abcdefghij", "execute-api", "us-west-2", "amazonaws", "com"])
ACCOUNT = "".join(["9876", "5432", "1098"])
DEPLOYMENT = "-".join(["backend", "service", "alpha", "us", "west", "2"])


def rule(name: str) -> guard.Rule:
    return next(candidate for candidate in guard.PUBLIC_RULES if candidate.name == name)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def commit(repo: Path, path: str, content: str, message: str) -> str:
    (repo / path).parent.mkdir(parents=True, exist_ok=True)
    (repo / path).write_text(content)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "guard@silmaril.dev")
    git(tmp_path, "config", "user.name", "Public Repo Guard")
    commit(tmp_path, "README.md", "Public SDK\n", "chore: initial commit")
    return tmp_path


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("aws-api-gateway-endpoint", f"https://{API_HOST}/prod/classify"),
        (
            "aws-lambda-function-url",
            ".".join(["a" * 20 + "b" * 12, "lambda-url", "us-east-1", "on", "aws"]),
        ),
        (
            "aws-appsync-endpoint",
            ".".join(["c" * 26, "appsync-api", "us-west-2", "amazonaws", "com"]),
        ),
        (
            "aws-load-balancer-host",
            ".".join(["internal-api-1234567890", "us-west-2", "elb", "amazonaws", "com"]),
        ),
        (
            "aws-load-balancer-host",
            ".".join(["api-0123456789abcdef", "elb", "us-west-2", "amazonaws", "com"]),
        ),
        (
            "aws-global-accelerator-host",
            ".".join(["a1b2c3d4e5f6a7b8", "awsglobalaccelerator", "com"]),
        ),
        ("aws-cloudfront-host", ".".join(["d1a2b3c4d5e6f7", "cloudfront", "net"])),
        ("aws-ecr-registry", ".".join([ACCOUNT, "dkr", "ecr", "us-west-2", "amazonaws", "com"])),
        ("aws-account-arn", ":".join(["arn", "aws", "iam", "", ACCOUNT, "role/deploy"])),
        ("deployment-identifier", DEPLOYMENT),
        ("silmaril-staged-host", ".".join(["api", "tenant", "alpha", "silmaril", "dev"])),
    ],
)
def test_public_rules_block_infrastructure_values(name: str, value: str) -> None:
    assert rule(name).matches(f"url = {value!r}")


@pytest.mark.parametrize(
    "value",
    [
        "<api-id>.execute-api.<region>.amazonaws.com",
        "arn:aws:iam::123456789012:role/deploy",
        "arn:aws:iam::111122223333:role/deploy",
        "000000000000.dkr.ecr.us-west-2.amazonaws.com",
        "<account-id>.dkr.ecr.us-west-2.amazonaws.com",
        "tenant-a-prod-us-west-2",
        "example-service-alpha-eu-west-1",
        "https://app.silmaril.dev/demo/setup-complete",
        "https://firewall-mcp.silmaril.dev/mcp",
        "region = us-west-2, stage = prod",
        "elasticloadbalancing.us-west-2.amazonaws.com",
    ],
)
def test_public_rules_allow_placeholders_and_public_hosts(value: str) -> None:
    assert not [match for candidate in guard.PUBLIC_RULES for match in candidate.matches(value)]


def test_customer_rule_is_case_insensitive_and_redacted() -> None:
    customer = guard.customer_rule(CANARY)
    finding = guard.Finding(customer, guard.Text("pull request title", CANARY.upper()), CANARY)

    assert customer.matches(f"Ship it for {CANARY.upper()}")
    assert CANARY not in finding.annotation().lower()
    assert finding.annotation() == (
        "::error title=public-repo-guard%3A customer-name::"
        "customer-name in pull request title: [redacted]"
    )


def test_annotation_escapes_file_properties_and_data() -> None:
    text = guard.Text("commit abc", API_HOST, "docs/a,b:c.md", 7)
    annotation = guard.Finding(rule("aws-api-gateway-endpoint"), text, "50%\nnext").annotation()

    assert annotation == (
        "::error title=public-repo-guard%3A aws-api-gateway-endpoint,file=docs/a%2Cb%3Ac.md,"
        "line=7::aws-api-gateway-endpoint in commit abc: 50%25%0Anext"
    )


def test_patch_texts_tracks_paths_and_added_line_numbers() -> None:
    patch = "\n".join(
        [
            "diff --git a/src/app.py b/src/app.py",
            "--- a/src/app.py",
            "+++ b/src/app.py",
            "@@ -3,0 +4,2 @@ def main():",
            "+first = 1",
            "+++ second = 2",
            "@@ -10 +12 @@",
            "-old",
            "+third = 3",
            "diff --git a/old.md b/docs/new.md",
            "similarity index 100%",
            "rename from old.md",
            "rename to docs/new.md",
            "diff --git a/gone.txt b/gone.txt",
            "--- a/gone.txt",
            "+++ /dev/null",
            "@@ -1 +0,0 @@",
            "-removed",
        ]
    )

    assert list(guard.patch_texts("a" * 40, patch)) == [
        guard.Text("commit aaaaaaaaaaaa path", "src/app.py", "src/app.py"),
        guard.Text("commit aaaaaaaaaaaa", "first = 1", "src/app.py", 4),
        guard.Text("commit aaaaaaaaaaaa", "++ second = 2", "src/app.py", 5),
        guard.Text("commit aaaaaaaaaaaa", "third = 3", "src/app.py", 12),
        guard.Text("commit aaaaaaaaaaaa path", "docs/new.md", "docs/new.md"),
    ]


def test_commit_texts_scans_every_commit_and_message(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo)
    base = git(repo, "rev-parse", "HEAD")
    commit(repo, "config.ts", f"export const url = '{API_HOST}';\n", "feat: add endpoint")
    head = commit(repo, "config.ts", "export const url = '';\n", f"fix: drop {DEPLOYMENT}")

    findings = guard.scan(guard.commit_texts(head, (base,)), guard.PUBLIC_RULES, frozenset())

    assert [(f.rule.name, f.text.path, f.text.line, f.match) for f in findings] == [
        ("aws-api-gateway-endpoint", "config.ts", 1, API_HOST),
        ("deployment-identifier", None, None, DEPLOYMENT),
    ]


def test_scan_skips_only_allowlisted_path_and_content() -> None:
    line = f"callback = '{CANARY}'"
    allowed = guard.Text("commit abc", line, "README.md", 3)
    elsewhere = guard.Text("commit abc", line, "docs/guide.md", 3)
    allowlist = frozenset({guard.fingerprint("README.md", f"  {line}  ")})

    findings = guard.scan([allowed, elsewhere], [guard.customer_rule(CANARY)], allowlist)

    assert [finding.text for finding in findings] == [elsewhere]


def test_load_allowlist_reads_first_column_and_skips_comments(tmp_path: Path) -> None:
    allowlist = tmp_path / "allowlist"
    allowlist.write_text("# reviewed\n\nabc README.md\ndef docs/guide.md\n")

    assert guard.load_allowlist(allowlist) == frozenset({"abc", "def"})
    assert guard.load_allowlist(tmp_path / "missing") == frozenset()


def pull_request_event(head_repository: str | None) -> dict:
    return {
        "pull_request": {
            "title": "feat: add guard",
            "body": "Line one\r\nLine two",
            "head": {"sha": "h" * 40, "repo": head_repository and {"full_name": head_repository}},
            "base": {"sha": "b" * 40},
        }
    }


def test_resolve_scope_for_same_repository_pull_request() -> None:
    scope = guard.resolve_scope("pull_request", pull_request_event("org/repo"), "org/repo", "dev")

    assert scope == guard.Scope(
        head="h" * 40,
        exclude=("b" * 40,),
        texts=(
            guard.Text("pull request title", "feat: add guard"),
            guard.Text("pull request body", "Line one"),
            guard.Text("pull request body", "Line two"),
        ),
        secrets_available=True,
    )


@pytest.mark.parametrize(
    ("head_repository", "actor"),
    [("fork/repo", "dev"), (None, "dev"), ("org/repo", guard.DEPENDABOT)],
)
def test_resolve_scope_marks_fork_and_dependabot_pull_requests_without_secrets(
    head_repository: str | None, actor: str
) -> None:
    event = pull_request_event(head_repository)

    assert not guard.resolve_scope("pull_request", event, "org/repo", actor).secrets_available


def push_event(ref: str, before: str, after: str, deleted: bool = False) -> dict:
    return {
        "ref": ref,
        "before": before,
        "after": after,
        "deleted": deleted,
        "repository": {"default_branch": "main"},
    }


def test_resolve_scope_for_new_branch_excludes_default_branch(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo)
    event = push_event("refs/heads/topic", guard.ZERO_SHA, "a" * 40)

    scope = guard.resolve_scope("push", event, "org/repo", "dev")

    assert scope.exclude == ("origin/main",)
    assert scope.secrets_available


def test_resolve_scope_for_default_branch_push_excludes_previous_head(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo)
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, "a.txt", "a\n", "feat: a")

    scope = guard.resolve_scope("push", push_event("refs/heads/main", before, after), "o/r", "d")

    assert scope == guard.Scope(head=after, exclude=(before,), texts=(), secrets_available=True)


def test_resolve_scope_for_force_push_ignores_unreachable_previous_head(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo)
    event = push_event("refs/heads/topic", "f" * 40, "a" * 40)

    assert guard.resolve_scope("push", event, "o/r", guard.DEPENDABOT) == guard.Scope(
        head="a" * 40, exclude=("origin/main",), texts=(), secrets_available=False
    )


def test_resolve_scope_skips_deleted_refs_and_rejects_other_events() -> None:
    deleted = push_event("refs/heads/topic", "a" * 40, guard.ZERO_SHA, deleted=True)

    assert guard.resolve_scope("push", deleted, "o/r", "d") is None
    with pytest.raises(SystemExit):
        guard.resolve_scope("workflow_dispatch", {}, "o/r", "d")


def run_scan_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, event_name: str, event: dict
) -> Path:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event))
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_EVENT_NAME", event_name)
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_ACTOR", "dev")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))
    return summary


def test_run_scan_reports_redacted_customer_findings(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.chdir(repo)
    before = git(repo, "rev-parse", "HEAD")
    after = commit(repo, "notes.md", f"Pilot with {CANARY}\n", "docs: notes")
    summary = run_scan_environment(
        monkeypatch, tmp_path, "push", push_event("refs/heads/main", before, after)
    )
    monkeypatch.setenv(guard.CUSTOMER_PATTERN_ENV, CANARY)

    assert guard.run_scan(repo) == 1
    assert (tmp_path / "output").read_text() == f"log-opts={after} --not {before}\n"
    output = capsys.readouterr().out
    assert "file=notes.md,line=1::customer-name" in output
    assert CANARY not in output
    assert "| customer-name | " in summary.read_text()
    assert CANARY not in summary.read_text()


def test_run_scan_honors_repository_allowlist(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo)
    before = git(repo, "rev-parse", "HEAD")
    line = f"Works with the {CANARY} client"
    (repo / ".github").mkdir()
    (repo / guard.ALLOWLIST_PATH).write_text(f"{guard.fingerprint('notes.md', line)} notes.md\n")
    after = commit(repo, "notes.md", f"{line}\n", "docs: notes")
    run_scan_environment(
        monkeypatch, tmp_path, "push", push_event("refs/heads/main", before, after)
    )
    monkeypatch.setenv(guard.CUSTOMER_PATTERN_ENV, CANARY)

    assert guard.run_scan(repo) == 0


def test_run_scan_fails_when_trusted_run_lacks_customer_pattern(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo)
    head = git(repo, "rev-parse", "HEAD")
    run_scan_environment(monkeypatch, tmp_path, "push", push_event("refs/heads/main", head, head))
    monkeypatch.delenv(guard.CUSTOMER_PATTERN_ENV, raising=False)

    assert guard.run_scan(repo) == 1


def test_run_scan_skips_customer_rule_for_fork_pull_requests(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.chdir(repo)
    base = git(repo, "rev-parse", "HEAD")
    head = commit(repo, "notes.md", f"Pilot with {CANARY}\n", "docs: notes")
    event = pull_request_event("fork/repo")
    event["pull_request"]["head"]["sha"] = head
    event["pull_request"]["base"]["sha"] = base
    summary = run_scan_environment(monkeypatch, tmp_path, "pull_request", event)
    monkeypatch.delenv(guard.CUSTOMER_PATTERN_ENV, raising=False)

    assert guard.run_scan(repo) == 0
    assert "::notice title=public-repo-guard::Customer-name rule skipped" in capsys.readouterr().out
    assert "Customer-name rule skipped" in summary.read_text()


def test_run_scan_blocks_fork_pull_request_infrastructure_values(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo)
    base = git(repo, "rev-parse", "HEAD")
    head = commit(repo, "client.go", f'const url = "{API_HOST}"\n', "feat: client")
    event = pull_request_event("fork/repo")
    event["pull_request"]["head"]["sha"] = head
    event["pull_request"]["base"]["sha"] = base
    run_scan_environment(monkeypatch, tmp_path, "pull_request", event)
    monkeypatch.delenv(guard.CUSTOMER_PATTERN_ENV, raising=False)

    assert guard.run_scan(repo) == 1


def test_fingerprint_command_prints_allowlist_entry(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setattr(
        "sys.argv", ["guard", "--workspace", str(repo), "fingerprint", "README.md", "1"]
    )

    assert guard.main() == 0
    assert capsys.readouterr().out == f"{guard.fingerprint('README.md', 'Public SDK')} README.md\n"
