# public-repo-guard

A CI check that keeps infrastructure endpoints, internal identifiers and customer names out of Silmaril Security's public repositories. GitHub secret scanning and push protection cover provider credentials; this check covers the leaks they do not and adds gitleaks' default credential rules.

## What it blocks

The check scans every new commit in a pull request or push (added lines, file paths and commit messages), plus the pull request title and body. History that already exists on the base branch is not rescanned.

| Rule | Blocks |
| --- | --- |
| `aws-api-gateway-endpoint` | `<api-id>.execute-api.<region>.amazonaws.com` hosts |
| `aws-lambda-function-url` | `<url-id>.lambda-url.<region>.on.aws` hosts |
| `aws-appsync-endpoint` | `<api-id>.appsync-api.<region>.amazonaws.com` hosts |
| `aws-load-balancer-host` | Classic, application and network load balancer hostnames |
| `aws-global-accelerator-host` | `<id>.awsglobalaccelerator.com` hosts |
| `aws-cloudfront-host` | `<distribution>.cloudfront.net` hosts |
| `aws-ecr-registry` | ECR registry hosts that carry a real account ID |
| `aws-account-arn` | ARNs that carry a real account ID |
| `deployment-identifier` | Resource names ending in `-<stage>-<region>` |
| `silmaril-staged-host` | Hosts under a stage subdomain of `silmaril.dev` |
| `customer-name` | Customer and tenant names, read at runtime from an organization secret |
| gitleaks | Credentials matched by the default rules of a pinned, checksum-verified gitleaks release |

Documentation placeholders pass: `<api-id>`-style tokens, the AWS documentation account IDs such as `123456789012`, account IDs made of one repeated digit, and deployment names that start with `tenant-<letter>`, `example`, `sample`, `placeholder`, `forbidden`, `my` or `your`.

The customer list is never stored in this repository. It lives in the `PUBLIC_REPO_GUARD_CUSTOMER_PATTERN` organization secret, granted only to the repositories that run the check. Findings from that rule are reported by location with the match redacted.

## Adopting the check

Add `.github/workflows/public-repo-guard.yml` to the repository:

```yaml
name: Public repo guard

on:
  push:
  pull_request:
    types: [opened, synchronize, reopened, edited]

permissions:
  contents: read

jobs:
  public-repo-guard:
    name: public-repo-guard
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: Silmaril-Security/public-repo-guard@main
        with:
          customer-pattern: ${{ secrets.PUBLIC_REPO_GUARD_CUSTOMER_PATTERN }}
```

Then grant the repository access to the organization secret and add it to the organization ruleset that requires the `public-repo-guard` status check on the default branch.

Pull requests from forks and Dependabot do not receive Actions secrets. For those runs the public rules still apply and the customer-name rule is skipped with a notice. Any other run without the secret fails, so a missing grant cannot silently disable the rule.

## Allowing a reviewed line

A repository can allow an exact line of an exact file by listing its fingerprint in `.github/public-repo-guard-allowlist`. The fingerprint is a SHA-256 of the path and the trimmed line, so the allowlist never names what it allows and stops matching as soon as the line or path changes. From the repository root:

```sh
python3 path/to/public_repo_guard.py fingerprint README.md 40 >> .github/public-repo-guard-allowlist
```

Allowlist changes go through code review like any other change. Commit messages and pull request text cannot be allowlisted. A reviewed gitleaks false positive goes in `.gitleaksignore` using the fingerprint gitleaks prints.

## Development

```sh
python -m pip install pytest==9.2.0 ruff==0.17.6
ruff format --check . && ruff check . && python -m pytest -q
```
