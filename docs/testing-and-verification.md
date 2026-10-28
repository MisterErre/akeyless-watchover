# Testing and verification

| Layer | Tool | Needs Akeyless? | Runs |
|---|---|---|---|
| Syntax/types | `terraform fmt -check`, `validate` | no | every PR |
| Model rules | `terraform test` (mocked provider, 18 runs) | no | every PR |
| Guard intent | `terraform/tests/guard_messages.sh` | no | every PR |
| Effective access (model semantics) | `scripts/akl_simulate.py` | no | every PR |
| Tooling + usage-guide drift | `pytest scripts/tests` (39 tests) | no | every PR |
| Bootstrap | `bootstrap/tests` (3 runs) | no | repo CI |
| Plan review | `terraform plan` | yes (plan identity) | every PR |
| Effective access (platform truth) | `scripts/akl_verify.py` / Console Impersonate As | yes | after apply |
| Drift | `terraform plan -detailed-exitcode` | yes | nightly |

## Offline access simulator

`akl_simulate.py` evaluates `access_expectations.yaml` against the model with the documented
semantics (wildcards `*` and `+`, implied `list`, deny precedence, sub-claim OR/AND/globs/case,
templated paths). Assumptions it makes - verify live once: `/a/*` does not match `/a` itself;
explicit `AND`/`OR` sub-claim operators are evaluated left to right.

```bash
python3 scripts/akl_simulate.py --model terraform/model --expectations terraform/model/access_expectations.yaml --explain
```

## Live verification

Give personas a CLI `profile` (test SSO user in the right group, test workload identity) and run:
```bash
python3 scripts/akl_verify.py --expectations terraform/model/access_expectations.yaml
```
It calls `describe-permissions --json` as each persona and compares `client_permissions` with the
expected set. How the CLI reports "no access at all" is not documented: by default an error stops
the run; after checking the behaviour, `--error-means-no-access` treats it as an empty set.

## Running everything locally

One command: `scripts/watchover test` (or `--tool tofu`). Step by step:

```bash
(cd terraform && terraform init -backend=false && terraform validate && terraform test && tests/guard_messages.sh terraform)
(cd bootstrap && terraform init -backend=false && terraform test)
pip install pyyaml pytest && python3 -m pytest -q scripts/tests
python3 scripts/akl_simulate.py --model terraform/model --expectations terraform/model/access_expectations.yaml
```
