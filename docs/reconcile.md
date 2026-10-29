# Reconcile: repository vs Akeyless

`scripts/watchover reconcile` compares the governance repository (for example on GitHub Enterprise) with the
live Akeyless configuration. It writes the changes as files for a person to review and commit.
**It never commits, pushes, merges or opens pull requests.**

## Command

```bash
# repository on GitHub Enterprise (HTTPS or SSH; your git credentials are used)
gh auth login --hostname ghe.example.com && gh auth setup-git --hostname ghe.example.com   # once, for HTTPS
scripts/watchover reconcile --repo-url https://ghe.example.com/platform/akeyless-governance.git \
    --ref main --profile akl-readonly --out reconcile/

# an existing checkout (read as it is, never modified), REST instead of the CLI
scripts/watchover reconcile --repo-dir ~/src/akeyless-governance --transport api --token "$AKEYLESS_TOKEN"

# offline, against an earlier export
scripts/watchover reconcile --repo-dir . --export-dir export/
```

| Option | Effect |
|---|---|
| `--repo-url` / `--repo-dir` | shallow clone of `--ref` with the push URL disabled, or a local checkout |
| `--model-path` | model directory in the repository (default `terraform/model`) |
| `--profile`, `--transport`, `--api`, `--token`, `--akeyless` | how Akeyless is read (same as `export`); a read-only identity is enough |
| `--export-dir`, `--from-dir` | use an earlier export, or replay a `raw/` directory |
| `--only`, `--exclude` | limit by object name (regex) |
| `--include-unmodelled` | also propose fields set in Akeyless but absent from the model (often provider defaults) |
| `--propose-removals` | propose removing objects that exist only in the repository |

Exit codes: 0 no differences; 1 differences found (files written); 2 git, export or model error.

## How it works

1. Reads the repository's model: roles, auth methods, folders, custom fields and key policies.
2. Exports the same families from Akeyless.
3. Compares object by object. Defaults, list order, `*_var` secret keys and guard switches are ignored.
   Custom fields are matched by name and object type.
4. Proposes the Akeyless value for every changed field and adds objects that exist only in Akeyless. Model
   files are edited in place, so comments and the other entries stay byte-identical.

## Output (`--out`, default `reconcile/` - keep it out of Git)

| File | Content |
|---|---|
| `REPORT.md` | repository URL, branch and commit, then each difference: changed / only in Akeyless / only in the repository |
| `changes.patch` | unified diff against the repository |
| `proposed/` | the complete changed files at their repository paths |
| `imports.tf` | import blocks for objects added from Akeyless |
| `summary.json` | the result for tools; `export/` holds the export used |

## Review and commit (by a person)

```bash
git switch -c reconcile/2026-10-29
git apply --3way reconcile/changes.patch      # then `git add -p`: keep the hunks you agree with
cp reconcile/imports.tf terraform/            # if objects were added
terraform plan                                # imports + the changes you kept, nothing else
git commit && git push                        # your own commit and pull request
```

For each difference, either Akeyless is right (keep the hunk, so the model codifies the console change) or
the repository is right (drop the hunk, so the next apply reverts Akeyless).

## Not compared

PKI issuers, event forwarders (Akeyless has no list operation for them), Gateway configuration, account
settings and targets. Use `terraform plan` against the account (or the nightly drift job): it is the
authoritative drift check for every managed object.
