# tmas-json-to-sarif

Convert a **TMAS** (TrendAI Artifact Scanner) JSON report to **SARIF 2.1.0**, so TMAS findings can be consumed by tools that read SARIF (GitHub Code Scanning, IDE SARIF viewers, other ASPM/security platforms).

TMAS has no native SARIF output: `tmas scan ... --output sarif=x.sarif` returns `InvalidOutputError: unsupported output format: sarif` (tested on TMAS v2.342.0; `--output` accepts `json` and `markdown` only).

## Requirements

- Python 3.8+ (standard library only, no `pip install` needed)
- A TMAS JSON report: `tmas scan <artifact> -VS --redacted --output json=tmas-report.json`

## Usage

```bash
python3 tmas2sarif.py tmas-report.json -o tmas-report.sarif \
  --base-dir "$PWD" --tool-version "$(tmas version | awk '/^Version:/{print $2}')"
```

| Option | Description |
|---|---|
| `input` | TMAS JSON report |
| `-o, --output` | SARIF output file (default: stdout) |
| `--base-dir` | Repository root; absolute paths in the report are made relative to it (default: `$GITHUB_WORKSPACE`) |
| `--tool-version` | TMAS version written to the SARIF driver |

Try it with the sanitized sample: `python3 tmas2sarif.py samples/tmas-report.sample.json --base-dir /home/runner/work/my-app/my-app`

## Mapping

| TMAS JSON | SARIF |
|---|---|
| `vulnerabilities.findings.<Severity>[]` | One rule per GHSA/CVE id; one result per finding location. Message includes package, version, related CVEs and fixed version |
| Severity | Critical/High → `error`, Medium → `warning`, Low/Negligible/Unknown → `note` |
| `cvssSummaries[].cvssMetrics.cvssBaseScore` | `security-severity` = highest base score (GitHub uses it to rank alerts); fallback by severity |
| `locations[]` (manifest) | `artifactLocation`, anchored to line 1 (TMAS reports no line for dependencies) |
| `secrets.findings.unmitigated[]` | Rule `secret/<ruleID>` with exact line/column; the secret value is **not** included (TMAS `--redacted` still leaves the first and last characters visible) |
| `secrets.findings.overridden[]` | Same as above, emitted with `suppressions` (kind `external`) |
| Paths | Secrets use absolute runner paths, vulnerabilities relative paths; both normalized to repo-relative URIs with `uriBaseId: SRCROOT` |
| — | `partialFingerprints` so re-scans de-duplicate alerts |

Not converted: malware findings, `policyEvaluation`, `artifactMetadata`.

## CI example

[`examples/github-actions-tmas-sarif.yml`](examples/github-actions-tmas-sarif.yml): scan with TMAS, convert, upload the SARIF artifact and optionally to GitHub Code Scanning. Uploading to Code Scanning requires a public repository or GitHub Advanced Security on private ones.

## Tested

- TMAS v2.342.0, `tmas scan dir:. -VS` on GitHub Actions (ubuntu-latest), reports with 58 vulnerabilities and 1 secret.
- Output validated against the SARIF 2.1.0 JSON schema (0 errors).
- The optional `upload-sarif` step to GitHub Code Scanning has **not** been tested yet (schema-valid SARIF is not a guarantee GitHub accepts every field).
- The input format is not a published TMAS contract: if a new TMAS version changes the JSON, re-validate.

## Related

For a human-readable console summary and HTML dashboard of the same TMAS JSON (including policy evaluation), see [`tmas-report.py`](https://github.com/XeniaP/trendai-cloudsecurity-poc-utilities/blob/main/CodeSecurity/tmas-report.py). It complements this converter (HTML for people, SARIF for tools).
