#!/usr/bin/env python3
"""Convert a TMAS JSON report (`tmas scan ... --output json=...`) to SARIF 2.1.0.

TMAS v2.342.0 has no native SARIF output (`unsupported output format: sarif`).
Input format validated against real reports from `tmas scan dir:. -VS`:
  vulnerabilities.findings.{Critical,High,Medium,Low,Negligible,Unknown}[]
      name, type, version, id, source, severity, fix, locations[], cvssSummaries[], relatedVulnerabilities[]
  secrets.findings.unmitigated[] (y .overridden[] si existe)
      ruleID, description, secret (redacted), location{path,startLine,endLine,startColumn,endColumn}

Usage:
  tmas2sarif.py tmas-report.json -o tmas-report.sarif [--base-dir "$GITHUB_WORKSPACE"] [--tool-version v2.342.0]
"""
import argparse
import hashlib
import json
import os
import sys

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning",
         "low": "note", "negligible": "note", "unknown": "note"}
# security-severity for GitHub Code Scanning when no CVSS score is available
DEFAULT_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0,
                 "negligible": 0.5, "unknown": 0.0}


def rel_uri(path, base_dir):
    """Path relative to the repository root, with '/' separators."""
    if not path:
        return "unknown"
    p = path.replace("\\", "/")
    if base_dir:
        b = base_dir.replace("\\", "/").rstrip("/") + "/"
        if p.startswith(b):
            p = p[len(b):]
    return p.lstrip("/") or "unknown"



def max_cvss(finding):
    scores = []
    for c in finding.get("cvssSummaries") or []:
        try:
            scores.append(float((c.get("cvssMetrics") or {}).get("cvssBaseScore")))
        except (TypeError, ValueError):
            pass
    return max(scores) if scores else None


def fingerprint(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def convert_vulns(vulns, base_dir, rules, results):
    findings = (vulns or {}).get("findings") or {}
    for sev_key, items in findings.items():
        for f in items or []:
            vid = f.get("id") or "UNKNOWN-VULN"
            sev = (f.get("severity") or sev_key or "unknown").lower()
            score = max_cvss(f)
            pkg = f"{f.get('name')}@{f.get('version')}"
            related = [r.get("id") for r in f.get("relatedVulnerabilities") or [] if r.get("id")]
            if vid not in rules:
                rules[vid] = {
                    "id": vid,
                    "name": vid,
                    "shortDescription": {"text": f"{vid} ({', '.join(related)})" if related else vid},
                    "fullDescription": {"text": f"Vulnerability {vid} in an open source dependency."},
                    "helpUri": f.get("source") or "",
                    "help": {"text": f"See {f.get('source') or vid}"},
                    "defaultConfiguration": {"level": LEVEL.get(sev, "warning")},
                    "properties": {
                        "tags": ["security", "vulnerability", "tmas"],
                        "security-severity": f"{score if score is not None else DEFAULT_SCORE.get(sev, 0.0):.1f}",
                        "precision": "high",
                    },
                }
            fix = f.get("fix")
            msg = (f"{pkg} ({f.get('type')}) is vulnerable to {vid}"
                   + (f" [{', '.join(related)}]" if related else "")
                   + f". Severity: {f.get('severity')}."
                   + (f" Fixed in: {fix}." if fix else " No fixed version available."))
            for loc in f.get("locations") or ["unknown"]:
                uri = rel_uri(loc, base_dir)
                results.append({
                    "ruleId": vid,
                    "level": LEVEL.get(sev, "warning"),
                    "message": {"text": msg},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        # TMAS gives no line number for manifests: anchor to line 1
                        "region": {"startLine": 1}}}],
                    "partialFingerprints": {"tmasVuln/v1": fingerprint(vid, pkg, uri)},
                    "properties": {"package": f.get("name"), "version": f.get("version"),
                                   "packageType": f.get("type"), "fixedVersion": fix,
                                   "severity": f.get("severity"), "cvss": score,
                                   "relatedVulnerabilities": related},
                })


def convert_secrets(secrets, base_dir, rules, results):
    findings = (secrets or {}).get("findings") or {}
    for bucket in ("unmitigated", "overridden"):
        for f in findings.get(bucket) or []:
            rid = f"secret/{f.get('ruleID') or 'unknown'}"
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": f.get("ruleID") or "secret",
                    "shortDescription": {"text": f"Exposed secret: {f.get('ruleID')}"},
                    "fullDescription": {"text": f.get("description") or "Secret detected by TMAS."},
                    "help": {"text": "Revoke/rotate the secret and remove it from the repository history."},
                    "defaultConfiguration": {"level": "error"},
                    "properties": {"tags": ["security", "secret", "tmas"],
                                   "security-severity": "8.0", "precision": "high"},
                }
            loc = f.get("location") or {}
            uri = rel_uri(loc.get("path"), base_dir)
            region = {k: loc[k] for k in ("startLine", "endLine", "startColumn", "endColumn")
                      if isinstance(loc.get(k), int) and loc[k] > 0}
            region.setdefault("startLine", 1)
            res = {
                "ruleId": rid,
                "level": "error",
                "message": {"text": f"{f.get('description') or 'Secret detected.'}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}],
                "partialFingerprints": {"tmasSecret/v1": fingerprint(rid, uri, region.get("startLine"), loc.get("startColumn"))},
            }
            if bucket == "overridden":
                res["suppressions"] = [{"kind": "external", "justification": "TMAS override"}]
            results.append(res)


def convert(report, base_dir, tool_version):
    rules, results = {}, []
    convert_vulns(report.get("vulnerabilities"), base_dir, rules, results)
    convert_secrets(report.get("secrets"), base_dir, rules, results)
    rule_list = list(rules.values())
    index = {r["id"]: i for i, r in enumerate(rule_list)}
    for r in results:
        r["ruleIndex"] = index[r["ruleId"]]
    driver = {"name": "TMAS", "fullName": "TrendAI Artifact Scanner (TMAS)", "rules": rule_list}
    if tool_version:
        driver["version"] = tool_version.lstrip("v")
    run = {"tool": {"driver": driver}, "results": results}
    if base_dir:
        run["originalUriBaseIds"] = {"SRCROOT": {"uri": "file://" + base_dir.replace("\\", "/").rstrip("/") + "/"}}
        for r in results:
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "SRCROOT"
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="TMAS JSON report")
    ap.add_argument("-o", "--output", default="-", help="SARIF output file (default: stdout)")
    ap.add_argument("--base-dir", default=os.environ.get("GITHUB_WORKSPACE", ""),
                    help="repository root used to make absolute paths relative (default: $GITHUB_WORKSPACE)")
    ap.add_argument("--tool-version", default="", help="TMAS version, e.g. v2.342.0")
    a = ap.parse_args()
    with open(a.input, encoding="utf-8") as fh:
        report = json.load(fh)
    sarif = convert(report, a.base_dir, a.tool_version)
    out = json.dumps(sarif, indent=2, ensure_ascii=False)
    if a.output == "-":
        print(out)
    else:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    n = len(sarif["runs"][0]["results"])
    print(f"SARIF 2.1.0: {n} results, {len(sarif['runs'][0]['tool']['driver']['rules'])} rules -> {a.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
