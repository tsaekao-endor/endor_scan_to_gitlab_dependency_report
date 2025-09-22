#!/usr/bin/env python3
"""
WHAT IT DOES:
- Coverts Endor Labs Results -> GitLab Dependency Scanning Report.
- Filled the Evidence Section With Call paths, Reachability (bool), Dependency path

FUTURE ENHANCEMENTS:
- Need to add a link back to the finding in the Endor Platform.
- Update Reachability section, which is a GitLab specific field
"""

from __future__ import annotations
import argparse, csv, json, re, sys, uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Endor severities -> GitLab severities
SEV_MAP = {
    "FINDING_LEVEL_CRITICAL": "Critical",
    "FINDING_LEVEL_HIGH": "High",
    "FINDING_LEVEL_MEDIUM": "Medium",
    "FINDING_LEVEL_LOW": "Low",
    "FINDING_LEVEL_INFO": "Info",
}

# Endor dev ecosystem codes to package manager names
PM_MAP = {
    "ECOSYSTEM_MAVEN": "maven",
    "ECOSYSTEM_GRADLE": "gradle",
    "ECOSYSTEM_NPM": "npm",
    "ECOSYSTEM_PYPI": "pip",
    "ECOSYSTEM_GEM": "gem",
    "ECOSYSTEM_GO": "go",
    "ECOSYSTEM_RUST": "cargo",
    "ECOSYSTEM_NUGET": "nuget",
    "ECOSYSTEM_COMPOSER": "composer",
}

# Fallback map from manifest filename to package manager
PM_FROM_FILE = {
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "package-lock.json": "npm",
    "package.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "pip",
    "Pipfile.lock": "pipenv",
    "poetry.lock": "pip",
    "Gemfile.lock": "gem",
    "go.mod": "go",
    "Cargo.lock": "cargo",
    "packages.lock.json": "nuget",
    "composer.lock": "composer",
}

# Helper Functions
def _first(*vals):
    for v in vals:
        if v not in (None, "", [], {}):
            return v
    return None

# Nested lookup by paths
def _get(d: Any, path: List[Any], default=None):
    cur = d
    for p in path:
        if isinstance(p, int):
            if not isinstance(cur, list) or p >= len(cur):
                return default
            cur = cur[p]
        else:
            if not isinstance(cur, dict) or p not in cur:
                return default
            cur = cur[p]
    return cur

# Ensures value is always a list
def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]

# Get package manager from manifest filename when dev ecosystem is missing
def _pm_from_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return PM_FROM_FILE.get(path.split("/")[-1])

# Produces timestamps in correct format
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

# Strips schemes so dependency paths are shorter
def _short_pkgref(s: str) -> str:
    return re.sub(r"^\w+://", "", s or "")

def _load_findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    for k in ("all_findings", "findings", "results"):
        v = payload.get(k)
        if isinstance(v, list):
            return v
    return []

# ---------- Evidence builders ----------
# This determines what shows up under the "Evidence" section in GitLab UI

# Builds all the reachable callchains
def build_call_paths_detail(spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    paths = _as_list(spec.get("reachable_paths"))
    if not paths:
        return None
    items = []
    for path in paths[:5]:  # cap for readability
        hops = []
        for n in _as_list(path.get("nodes")):
            fr = n.get("function_ref") or {}
            cls = fr.get("classname") or ""
            fn  = fr.get("function_or_attribute_name") or ""
            hop = ".".join([p for p in (cls, fn) if p]).strip(".") or fr.get("language_specific") or ""
            if hop:
                hops.append(hop)
        if hops:
            items.append({"type": "text", "value": " -> ".join(hops)})
    if not items:
        return None
    return {"name": "Call paths", "type": "list", "items": items}

# Set to TRUE if there are any reachable paths
def build_reachability_detail(spec: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": "Reachability", "type": "value", "value": bool(_as_list(spec.get("reachable_paths")))}

# Shows the call chain from the first reachable path
def build_dependency_path_detail(spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    items = []
    paths = _as_list(spec.get("reachable_paths"))
    if paths:
        chain = []
        for n in _as_list(paths[0].get("nodes")):
            pv = n.get("package_version")
            if pv:
                chain.append(_short_pkgref(pv))
        if chain:
            items.append({"type": "text", "value": " -> ".join(chain)})
    rel = spec.get("relationship")
    if rel and not items:
        items.append({"type": "text", "value": str(rel)})
    if not items:
        return None
    return {"name": "Dependency path", "type": "list", "items": items}

# ---------- Conversion ----------
# Does the conversion from Endor JSON Findings into GitLab Dependency Scanning Report Format

def build_report_v15(endor_payload: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    findings = _load_findings(endor_payload)

    # Collect manifests for the dependency_files section
    manifests: List[str] = []
    seen = set()
    for f in findings:
        for p in _as_list(f.get("spec", {}).get("dependency_file_paths")):
            if isinstance(p, str) and p not in seen:
                seen.add(p); manifests.append(p)

    # Create report "header"
    report: Dict[str, Any] = {
        "version": "15.0.7",
        "scan": {
            "analyzer": {"id": "endor-dependency-scanner","name": "Endor Labs","vendor":{"name":"Endor Labs"},"version":"latest"},
            "scanner":  {"id": "endor-dependency-scanner","name": "Endor Labs","vendor":{"name":"Endor Labs"},"version":"latest"},
            "type": "dependency_scanning",
            "start_time": _now_iso(),
            "end_time": _now_iso(),
            "status": "success",
        },
        "dependency_files": [
            {"path": p, "package_manager": _pm_from_file(p) or "unknown", "dependencies": []}
            for p in manifests
        ],
        "vulnerabilities": [],
    }

    rows: List[Dict[str, str]] = []

    # For each finding, convert to GitLab vuln format
    for fnd in findings:
        spec = fnd.get("spec", {}) or {}
        fmd  = spec.get("finding_metadata", {}) or {}
        vuln_obj  = fmd.get("vulnerability") or {}
        vuln_spec = vuln_obj.get("spec", {}) or {}
        vuln_meta = vuln_obj.get("meta", {}) or {}

        aliases = _as_list(vuln_spec.get("aliases"))
        dep_files = _as_list(spec.get("dependency_file_paths"))
        file_path = dep_files[0] if dep_files else None

        pkg = _first(
            spec.get("target_dependency_name"),
            _get(vuln_spec, ["affected", 0, "package", "name"]),
        )
        version = _first(
            spec.get("target_dependency_version"),
            _get(vuln_spec, ["affected", 0, "versions", -1]),
            _get(vuln_spec, ["affected", 0, "ranges", 0, "introduced"]),
        )
        if not pkg or not version:
            continue

        pm = PM_MAP.get(spec.get("ecosystem")) or _pm_from_file(file_path) or "unknown"
        severity = SEV_MAP.get(spec.get("level"), "Unknown")

        preferred_id = None
        for a in aliases:
            a = str(a)
            if a.startswith(("CVE-", "GHSA-")):
                preferred_id = a; break
        if not preferred_id:
            preferred_id = _first(vuln_meta.get("name"), fmd.get("extra_key"), "Advisory")

        title = f"{pkg}@{version} - {preferred_id}"
        description = _first(
            vuln_meta.get("description"),
            vuln_spec.get("details"),
            spec.get("summary"),
            spec.get("explanation"),
            "Dependency vulnerability identified by Endor Labs.",
        )

        # identifiers WITHOUT URLs (prevents GitLab from rendering links)
        identifiers = []
        for a in aliases:
            a = str(a)
            if a.startswith("CVE-"):
                identifiers.append({"type":"cve","name":a,"value":a})
            elif a.startswith("GHSA-"):
                identifiers.append({"type":"ghsa","name":a,"value":a})
        if not identifiers and preferred_id:
            identifiers = [{"type":"other","name":preferred_id,"value":preferred_id}]

        fix_ver = _first(
            spec.get("proposed_version"),
            _get(vuln_spec, ["affected", 0, "ranges", 0, "fixed"]),
        )
        solution = f"Upgrade {pkg} to {fix_ver}." if (fix_ver and pkg) else None

        location = {
            "file": file_path or "dependency.manifest",
            "dependency": {"package": {"name": pkg}, "version": str(version)},
        }

        # Assemble what shows up under "Evidence" section in GitLab UI using above helpers
        details: Dict[str, Any] = {}
        d_call  = build_call_paths_detail(spec)
        d_reach = build_reachability_detail(spec)
        d_dep   = build_dependency_path_detail(spec)
        if d_call:  details["Call paths"] = d_call
        if d_reach: details["Reachability"] = d_reach
        if d_dep:   details["Dependency path"] = d_dep

        vuln = {
            "id": str(uuid.uuid4()),
            "category": "dependency_scanning",
            "name": title,
            "description": description,
            "severity": severity,
            "scanner": {"id":"endor-dependency-scanner","name":"Endor Labs"},
            "identifiers": identifiers,
            "location": location,
        }
        if details:
            vuln["details"] = details
        if solution:
            vuln["solution"] = solution
        # NOTE: no "links" field at all.

        report["vulnerabilities"].append(vuln)

        rows.append({
            "package": pkg,
            "version": str(version),
            "manifest": location["file"],
            "package_manager": pm,
            "severity": severity,
            "id_or_alias": preferred_id or "",
        })

    return report, rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", "-i", required=True, help="Path to Endor endor-results.json")
    ap.add_argument("--output", "-o", default="gl-dependency-scanning-report.json")
    ap.add_argument("--csv", default="endor-findings.csv", help="Optional CSV path (set empty to skip)")
    args = ap.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read input JSON: {e}", file=sys.stderr); sys.exit(2)

    report, rows = build_report_v15(payload)

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    except Exception as e:
        print(f"[ERROR] Failed to write report JSON: {e}", file=sys.stderr); sys.exit(3)

    if args.csv:
        try:
            with open(args.csv, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["package","version","manifest","package_manager","severity","id_or_alias"])
                w.writeheader(); w.writerows(rows)
        except Exception as e:
            print(f"[WARN] Failed to write CSV: {e}", file=sys.stderr)

    print(f"[OK] Wrote {args.output}" + (f" and {args.csv}" if args.csv else ""))

if __name__ == "__main__":
    sys.exit(main())
