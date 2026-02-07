"""Enrichment and radar data assembly.

Combines CVE List V5 parsed data with KEV, EPSS, PatchThis, and NVD
sources to build the final radar dataset. Also handles file traversal
of the extracted CVE archive.
"""

import datetime as dt
import json
import shutil
from pathlib import Path
from typing import Any, Iterator, Sequence

from .parsers import (
    cve_year_and_num,
    matches_watchlist,
    norm,
    parse_cve_json_data,
)


def now_utc_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def find_cves_root(extracted_dir: Path) -> Path:
    """Locate the ``cves/`` directory inside an extracted CVE archive.

    Args:
        extracted_dir: Root of the extracted ZIP.

    Returns:
        Path to the ``cves/`` directory (or extracted_dir as fallback).
    """
    candidates = []
    for p in extracted_dir.rglob("cves"):
        if p.is_dir():
            candidates.append(p)
    if not candidates:
        return extracted_dir
    return sorted(candidates, key=lambda x: len(str(x)))[0]


def years_to_process(min_year: int, max_year: int | None) -> list[int]:
    """Generate a list of years to scan.

    Args:
        min_year: Inclusive lower bound.
        max_year: Inclusive upper bound (defaults to current year).

    Returns:
        Sorted list of years.
    """
    if max_year is None:
        max_year = dt.datetime.now().year
    if max_year < min_year:
        return []
    return list(range(min_year, max_year + 1))


def iter_cve_json_paths(cves_root: Path, years: Sequence[int]) -> Iterator[Path]:
    """Yield paths to CVE JSON files for the given years.

    Args:
        cves_root: Root ``cves/`` directory.
        years: Years to scan.

    Yields:
        Path objects for each ``CVE-*.json`` file.
    """
    for year in years:
        year_dir = cves_root / str(year)
        if year_dir.exists() and year_dir.is_dir():
            yield from year_dir.rglob("CVE-*.json")


def guess_cve_path(cves_root: Path, cve_id: str) -> Path | None:
    """Guess the file path for a CVE ID using the standard directory layout.

    Args:
        cves_root: Root ``cves/`` directory.
        cve_id: CVE identifier.

    Returns:
        Path if found, None otherwise.
    """
    parsed = cve_year_and_num(cve_id)
    if not parsed:
        return None
    year, num = parsed
    group = f"{num // 1000}xxx"
    guess = cves_root / str(year) / group / f"{cve_id.upper()}.json"
    if guess.exists():
        return guess
    year_dir = cves_root / str(year)
    if year_dir.exists():
        match = next(iter(year_dir.rglob(f"{cve_id.upper()}.json")), None)
        if match:
            return match
    return None


def parse_cve_json(path: Path) -> dict[str, Any] | None:
    """Load and parse a single CVE JSON file.

    Args:
        path: Path to a CVE V5 JSON file.

    Returns:
        Parsed record dict, or None on failure.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    return parse_cve_json_data(data)


def build_radar_data(
    extracted_dir: Path,
    wl_vendors: set[str],
    wl_products: set[str],
    kev_by_cve: dict[str, dict[str, Any]],
    epss_by_cve: dict[str, float],
    patchthis_cves: set[str],
    nvd_by_cve: dict[str, dict[str, Any]],
    min_year: int,
    max_year: int | None,
    include_kev_outside_window: bool,
    severity_threshold: float | None = None,
    epss_threshold: float | None = None,
) -> list[dict[str, Any]]:
    """Assemble the final radar dataset.

    Scans the extracted CVE archive, filters by watchlist, and enriches
    each matching CVE with KEV, EPSS, PatchThis, and NVD data.

    Args:
        extracted_dir: Root of the extracted CVE List archive.
        wl_vendors: Set of normalized watchlist vendor strings.
        wl_products: Set of normalized watchlist product strings.
        kev_by_cve: KEV lookup dict.
        epss_by_cve: EPSS lookup dict.
        patchthis_cves: Set of CVE IDs with exploit intel.
        nvd_by_cve: NVD enrichment lookup dict.
        min_year: Minimum CVE year to scan.
        max_year: Maximum CVE year (None = current year).
        include_kev_outside_window: Whether to include KEV entries
            outside the year range.
        severity_threshold: Optional CVSS floor — CVEs at or above
            this score AND on the watchlist are flagged critical.
        epss_threshold: Optional EPSS floor — CVEs at or above this
            probability AND on the watchlist are flagged critical.

    Returns:
        List of enriched radar item dicts.
    """
    cves_root = find_cves_root(extracted_dir)
    years = years_to_process(min_year, max_year)

    paths: set[Path] = set(iter_cve_json_paths(cves_root, years))

    if include_kev_outside_window:
        for cve_id in kev_by_cve:
            year_num = cve_year_and_num(cve_id)
            if not year_num:
                continue
            year, _ = year_num
            if year in years:
                continue
            p = guess_cve_path(cves_root, cve_id)
            if p:
                paths.add(p)

    items: list[dict[str, Any]] = []
    for p in sorted(paths):
        parsed = parse_cve_json(p)
        if not parsed:
            continue

        cve_id = parsed["cve_id"]
        affected = parsed.get("affected") or []
        watch_hit = False
        matched_terms: list[str] = []
        for a in affected:
            if not isinstance(a, dict):
                continue
            vendor = a.get("vendor") or ""
            product = a.get("product") or ""
            if matches_watchlist(str(vendor), str(product), wl_vendors, wl_products):
                watch_hit = True
                if vendor:
                    matched_terms.append(f"vendor:{vendor}")
                if product:
                    matched_terms.append(f"product:{product}")

        kev = kev_by_cve.get(cve_id)
        active_threat = kev is not None
        in_patchthis = cve_id in patchthis_cves
        in_watchlist = watch_hit

        # ── Criticality logic ────────────────────────────────────────
        # Original rule: patchthis + watchlist = critical
        is_critical = bool(in_patchthis and in_watchlist)

        # Configurable thresholds: CVSS >= severity_threshold (on watchlist)
        cvss_val = parsed.get("cvss_score")
        epss_val = epss_by_cve.get(cve_id)
        if not is_critical and in_watchlist and severity_threshold is not None:
            try:
                if cvss_val is not None and float(cvss_val) >= severity_threshold:
                    is_critical = True
            except (TypeError, ValueError):
                pass

        # Configurable thresholds: EPSS >= epss_threshold (on watchlist)
        if not is_critical and in_watchlist and epss_threshold is not None:
            try:
                if epss_val is not None and float(epss_val) >= epss_threshold:
                    is_critical = True
            except (TypeError, ValueError):
                pass

        if is_critical:
            if in_patchthis and in_watchlist:
                priority_label = "CRITICAL (Active Exploit in Stack)"
            elif severity_threshold is not None and cvss_val is not None:
                try:
                    if float(cvss_val) >= severity_threshold:
                        priority_label = f"CRITICAL (CVSS ≥ {severity_threshold})"
                    else:
                        priority_label = f"CRITICAL (EPSS ≥ {epss_threshold})"
                except (TypeError, ValueError):
                    priority_label = "CRITICAL"
            else:
                priority_label = "CRITICAL"
        else:
            priority_label = ""

        if (not in_watchlist) and (not active_threat):
            continue

        record: dict[str, Any] = {
            **parsed,
            "watchlist_hit": watch_hit,
            "in_watchlist": in_watchlist,
            "in_patchthis": in_patchthis,
            "is_critical": is_critical,
            "priority_label": priority_label,
            "matched_terms": sorted(set(matched_terms)) if watch_hit else [],
            "active_threat": active_threat,
            "probability_score": epss_by_cve.get(cve_id),
        }

        if kev:
            record["kev"] = {
                "cveID": kev.get("cveID"),
                "vendorProject": kev.get("vendorProject"),
                "product": kev.get("product"),
                "vulnerabilityName": kev.get("vulnerabilityName"),
                "dateAdded": kev.get("dateAdded"),
                "shortDescription": kev.get("shortDescription"),
                "requiredAction": kev.get("requiredAction"),
                "dueDate": kev.get("dueDate"),
                "knownRansomwareCampaignUse": kev.get("knownRansomwareCampaignUse"),
            }

        nvd = nvd_by_cve.get(cve_id)
        if nvd:
            if record.get("cvss_score") is None and nvd.get("cvss_v3_score"):
                record["cvss_score"] = nvd["cvss_v3_score"]
                record["cvss_severity"] = nvd.get("cvss_v3_severity")
                record["cvss_vector"] = nvd.get("cvss_v3_vector")
            record["nvd"] = {
                "cvss_v3_score": nvd.get("cvss_v3_score"),
                "cvss_v3_severity": nvd.get("cvss_v3_severity"),
                "cvss_v2_score": nvd.get("cvss_v2_score"),
                "cvss_v2_severity": nvd.get("cvss_v2_severity"),
                "cwe_ids": nvd.get("cwe_ids"),
                "cpe_count": nvd.get("cpe_count"),
                "reference_count": nvd.get("reference_count"),
            }

        items.append(record)

    return items


def write_radar_data(path: Path, items: list[dict[str, Any]]) -> None:
    """Write radar data to a JSON file atomically.

    Args:
        path: Output file path.
        items: List of radar item dicts.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": now_utc_iso(),
        "count": len(items),
        "items": items,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")
    tmp.replace(path)


def extract_all_vendors_products(extracted_dir: Path, years: list[int]) -> tuple[set[str], set[str]]:
    """Extract all unique vendors and products from CVE data.

    Used by discovery commands (``--list-vendors``, ``--list-products``).

    Args:
        extracted_dir: Root of the extracted CVE archive.
        years: Years to scan.

    Returns:
        Tuple of (vendors_set, products_set).
    """
    cves_root = find_cves_root(extracted_dir)
    vendors: set[str] = set()
    products: set[str] = set()

    for p in iter_cve_json_paths(cves_root, years):
        try:
            with p.open("r", encoding="utf-8") as f:
                raw = json.load(f)
            containers = raw.get("containers", {})
            cna = containers.get("cna", {})
            affected = cna.get("affected") or []
            for a in affected:
                if not isinstance(a, dict):
                    continue
                v = norm(str(a.get("vendor") or ""))
                prod = norm(str(a.get("product") or ""))
                if v and v not in ("n/a", "unknown", "unspecified", ""):
                    vendors.add(v)
                if prod and prod not in ("n/a", "unknown", "unspecified", ""):
                    products.add(prod)
        except Exception:
            continue

    return vendors, products
