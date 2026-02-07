"""Unit tests for vulnradar.enrichment — CVE traversal and radar assembly."""

import json
from pathlib import Path
from typing import Any

import pytest

from vulnradar.enrichment import (
    build_radar_data,
    extract_all_vendors_products,
    find_cves_root,
    guess_cve_path,
    iter_cve_json_paths,
    now_utc_iso,
    parse_cve_json,
    write_radar_data,
    years_to_process,
)

# ── Helpers / fixtures ───────────────────────────────────────────────────────


def _make_cve_file(cves_root: Path, cve_id: str, vendor: str, product: str) -> Path:
    """Create a minimal CVE V5 JSON file in the standard directory layout."""
    year, num = cve_id.split("-")[1], int(cve_id.split("-")[2])
    group = f"{num // 1000}xxx"
    dest = cves_root / year / group / f"{cve_id}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": "2024-06-15T10:00:00.000Z",
        },
        "containers": {
            "cna": {
                "affected": [{"vendor": vendor, "product": product}],
                "descriptions": [{"lang": "en", "value": f"Vuln in {product}"}],
                "metrics": [{"cvssV3_1": {"baseScore": 8.0, "baseSeverity": "HIGH"}}],
            }
        },
    }
    dest.write_text(json.dumps(doc))
    return dest


@pytest.fixture
def cve_tree(tmp_path: Path) -> Path:
    """Create a small CVE tree under tmp_path/extracted/cves."""
    cves_root = tmp_path / "extracted" / "cves"
    _make_cve_file(cves_root, "CVE-2024-10001", "Apache", "Log4j")
    _make_cve_file(cves_root, "CVE-2024-10002", "Microsoft", "Exchange")
    _make_cve_file(cves_root, "CVE-2023-20001", "Linux", "Kernel")
    return tmp_path / "extracted"


# ── now_utc_iso ──────────────────────────────────────────────────────────────


class TestNowUtcIso:
    def test_format(self):
        ts = now_utc_iso()
        assert "T" in ts
        assert "+" in ts or "Z" in ts


# ── find_cves_root ───────────────────────────────────────────────────────────


class TestFindCvesRoot:
    def test_finds_cves_dir(self, cve_tree: Path):
        root = find_cves_root(cve_tree)
        assert root.name == "cves"
        assert root.is_dir()

    def test_no_cves_dir_fallback(self, tmp_path: Path):
        root = find_cves_root(tmp_path)
        assert root == tmp_path

    def test_nested_cves_picks_shallowest(self, tmp_path: Path):
        (tmp_path / "a" / "cves").mkdir(parents=True)
        (tmp_path / "a" / "b" / "cves").mkdir(parents=True)
        root = find_cves_root(tmp_path)
        # The shallowest path is a/cves, not a/b/cves
        assert root == tmp_path / "a" / "cves"


# ── years_to_process ─────────────────────────────────────────────────────────


class TestYearsToProcess:
    def test_range(self):
        assert years_to_process(2022, 2024) == [2022, 2023, 2024]

    def test_single_year(self):
        assert years_to_process(2024, 2024) == [2024]

    def test_inverted_range(self):
        assert years_to_process(2025, 2020) == []

    def test_none_max_defaults_to_current(self):
        import datetime as dt

        result = years_to_process(2024, None)
        assert dt.datetime.now().year in result


# ── iter_cve_json_paths ──────────────────────────────────────────────────────


class TestIterCveJsonPaths:
    def test_yields_json_files(self, cve_tree: Path):
        root = find_cves_root(cve_tree)
        paths = list(iter_cve_json_paths(root, [2024]))
        assert len(paths) == 2
        names = {p.name for p in paths}
        assert "CVE-2024-10001.json" in names
        assert "CVE-2024-10002.json" in names

    def test_year_without_files(self, cve_tree: Path):
        root = find_cves_root(cve_tree)
        assert list(iter_cve_json_paths(root, [1999])) == []

    def test_multi_year(self, cve_tree: Path):
        root = find_cves_root(cve_tree)
        paths = list(iter_cve_json_paths(root, [2023, 2024]))
        assert len(paths) == 3


# ── guess_cve_path ───────────────────────────────────────────────────────────


class TestGuessCvePath:
    def test_standard_layout(self, cve_tree: Path):
        root = find_cves_root(cve_tree)
        path = guess_cve_path(root, "CVE-2024-10001")
        assert path is not None
        assert path.name == "CVE-2024-10001.json"

    def test_not_found(self, cve_tree: Path):
        root = find_cves_root(cve_tree)
        assert guess_cve_path(root, "CVE-2024-99999") is None

    def test_invalid_cve(self, cve_tree: Path):
        root = find_cves_root(cve_tree)
        assert guess_cve_path(root, "not-a-cve") is None


# ── parse_cve_json ───────────────────────────────────────────────────────────


class TestParseCveJson:
    def test_valid_file(self, cve_tree: Path):
        root = find_cves_root(cve_tree)
        path = guess_cve_path(root, "CVE-2024-10001")
        result = parse_cve_json(path)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-10001"

    def test_bad_file(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("NOT JSON")
        assert parse_cve_json(bad) is None

    def test_nonexistent_file(self, tmp_path: Path):
        assert parse_cve_json(tmp_path / "nope.json") is None


# ── build_radar_data ─────────────────────────────────────────────────────────


class TestBuildRadarData:
    def test_basic_watchlist_match(self, cve_tree: Path):
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"apache"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={},
            patchthis_cves=set(),
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
        )
        assert len(items) == 1
        assert items[0]["cve_id"] == "CVE-2024-10001"
        assert items[0]["in_watchlist"] is True

    def test_kev_match_without_watchlist(self, cve_tree: Path):
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors=set(),
            wl_products=set(),
            kev_by_cve={"CVE-2024-10002": {"cveID": "CVE-2024-10002", "dateAdded": "2024-01-01"}},
            epss_by_cve={},
            patchthis_cves=set(),
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
        )
        assert len(items) == 1
        assert items[0]["active_threat"] is True

    def test_enrichment_epss_and_patchthis(self, cve_tree: Path):
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"apache"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={"CVE-2024-10001": 0.92},
            patchthis_cves={"CVE-2024-10001"},
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
        )
        assert len(items) == 1
        assert items[0]["probability_score"] == 0.92
        assert items[0]["in_patchthis"] is True
        assert items[0]["is_critical"] is True  # patchthis + watchlist

    def test_nvd_enrichment(self, cve_tree: Path):
        nvd = {
            "CVE-2024-10001": {
                "cvss_v3_score": 9.1,
                "cvss_v3_severity": "CRITICAL",
                "cvss_v3_vector": "AV:N",
                "cvss_v2_score": None,
                "cvss_v2_severity": None,
                "cwe_ids": ["CWE-79"],
                "cpe_count": 2,
                "reference_count": 3,
            }
        }
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"apache"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={},
            patchthis_cves=set(),
            nvd_by_cve=nvd,
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
        )
        assert items[0].get("nvd") is not None
        assert items[0]["nvd"]["cwe_ids"] == ["CWE-79"]

    def test_kev_outside_window(self, cve_tree: Path):
        """KEV CVEs from years outside the scan window should be included."""
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors=set(),
            wl_products=set(),
            kev_by_cve={"CVE-2023-20001": {"cveID": "CVE-2023-20001"}},
            epss_by_cve={},
            patchthis_cves=set(),
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=True,
        )
        ids = {i["cve_id"] for i in items}
        assert "CVE-2023-20001" in ids

    def test_no_matches(self, cve_tree: Path):
        items = build_radar_data(
            extracted_dir=cve_tree,
            wl_vendors={"nonexistent"},
            wl_products=set(),
            kev_by_cve={},
            epss_by_cve={},
            patchthis_cves=set(),
            nvd_by_cve={},
            min_year=2024,
            max_year=2024,
            include_kev_outside_window=False,
        )
        assert items == []


# ── write_radar_data ─────────────────────────────────────────────────────────


class TestWriteRadarData:
    def test_creates_json(self, tmp_path: Path):
        out = tmp_path / "out" / "radar.json"
        write_radar_data(out, [{"cve_id": "CVE-2024-00001"}])
        assert out.exists()
        payload = json.loads(out.read_text())
        assert payload["count"] == 1
        assert isinstance(payload["items"], list)
        assert "generated_at" in payload

    def test_atomic_write(self, tmp_path: Path):
        """No .tmp file should remain after write."""
        out = tmp_path / "data.json"
        write_radar_data(out, [])
        assert not (tmp_path / "data.json.tmp").exists()

    def test_overwrites_existing(self, tmp_path: Path):
        out = tmp_path / "data.json"
        write_radar_data(out, [{"id": 1}])
        write_radar_data(out, [{"id": 2}, {"id": 3}])
        payload = json.loads(out.read_text())
        assert payload["count"] == 2


# ── extract_all_vendors_products ─────────────────────────────────────────────


class TestExtractAllVendorsProducts:
    def test_extracts(self, cve_tree: Path):
        vendors, products = extract_all_vendors_products(cve_tree, [2023, 2024])
        assert "apache" in vendors or "apache software foundation" in vendors
        assert "log4j" in products

    def test_empty_years(self, cve_tree: Path):
        vendors, products = extract_all_vendors_products(cve_tree, [1999])
        assert len(vendors) == 0
        assert len(products) == 0
