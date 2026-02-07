# VulnRadar Improvement Plan

> Synthesized from ChatGPT and Gemini architectural reviews, plus independent analysis of the current codebase.
> Goal: Transform VulnRadar from a working prototype into a production-grade, conference-ready tool — without breaking the "fork and go" simplicity.

---

## Current State Assessment

The codebase works, has good feature coverage (KEV, EPSS, PatchThis, NVD enrichment, multi-platform notifications, GitHub Projects v2, state management, demo mode), and already has decent test coverage. However:

- **etl.py** is 1,236 lines — one monolithic file doing config loading, HTTP fetching, CVE parsing, NVD enrichment, data building, and Markdown report generation.
- **notify.py** is 2,214 lines — state management, GitHub API, Discord/Slack/Teams each implemented as standalone functions with massive copy-paste between platforms (~200 lines per provider × 3 methods each = ~1,800 lines of repetitive webhook code).
- Sequential HTTP downloads mean the ETL phase is I/O-bound and slow.
- Report generation uses string concatenation — brittle and hard to customize.
- No structured config validation — watchlist loading is ad-hoc, no schema enforcement.

---

## Phase 1: Modularize (Foundation)

**Priority: HIGH | Risk: LOW | Estimated effort: 1 day**

Split the two mega-files into a proper package. This unlocks everything else.

### 1.1 Create package structure

```
vulnradar/
├── __init__.py            # version, public API
├── cli.py                 # argparse for both ETL and notify entry points
├── config.py              # Pydantic models for watchlist + app settings
├── downloaders.py         # All HTTP fetch logic (CVE list, KEV, EPSS, PatchThis, NVD)
├── parsers.py             # CVE JSON parsing, CVSS extraction, affected-product matching
├── enrichment.py          # KEV/EPSS/PatchThis/NVD enrichment merge logic
├── report.py              # Markdown report generation (Jinja2)
├── state.py               # StateManager class (extract from notify.py)
├── notifications/
│   ├── __init__.py        # registry + load_providers()
│   ├── base.py            # Abstract NotificationProvider
│   ├── discord.py         # DiscordProvider
│   ├── slack.py           # SlackProvider
│   ├── teams.py           # TeamsProvider
│   └── github_issues.py   # GitHubIssueProvider (+ Projects v2)
└── templates/
    └── report.md.j2       # Jinja2 report template
```

Keep `etl.py` and `notify.py` at the repo root as thin entry-point shims that import from `vulnradar/` — preserves backward compatibility with existing GitHub Actions workflows.

### 1.2 Extract StateManager

`StateManager` and `Change` are already clean classes in notify.py. Move them to `vulnradar/state.py` unchanged. This is a zero-risk move.

### 1.3 Extract parsers

Functions like `parse_cve_json`, `_pick_best_description`, `_extract_cvss`, `_affected_vendor_products`, `_matches_watchlist` are pure logic with no I/O. Move to `vulnradar/parsers.py`. Easy to test in isolation.

---

## Phase 2: Notification Provider Pattern (Biggest Code Quality Win)

**Priority: HIGH | Risk: LOW | Estimated effort: 0.5 days**

This is where the largest code reduction lives. notify.py has ~1,800 lines of near-identical webhook code across Discord, Slack, and Teams (each has `send_*_alert`, `send_*_summary`, `send_*_baseline` — 9 functions doing roughly the same thing with different payload formats).

### 2.1 Abstract base class

```python
from abc import ABC, abstractmethod

class NotificationProvider(ABC):
    """Base class for all notification providers."""

    name: str  # "discord", "slack", "teams"

    @abstractmethod
    def send_alert(self, item: dict, changes: list[Change]) -> None: ...

    @abstractmethod
    def send_summary(self, items: list[dict], repo: str, changes_by_cve: dict | None) -> None: ...

    @abstractmethod
    def send_baseline(self, items: list[dict], critical_items: list[dict], repo: str) -> None: ...
```

### 2.2 Concrete implementations

Each provider becomes a single class (~100-150 lines) instead of 3 scattered functions (~200 lines each). This cuts notify.py roughly in half and makes adding providers (Matrix, PagerDuty, email) trivial.

### 2.3 Dynamic provider loading

```python
def load_providers(args) -> list[NotificationProvider]:
    providers = []
    if args.discord_webhook:
        providers.append(DiscordProvider(args.discord_webhook, max_alerts=args.discord_max))
    if args.slack_webhook:
        providers.append(SlackProvider(args.slack_webhook, max_alerts=args.slack_max))
    if args.teams_webhook:
        providers.append(TeamsProvider(args.teams_webhook, max_alerts=args.teams_max))
    return providers
```

The main loop shrinks from ~150 lines of provider-specific if/else to:

```python
for provider in providers:
    if is_first_run:
        provider.send_baseline(items, critical_items, repo)
    else:
        provider.send_summary(items, repo, changes_by_cve)
        for item in candidates[:provider.max_alerts]:
            provider.send_alert(item, changes)
```

---

## Phase 3: Pydantic Config Validation

**Priority: MEDIUM | Risk: LOW | Estimated effort: 0.5 days**

Replace the ad-hoc dictionary parsing of `watchlist.yaml` with validated Pydantic models. Currently `load_watchlist()` manually iterates, checks types, normalizes — Pydantic does this declaratively.

### 3.1 Config models

```python
from pydantic import BaseModel, field_validator

class WatchlistConfig(BaseModel):
    vendors: list[str] = []
    products: list[str] = []
    exclude_vendors: list[str] = []
    exclude_products: list[str] = []

    @field_validator("vendors", "products", "exclude_vendors", "exclude_products", mode="before")
    @classmethod
    def normalize_entries(cls, v: list) -> list[str]:
        return [s.strip().lower() for s in v if isinstance(s, str) and s.strip()]
```

### 3.2 App-level settings

Add an optional `vulnradar.yaml` (or section in watchlist.yaml) for settings currently only available via CLI args:

```yaml
settings:
  min_year: 2022
  severity_threshold: 9.0       # CVSS floor for "critical" (ChatGPT idea)
  epss_spike_threshold: 0.3     # EPSS increase to trigger alert
  skip_nvd: false
  nvd_cache_dir: .cache/nvd
```

**Constraint:** All settings must have sensible defaults. Zero-config must still work.

---

## Phase 4: Jinja2 Report Templating

**Priority: MEDIUM | Risk: LOW | Estimated effort: 0.5 days**

`write_markdown_report()` is 120 lines of string concatenation. Moving to Jinja2 makes the report layout user-customizable and much easier to maintain.

### 4.1 Create template

Move report layout to `vulnradar/templates/report.md.j2`. Users who want to customize the report format can override the template without touching Python.

### 4.2 Refactor writer

```python
from jinja2 import Environment, PackageLoader

def write_markdown_report(path: Path, items: list[dict], **kwargs) -> None:
    env = Environment(loader=PackageLoader("vulnradar", "templates"))
    template = env.get_template("report.md.j2")
    content = template.render(items=items, generated_at=_now_utc_iso(), **kwargs)
    path.write_text(content)
```

### 4.3 Template content

The template should include:
- Executive summary with critical findings table
- Summary stats (total, KEV, PatchThis, EPSS)
- Top findings table (sortable by risk)
- Recent changes section (last 7 days)
- CVE links to cve.org and NVD

---

## Phase 5: Async ETL Downloads

**Priority: MEDIUM | Risk: MEDIUM | Estimated effort: 1 day**

The ETL pipeline downloads 6+ data sources sequentially. NVD feeds alone can be 5 files × 15MB each. This is the main bottleneck.

### 5.1 Approach: `asyncio` + `aiohttp`

**Gemini's approach (full async rewrite)** is architecturally clean but adds complexity and a new dependency. The pragmatic path:

- Keep the main ETL flow synchronous for simplicity.
- Use `asyncio.run()` only for the download phase — a single `download_all()` coroutine that fetches KEV, EPSS, PatchThis, NVD feeds, and CVE list ZIP in parallel.
- Use `tenacity` for retry logic (it already supports async).

```python
async def download_all(session: aiohttp.ClientSession, years: list[int]) -> DownloadResults:
    """Download all data sources in parallel."""
    results = await asyncio.gather(
        download_kev(session),
        download_epss(session),
        download_patchthis(session),
        download_nvd_feeds(session, years),
        download_cvelist_zip(session),
        return_exceptions=True,
    )
    # Handle individual failures gracefully
    ...
```

### 5.2 Graceful degradation

If any single download fails, continue with what we have. Currently the code already does this for NVD feeds but not for others. Extend this pattern everywhere.

### 5.3 Progress reporting

Add simple progress output: "Downloading 7 sources in parallel..." with per-source completion logs. No need for a progress bar library in CI.

### 5.4 Dependency note

Adds `aiohttp` to requirements.txt. This is the only net-new dependency from this phase. **Evaluate whether the speed gain is worth the added dependency** — if users are running in GitHub Actions on a timer, the extra 60 seconds may not matter. Consider making this opt-in with a `--parallel` flag and keeping the `requests`-based sequential path as default.

---

## Phase 6: Testing Improvements

**Priority: HIGH | Risk: LOW | Estimated effort: 0.5 days**

Tests exist for parsers and some notify functions. Gaps:

### 6.1 New test coverage needed

| Area | What to test | Current coverage |
|------|-------------|-----------------|
| `config.py` | Pydantic validation, normalization, defaults | None (new) |
| `downloaders.py` | Mocked HTTP responses, retry behavior, graceful failures | None |
| `notifications/` | Payload format for each provider (mock `requests.post`) | Partial |
| `state.py` | Change detection, pruning, snapshot updates | None (logic exists in test_notify.py but not exhaustive) |
| `report.py` | Jinja2 template rendering with edge cases | None |
| Integration | End-to-end with fixture data (no network) | None |

### 6.2 Test fixtures

Create `tests/fixtures/` with:
- Sample CVE JSON (from cvelistV5 format)
- Sample KEV response
- Sample EPSS CSV
- Sample NVD feed JSON
- Sample radar_data.json output

### 6.3 Coverage target

Aim for 80%+ on business logic (parsers, enrichment, change detection, config). Don't waste time mocking GitHub API calls exhaustively.

---

## Phase 7: Feature Enhancements

**Priority: LOW-MEDIUM | Risk: MEDIUM | Estimated effort: 1-2 days**

These are nice-to-haves from both prompts. Implement after the architectural work is solid.

### 7.1 Configurable severity threshold (ChatGPT)

Currently "critical" means `in_patchthis AND in_watchlist`. Add an option for CVSS-based threshold:

```yaml
settings:
  severity_threshold: 9.0    # Also flag CVEs with CVSS >= 9.0 as critical
  epss_threshold: 0.5        # Flag CVEs with EPSS >= 50%
```

This expands the definition of "critical" beyond just exploit intel + watchlist.

### 7.2 Configurable notification routing

Allow different webhook URLs per severity level:

```yaml
notifications:
  discord:
    - url: $DISCORD_CRITICAL_WEBHOOK
      filter: critical          # Only critical alerts
    - url: $DISCORD_ALL_WEBHOOK
      filter: all               # Everything including summaries
```

### 7.3 Email notifications (stretch goal)

Add an `EmailProvider` using SMTP. Low priority since most users will use webhooks, but useful for enterprise environments.

### 7.4 SARIF output (stretch goal)

Export findings in SARIF format for GitHub Code Scanning integration. This would let VulnRadar findings appear directly in the Security tab.

---

## Phase 8: Documentation & Developer Experience

**Priority: MEDIUM | Risk: LOW | Estimated effort: 0.5 days**

### 8.1 README updates

- Add architecture diagram (Mermaid) showing data flow
- Document new config options
- Add "Running locally" section with Docker option
- Add BSides presentation badge/link

### 8.2 Contributing guide

Update `docs/contributing.md` with:
- How to add a new notification provider (just extend `NotificationProvider`)
- How to customize the report template
- How to run tests locally

### 8.3 Inline documentation

Add Google-style docstrings to all public classes and methods. The current code has some but is inconsistent.

---

## Dependency Changes

| Package | Purpose | Required? |
|---------|---------|-----------|
| `pydantic` | Config validation | Yes (Phase 3) |
| `jinja2` | Report templating | Yes (Phase 4) |
| `aiohttp` | Async downloads | Optional (Phase 5) |

Updated `requirements.txt`:
```
requests>=2.31.0
tenacity>=8.2.3
pyyaml>=6.0.1
pydantic>=2.0
jinja2>=3.1
```

---

## What We're NOT Doing (and Why)

These ideas from the prompts were evaluated and intentionally excluded:

| Idea | Why not |
|------|---------|
| **Full async rewrite** (Gemini) | Overkill for a CI tool. Async downloads yes, but keeping the main flow sync avoids complexity for contributors. |
| **CLI framework (click/typer)** | argparse works fine and has zero dependencies. Not worth the migration cost. |
| **Docker-first deployment** | This is a GitHub Actions tool. Docker adds setup friction for the primary use case. Document it in README for local use, don't architect around it. |
| **Database backend** | JSON state file is sufficient for the scale. SQLite would add complexity with no user benefit. |
| **Streamlit dashboard** | README mentions it was already removed. The Markdown report is the dashboard. Keep it simple. |
| **AsyncDownloader class** (Gemini) | A class for downloading is over-abstraction. Module-level async functions with `asyncio.gather()` are simpler and more Pythonic. |

---

## Implementation Order

```
Phase 1 (Modularize)         ████████████████████  Day 1
Phase 2 (Provider Pattern)   ██████████            Day 1-2
Phase 3 (Pydantic Config)    ██████                Day 2
Phase 4 (Jinja2 Reports)     ██████                Day 2
Phase 6 (Tests)              ██████████            Day 2-3
Phase 5 (Async Downloads)    ██████████            Day 3 (optional)
Phase 7 (Features)           ████████████          Day 3-4 (optional)
Phase 8 (Docs)               ██████                Day 4
```

Phases 1-4 and 6 are the core improvements. Phases 5, 7, and 8 are stretch goals.

---

## Success Criteria

- [ ] `etl.py` and `notify.py` are each under 100 lines (thin CLI shims)
- [ ] Adding a new notification provider requires only one new file (~100 lines)
- [ ] Report format is customizable via template without touching Python
- [ ] `watchlist.yaml` parsing has full Pydantic validation with clear error messages
- [ ] Test coverage ≥ 80% on business logic
- [ ] Zero breaking changes to existing CLI flags or GitHub Actions workflows
- [ ] Default config (no customization) still works out of the box
- [ ] BSides demo mode still works end-to-end
