#!/usr/bin/env python3

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

import requests

DEFAULT_TIMEOUT = (10, 60)


def _session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "User-Agent": "VulnRadar-Notify/0.1",
            "Authorization": f"Bearer {token}",
        }
    )
    return s


def _load_items(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return payload["items"]
    if isinstance(payload, list):
        return payload
    return []


def _iter_recent_issues(session: requests.Session, repo: str, *, max_pages: int = 3) -> Iterable[Dict[str, Any]]:
    """Yield recent issues (not PRs) without using Search API."""

    base = f"https://api.github.com/repos/{repo}/issues"
    for page in range(1, max_pages + 1):
        r = session.get(
            base,
            params={"state": "all", "per_page": 100, "page": page},
            timeout=DEFAULT_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list) or not data:
            return
        for issue in data:
            if not isinstance(issue, dict):
                continue
            if "pull_request" in issue:
                continue
            yield issue


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


def _existing_notified_cves(session: requests.Session, repo: str) -> Set[str]:
    out: Set[str] = set()
    for issue in _iter_recent_issues(session, repo, max_pages=4):
        title = str(issue.get("title") or "")
        if "[VulnRadar]" not in title:
            continue
        m = _CVE_RE.search(title)
        if m:
            out.add(m.group(0).upper())
    return out


def _create_issue(session: requests.Session, repo: str, title: str, body: str, labels: Optional[List[str]] = None) -> None:
    url = f"https://api.github.com/repos/{repo}/issues"
    payload: Dict[str, Any] = {"title": title, "body": body}
    if labels:
        payload["labels"] = labels
    r = session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def _issue_body(item: Dict[str, Any]) -> str:
    cve_id = str(item.get("cve_id") or "")
    desc = str(item.get("description") or "").strip()
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    kev = bool(item.get("active_threat"))
    patch = bool(item.get("in_patchthis"))
    watch = bool(item.get("watchlist_hit"))
    is_critical = bool(item.get("is_critical"))
    priority = "CRITICAL" if is_critical else "ALERT"
    kev_due = ""
    kev_obj = item.get("kev")
    if isinstance(kev_obj, dict):
        kev_due = str(kev_obj.get("dueDate") or "").strip()

    def fmt(x: Any, ndigits: int) -> str:
        try:
            return f"{float(x):.{ndigits}f}"
        except Exception:
            return ""

    lines = []
    lines.append(f"CVE: {cve_id}")
    lines.append(f"Priority: {priority}" if priority else "Priority: (none)")
    lines.append("")
    lines.append("Signals:")
    lines.append(f"- PatchThis: {'yes' if patch else 'no'}")
    lines.append(f"- Watchlist: {'yes' if watch else 'no'}")
    lines.append(f"- CISA KEV: {'yes' if kev else 'no'}")
    if kev_due:
        lines.append(f"- KEV Due Date: {kev_due}")
    lines.append(f"- EPSS: {fmt(epss, 3)}")
    lines.append(f"- CVSS: {fmt(cvss, 1)}")
    lines.append("")
    if desc:
        lines.append("Description:")
        lines.append(desc)
        lines.append("")
    lines.append(f"CVE.org record: https://www.cve.org/CVERecord?id={cve_id}")
    return "\n".join(lines)


def send_discord_alert(webhook_url: str, item: Dict[str, Any]) -> None:
    """Send a formatted Discord embed for a CVE finding."""
    cve_id = str(item.get("cve_id") or "")
    desc = str(item.get("description") or "")[:500]
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    kev = bool(item.get("active_threat"))
    patch = bool(item.get("in_patchthis"))
    is_critical = bool(item.get("is_critical"))
    
    # Color: red for critical, orange for KEV, blue for others
    if is_critical:
        color = 0xFF0000  # Red
        priority = "🚨 CRITICAL"
    elif kev:
        color = 0xFFA500  # Orange
        priority = "⚠️ KEV"
    else:
        color = 0x3498DB  # Blue
        priority = "ℹ️ ALERT"
    
    # Format scores
    try:
        epss_str = f"{float(epss):.1%}" if epss is not None else "N/A"
    except Exception:
        epss_str = "N/A"
    try:
        cvss_str = f"{float(cvss):.1f}" if cvss is not None else "N/A"
    except Exception:
        cvss_str = "N/A"
    
    # Get KEV due date if available
    kev_due = ""
    kev_obj = item.get("kev")
    if isinstance(kev_obj, dict):
        kev_due = str(kev_obj.get("dueDate") or "")
    
    fields = [
        {"name": "EPSS", "value": epss_str, "inline": True},
        {"name": "CVSS", "value": cvss_str, "inline": True},
        {"name": "KEV", "value": "✅ Yes" if kev else "❌ No", "inline": True},
        {"name": "PatchThis", "value": "✅ Yes" if patch else "❌ No", "inline": True},
    ]
    
    if kev_due:
        fields.append({"name": "KEV Due Date", "value": kev_due, "inline": True})
    
    payload = {
        "embeds": [{
            "title": f"{priority}: {cve_id}",
            "description": desc if desc else "No description available.",
            "color": color,
            "fields": fields,
            "url": f"https://www.cve.org/CVERecord?id={cve_id}",
            "footer": {"text": "VulnRadar Alert"}
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def send_discord_summary(webhook_url: str, items: List[Dict[str, Any]], repo: str) -> None:
    """Send a summary embed to Discord with counts and top findings."""
    total = len(items)
    critical_count = sum(1 for i in items if bool(i.get("is_critical")))
    kev_count = sum(1 for i in items if bool(i.get("active_threat")))
    patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))
    
    # Get top 5 critical items
    critical_items = [i for i in items if bool(i.get("is_critical"))]
    critical_items.sort(key=lambda x: float(x.get("probability_score") or 0), reverse=True)
    top_5 = critical_items[:5]
    
    top_list = ""
    for i in top_5:
        cve = i.get("cve_id", "")
        epss = i.get("probability_score")
        try:
            epss_str = f"{float(epss):.1%}" if epss else "?"
        except Exception:
            epss_str = "?"
        top_list += f"• [{cve}](https://www.cve.org/CVERecord?id={cve}) (EPSS: {epss_str})\n"
    
    if not top_list:
        top_list = "No critical findings."
    
    color = 0xFF0000 if critical_count > 0 else 0x00FF00
    
    payload = {
        "embeds": [{
            "title": "📊 VulnRadar Daily Summary",
            "color": color,
            "fields": [
                {"name": "Total CVEs", "value": str(total), "inline": True},
                {"name": "🚨 Critical", "value": str(critical_count), "inline": True},
                {"name": "⚠️ CISA KEV", "value": str(kev_count), "inline": True},
                {"name": "🔥 PatchThis", "value": str(patch_count), "inline": True},
                {"name": "Top Critical Findings", "value": top_list, "inline": False},
            ],
            "footer": {"text": f"Repo: {repo}"}
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


# ─────────────────────────────────────────────────────────────────────────────
# Slack Webhooks
# ─────────────────────────────────────────────────────────────────────────────

def send_slack_alert(webhook_url: str, item: Dict[str, Any]) -> None:
    """Send a formatted Slack message for a CVE finding."""
    cve_id = str(item.get("cve_id") or "")
    desc = str(item.get("description") or "")[:500]
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    kev = bool(item.get("active_threat"))
    patch = bool(item.get("in_patchthis"))
    is_critical = bool(item.get("is_critical"))
    
    # Priority indicator
    if is_critical:
        priority = "🚨 *CRITICAL*"
        color = "danger"
    elif kev:
        priority = "⚠️ *KEV*"
        color = "warning"
    else:
        priority = "ℹ️ *ALERT*"
        color = "#3498DB"
    
    # Format scores
    try:
        epss_str = f"{float(epss):.1%}" if epss is not None else "N/A"
    except Exception:
        epss_str = "N/A"
    try:
        cvss_str = f"{float(cvss):.1f}" if cvss is not None else "N/A"
    except Exception:
        cvss_str = "N/A"
    
    cve_url = f"https://www.cve.org/CVERecord?id={cve_id}"
    
    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{priority}: <{cve_url}|{cve_id}>\n{desc}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*EPSS:* {epss_str}"},
                        {"type": "mrkdwn", "text": f"*CVSS:* {cvss_str}"},
                        {"type": "mrkdwn", "text": f"*KEV:* {'✅ Yes' if kev else '❌ No'}"},
                        {"type": "mrkdwn", "text": f"*PatchThis:* {'✅ Yes' if patch else '❌ No'}"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": "VulnRadar Alert"}]
                }
            ]
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def send_slack_summary(webhook_url: str, items: List[Dict[str, Any]], repo: str) -> None:
    """Send a summary message to Slack with counts and top findings."""
    total = len(items)
    critical_count = sum(1 for i in items if bool(i.get("is_critical")))
    kev_count = sum(1 for i in items if bool(i.get("active_threat")))
    patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))
    
    # Get top 5 critical items
    critical_items = [i for i in items if bool(i.get("is_critical"))]
    critical_items.sort(key=lambda x: float(x.get("probability_score") or 0), reverse=True)
    top_5 = critical_items[:5]
    
    top_list = ""
    for i in top_5:
        cve = i.get("cve_id", "")
        epss = i.get("probability_score")
        cve_url = f"https://www.cve.org/CVERecord?id={cve}"
        try:
            epss_str = f"{float(epss):.1%}" if epss else "?"
        except Exception:
            epss_str = "?"
        top_list += f"• <{cve_url}|{cve}> (EPSS: {epss_str})\n"
    
    if not top_list:
        top_list = "No critical findings."
    
    color = "danger" if critical_count > 0 else "good"
    
    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "📊 VulnRadar Daily Summary", "emoji": True}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Total CVEs:* {total}"},
                        {"type": "mrkdwn", "text": f"*🚨 Critical:* {critical_count}"},
                        {"type": "mrkdwn", "text": f"*⚠️ CISA KEV:* {kev_count}"},
                        {"type": "mrkdwn", "text": f"*🔥 PatchThis:* {patch_count}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Top Critical Findings:*\n{top_list}"}
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"Repo: {repo}"}]
                }
            ]
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Teams Webhooks (Adaptive Cards)
# ─────────────────────────────────────────────────────────────────────────────

def send_teams_alert(webhook_url: str, item: Dict[str, Any]) -> None:
    """Send a formatted Teams Adaptive Card for a CVE finding."""
    cve_id = str(item.get("cve_id") or "")
    desc = str(item.get("description") or "")[:500]
    epss = item.get("probability_score")
    cvss = item.get("cvss_score")
    kev = bool(item.get("active_threat"))
    patch = bool(item.get("in_patchthis"))
    is_critical = bool(item.get("is_critical"))
    
    # Priority indicator and color
    if is_critical:
        priority = "🚨 CRITICAL"
        color = "attention"
    elif kev:
        priority = "⚠️ KEV"
        color = "warning"
    else:
        priority = "ℹ️ ALERT"
        color = "accent"
    
    # Format scores
    try:
        epss_str = f"{float(epss):.1%}" if epss is not None else "N/A"
    except Exception:
        epss_str = "N/A"
    try:
        cvss_str = f"{float(cvss):.1f}" if cvss is not None else "N/A"
    except Exception:
        cvss_str = "N/A"
    
    cve_url = f"https://www.cve.org/CVERecord?id={cve_id}"
    
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": f"{priority}: {cve_id}",
                        "weight": "Bolder",
                        "size": "Large",
                        "color": color
                    },
                    {
                        "type": "TextBlock",
                        "text": desc if desc else "No description available.",
                        "wrap": True
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "EPSS", "value": epss_str},
                            {"title": "CVSS", "value": cvss_str},
                            {"title": "KEV", "value": "✅ Yes" if kev else "❌ No"},
                            {"title": "PatchThis", "value": "✅ Yes" if patch else "❌ No"},
                        ]
                    }
                ],
                "actions": [
                    {
                        "type": "Action.OpenUrl",
                        "title": "View CVE Details",
                        "url": cve_url
                    }
                ]
            }
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def send_teams_summary(webhook_url: str, items: List[Dict[str, Any]], repo: str) -> None:
    """Send a summary Adaptive Card to Teams with counts and top findings."""
    total = len(items)
    critical_count = sum(1 for i in items if bool(i.get("is_critical")))
    kev_count = sum(1 for i in items if bool(i.get("active_threat")))
    patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))
    
    # Get top 5 critical items
    critical_items = [i for i in items if bool(i.get("is_critical"))]
    critical_items.sort(key=lambda x: float(x.get("probability_score") or 0), reverse=True)
    top_5 = critical_items[:5]
    
    top_list = ""
    for i in top_5:
        cve = i.get("cve_id", "")
        epss = i.get("probability_score")
        try:
            epss_str = f"{float(epss):.1%}" if epss else "?"
        except Exception:
            epss_str = "?"
        top_list += f"- [{cve}](https://www.cve.org/CVERecord?id={cve}) (EPSS: {epss_str})\n"
    
    if not top_list:
        top_list = "No critical findings."
    
    color = "attention" if critical_count > 0 else "good"
    
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": "📊 VulnRadar Daily Summary",
                        "weight": "Bolder",
                        "size": "Large"
                    },
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {
                                "type": "Column",
                                "width": "stretch",
                                "items": [
                                    {"type": "TextBlock", "text": "Total CVEs", "weight": "Bolder"},
                                    {"type": "TextBlock", "text": str(total), "size": "ExtraLarge", "color": color}
                                ]
                            },
                            {
                                "type": "Column",
                                "width": "stretch",
                                "items": [
                                    {"type": "TextBlock", "text": "🚨 Critical", "weight": "Bolder"},
                                    {"type": "TextBlock", "text": str(critical_count), "size": "ExtraLarge", "color": "attention"}
                                ]
                            },
                            {
                                "type": "Column",
                                "width": "stretch",
                                "items": [
                                    {"type": "TextBlock", "text": "⚠️ KEV", "weight": "Bolder"},
                                    {"type": "TextBlock", "text": str(kev_count), "size": "ExtraLarge", "color": "warning"}
                                ]
                            },
                            {
                                "type": "Column",
                                "width": "stretch",
                                "items": [
                                    {"type": "TextBlock", "text": "🔥 PatchThis", "weight": "Bolder"},
                                    {"type": "TextBlock", "text": str(patch_count), "size": "ExtraLarge"}
                                ]
                            }
                        ]
                    },
                    {
                        "type": "TextBlock",
                        "text": "**Top Critical Findings:**",
                        "weight": "Bolder",
                        "spacing": "Medium"
                    },
                    {
                        "type": "TextBlock",
                        "text": top_list,
                        "wrap": True
                    },
                    {
                        "type": "TextBlock",
                        "text": f"Repo: {repo}",
                        "size": "Small",
                        "isSubtle": True,
                        "spacing": "Medium"
                    }
                ]
            }
        }]
    }
    
    r = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()


def main() -> int:
    p = argparse.ArgumentParser(description="VulnRadar notifications (GitHub Issues + Discord)")
    p.add_argument("--in", dest="inp", default="data/radar_data.json", help="Path to radar_data.json")
    p.add_argument("--max", dest="max_items", type=int, default=25, help="Max issues to create per run")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print would-notify CVEs without creating issues",
    )
    # Discord options
    p.add_argument(
        "--discord-webhook",
        dest="discord_webhook",
        default=os.environ.get("DISCORD_WEBHOOK_URL"),
        help="Discord webhook URL (or set DISCORD_WEBHOOK_URL env var)",
    )
    p.add_argument(
        "--discord-summary-only",
        action="store_true",
        help="Only send a summary to Discord, not individual alerts",
    )
    p.add_argument(
        "--discord-max",
        dest="discord_max",
        type=int,
        default=10,
        help="Max individual Discord alerts per run (default: 10)",
    )
    # Slack options
    p.add_argument(
        "--slack-webhook",
        dest="slack_webhook",
        default=os.environ.get("SLACK_WEBHOOK_URL"),
        help="Slack webhook URL (or set SLACK_WEBHOOK_URL env var)",
    )
    p.add_argument(
        "--slack-summary-only",
        action="store_true",
        help="Only send a summary to Slack, not individual alerts",
    )
    p.add_argument(
        "--slack-max",
        dest="slack_max",
        type=int,
        default=10,
        help="Max individual Slack alerts per run (default: 10)",
    )
    # Microsoft Teams options
    p.add_argument(
        "--teams-webhook",
        dest="teams_webhook",
        default=os.environ.get("TEAMS_WEBHOOK_URL"),
        help="Microsoft Teams webhook URL (or set TEAMS_WEBHOOK_URL env var)",
    )
    p.add_argument(
        "--teams-summary-only",
        action="store_true",
        help="Only send a summary to Teams, not individual alerts",
    )
    p.add_argument(
        "--teams-max",
        dest="teams_max",
        type=int,
        default=10,
        help="Max individual Teams alerts per run (default: 10)",
    )
    args = p.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise SystemExit("GITHUB_REPOSITORY is required")
    if not token:
        raise SystemExit("GITHUB_TOKEN (or GH_TOKEN) is required")

    items = _load_items(Path(args.inp))

    # Notify policy: notify on is_critical (PatchThis + Watchlist)
    candidates: List[Dict[str, Any]] = []
    for it in items:
        if bool(it.get("is_critical")):
            candidates.append(it)

    # Sort to notify highest first
    def key(it: Dict[str, Any]) -> tuple:
        try:
            epss = float(it.get("probability_score") or 0.0)
        except Exception:
            epss = 0.0
        try:
            cvss = float(it.get("cvss_score") or 0.0)
        except Exception:
            cvss = 0.0
        return (
            1 if bool(it.get("is_critical")) else 0,
            1 if bool(it.get("active_threat")) else 0,
            epss,
            cvss,
        )

    candidates = sorted(candidates, key=key, reverse=True)

    session = _session(token)
    existing = _existing_notified_cves(session, repo)
    created = 0
    
    # Check if issues are enabled on the repo
    issues_enabled = True
    try:
        r = session.get(f"https://api.github.com/repos/{repo}", timeout=DEFAULT_TIMEOUT)
        if r.ok:
            repo_data = r.json()
            issues_enabled = repo_data.get("has_issues", True)
    except Exception:
        pass  # Assume issues are enabled if we can't check
    
    if not issues_enabled:
        print(f"GitHub Issues are disabled on {repo}, skipping issue creation.")
    else:
        for it in candidates:
            if created >= args.max_items:
                break
            cve_id = str(it.get("cve_id") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue

            if cve_id in existing:
                continue

            priority = "CRITICAL" if bool(it.get("is_critical")) else "ALERT"
            title = f"[VulnRadar] {priority}: {cve_id}"
            body = _issue_body(it)
            labels = ["vulnradar", "alert"]
            if bool(it.get("is_critical")):
                labels.append("critical")
            if bool(it.get("active_threat")):
                labels.append("kev")

            if args.dry_run:
                print(f"DRY RUN: would create issue: {title}")
                created += 1
                continue

            try:
                _create_issue(session, repo, title=title, body=body, labels=labels)
                print(f"Created issue for {cve_id}")
                existing.add(cve_id)
                created += 1
            except Exception as e:
                print(f"Failed to create issue for {cve_id}: {e}")
                break

        print(f"Done. Created {created} GitHub issues.")
    
    # Discord notifications
    if args.discord_webhook:
        print(f"Sending Discord notifications...")
        try:
            # Always send summary
            send_discord_summary(args.discord_webhook, items, repo)
            print("Sent Discord summary.")
            
            # Send individual alerts unless summary-only
            if not args.discord_summary_only:
                discord_sent = 0
                for it in candidates[:args.discord_max]:
                    cve_id = str(it.get("cve_id") or "").strip().upper()
                    if args.dry_run:
                        print(f"DRY RUN: would send Discord alert for {cve_id}")
                    else:
                        # Rate limit: Discord allows ~30 requests/minute per webhook
                        time.sleep(0.5)
                        send_discord_alert(args.discord_webhook, it)
                        print(f"Sent Discord alert for {cve_id}")
                    discord_sent += 1
                print(f"Sent {discord_sent} Discord alerts.")
        except Exception as e:
            print(f"Discord notification failed: {e}")
    
    # Slack notifications
    if args.slack_webhook:
        print(f"Sending Slack notifications...")
        try:
            # Always send summary
            send_slack_summary(args.slack_webhook, items, repo)
            print("Sent Slack summary.")
            
            # Send individual alerts unless summary-only
            if not args.slack_summary_only:
                slack_sent = 0
                for it in candidates[:args.slack_max]:
                    cve_id = str(it.get("cve_id") or "").strip().upper()
                    if args.dry_run:
                        print(f"DRY RUN: would send Slack alert for {cve_id}")
                    else:
                        # Rate limit: Slack allows ~1 request/second
                        time.sleep(1.0)
                        send_slack_alert(args.slack_webhook, it)
                        print(f"Sent Slack alert for {cve_id}")
                    slack_sent += 1
                print(f"Sent {slack_sent} Slack alerts.")
        except Exception as e:
            print(f"Slack notification failed: {e}")
    
    # Microsoft Teams notifications
    if args.teams_webhook:
        print(f"Sending Teams notifications...")
        try:
            # Always send summary
            send_teams_summary(args.teams_webhook, items, repo)
            print("Sent Teams summary.")
            
            # Send individual alerts unless summary-only
            if not args.teams_summary_only:
                teams_sent = 0
                for it in candidates[:args.teams_max]:
                    cve_id = str(it.get("cve_id") or "").strip().upper()
                    if args.dry_run:
                        print(f"DRY RUN: would send Teams alert for {cve_id}")
                    else:
                        # Rate limit: Teams allows ~4 requests/second
                        time.sleep(0.5)
                        send_teams_alert(args.teams_webhook, it)
                        print(f"Sent Teams alert for {cve_id}")
                    teams_sent += 1
                print(f"Sent {teams_sent} Teams alerts.")
        except Exception as e:
            print(f"Teams notification failed: {e}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
