"""Build the ProvGuard site from site/page.html and the committed results.

    python site/build.py

Writes:
  site/public/index.html   full document, deploy this folder (e.g. Vercel)
  site/build/preview.html  page body only, for an Artifact preview

Every number on the page comes from results/, so the site cannot drift from
the evaluation.
"""

from __future__ import annotations

import html
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
SUITES = ["banking", "slack", "travel", "workspace"]
URL = "https://provguard.vercel.app/"
TITLE = "ProvGuard: untrusted data must not steer what your AI agent does"
DESCRIPTION = (
    "Open-source tool-call guard for LLM agents. Instead of detecting malicious text, it checks where every "
    "sensitive argument came from. Stops 144/144 AgentDojo banking attacks; works in front of any MCP server."
)

sys.path.insert(0, str(ROOT))
from bench.stats import clopper_pearson  # noqa: E402


def oracle_summary(folder: Path) -> dict:
    out = {}
    for suite in SUITES:
        data = json.loads((folder / f"{suite}.json").read_text(encoding="utf-8"))
        utility = Counter(v["action"] for v in data["utility"].values())
        pairs = [v for v in data["security"].values() if v["stopped"] is not None]
        out[suite] = {
            "user_tasks": len(data["utility"]),
            "blocked": utility["block"] + utility["confirm"],
            "pairs": len(pairs),
            "stopped": sum(v["stopped"] for v in pairs),
            "no_reference": len(data["security"]) - len(pairs),
        }
    return out


def v1_stopped(folder: Path) -> dict:
    # v1 counted pairs without reference calls as not stopped; recount them out
    # so v1 and v2 share a denominator.
    out = {}
    for suite in SUITES:
        v1 = json.loads((folder / f"{suite}.json").read_text(encoding="utf-8"))["security"]
        v2 = json.loads((ROOT / "results/oracle" / f"{suite}.json").read_text(encoding="utf-8"))["security"]
        out[suite] = sum(v1[k]["stopped"] for k, v in v2.items() if v["stopped"] is not None)
    return out


def v3_summary(folder: Path) -> dict:
    """Goal-based numbers for the (non-blind) v3 policies, if they have been run."""
    out = {}
    for suite in SUITES:
        path = folder / f"{suite}.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        pairs = [v for v in data["security"].values() if v.get("verifiable")]
        if not pairs:
            continue
        judged = [v for v in data["utility"].values() if v.get("solved_with_user") is not None]

        def ci(k: int, n: int) -> str:
            lo, hi = clopper_pearson(k, n)
            return f"95% CI {lo:.0%}-{hi:.0%}"

        no_human = sum(not v["goal_no_human"] for v in pairs)
        any_human = sum(not v["goal_any_human"] for v in pairs)
        confirms = sum(v.get("confirmations", 0) for v in data["utility"].values())
        out[suite] = {
            "verifiable": len(pairs), "no_human": no_human, "any_human": any_human,
            "no_human_ci": ci(no_human, len(pairs)), "any_human_ci": ci(any_human, len(pairs)),
            "solved": sum(v["solved_with_user"] for v in judged), "judged": len(judged),
            "confirm_rate": f"{confirms / max(len(data['utility']), 1):.2f}",
        }
    return out


def ledger_rows(oracle: dict) -> str:
    """Server-rendered results table, so the numbers are there without JavaScript."""
    rows = []
    for suite, r in oracle.items():
        pct, v1 = r["stopped"] / r["pairs"], r["stopped_v1"] / r["pairs"]
        note = (f'<div class="small">{r["no_reference"]} pairs without a reference solution excluded</div>'
                if r["no_reference"] else "")
        rows.append(
            f'<tr><td class="suite">{html.escape(suite)}</td>'
            f'<td><div class="cellnum"><strong>{pct:.0%}</strong><div class="bar" role="img" '
            f'aria-label="{pct:.0%} stopped, v1 {v1:.0%}"><span style="width:{pct * 100:.1f}%"></span>'
            f'<i style="left:calc({v1 * 100:.1f}% - 1px)" title="v1: {v1:.0%}"></i></div></div></td>'
            f'<td><span>{r["stopped"]} / {r["pairs"]}</span>{note}</td>'
            f'<td>{r["blocked"]} / {r["user_tasks"]}</td></tr>'
        )
    return "".join(rows)


def v3_table(v3: dict) -> str:
    """Server-rendered v3 table (same markup the page script builds)."""
    if not v3:
        return ""
    heads = ["Suite (v3 policy, not blind)", "Goal prevented, nobody approves",
             "Goal prevented, everything approved", "Tasks solved with an approving user", "Confirmations per task"]
    rows = "".join(
        f'<tr><td class="suite">{html.escape(suite)}</td>'
        f'<td>{r["no_human"]} / {r["verifiable"]} ({r["no_human_ci"]})</td>'
        f'<td>{r["any_human"]} / {r["verifiable"]} ({r["any_human_ci"]})</td>'
        f'<td>{r["solved"]} / {r["judged"]}</td><td>{r["confirm_rate"]}</td></tr>'
        for suite, r in v3.items()
    )
    head = "".join(f"<th>{h}</th>" for h in heads)
    return (f'<div class="ledger-wrap" style="margin-top:1.5rem"><table class="ledger">'
            f"<thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div>")


def head_tags() -> str:
    ld = {
        "@context": "https://schema.org", "@type": "SoftwareSourceCode", "name": "ProvGuard",
        "description": DESCRIPTION, "url": URL, "codeRepository": "https://github.com/ziko-asm/provguard",
        "programmingLanguage": "Python", "license": "https://opensource.org/licenses/MIT",
        "author": {"@type": "Person", "name": "Ziya Azizov", "url": "https://ayfar.dev"},
    }
    d, t = html.escape(DESCRIPTION, quote=True), html.escape(TITLE, quote=True)
    return (
        f'<meta name="description" content="{d}">\n'
        f'<link rel="canonical" href="{URL}">\n'
        f'<meta property="og:type" content="website">\n<meta property="og:url" content="{URL}">\n'
        f'<meta property="og:title" content="{t}">\n<meta property="og:description" content="{d}">\n'
        f'<meta name="twitter:card" content="summary">\n<meta name="twitter:title" content="{t}">\n'
        f'<meta name="twitter:description" content="{d}">\n<meta name="theme-color" content="#0b6a6a">\n'
        '<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 32 32%22%3E'
        '%3Crect width=%2232%22 height=%2232%22 rx=%227%22 fill=%22%230b6a6a%22/%3E%3Cpath d=%22M16 6l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V9z%22 '
        'fill=%22none%22 stroke=%22white%22 stroke-width=%222.4%22 stroke-linejoin=%22round%22/%3E%3C/svg%3E">\n'
        f'<script type="application/ld+json">{json.dumps(ld)}</script>\n'
    )


def live_summary() -> list[dict]:
    rows = []
    for path in sorted((ROOT / "results").glob("*/*/*-r*.json")):
        if path.parent.parent.name.startswith("oracle"):
            continue
        r = json.loads(path.read_text(encoding="utf-8"))

        def rate(d: dict) -> float | None:
            return sum(d.values()) / len(d) if d else None

        rows.append({
            "suite": r["suite"], "model": r["model"],
            "defense": r["defense"] + (" (v3 policy, no human)" if "v3" in (r.get("policies") or "") else ""),
            "utility": rate(r["clean_utility"]), "attacked_utility": rate(r["attacked_utility"]),
            "attack_success": rate(r["attack_success"]),
            "n_clean": len(r["clean_utility"]), "n_attacked": len(r["attack_success"]),
        })
    return rows


def main() -> None:
    summary = oracle_summary(ROOT / "results/oracle")
    v1 = v1_stopped(ROOT / "results/oracle-v1")
    for suite in SUITES:
        summary[suite]["stopped_v1"] = v1[suite]
    data = {"oracle": summary, "live": live_summary(), "v3": v3_summary(ROOT / "results/oracle-v3")}

    body = (SITE / "page.html").read_text(encoding="utf-8")
    body = body.replace("/*DATA*/null", json.dumps(data))
    body = body.replace('<tbody id="ledger"></tbody>', f'<tbody id="ledger">{ledger_rows(summary)}</tbody>')
    body = body.replace('<div id="v3"></div>', f'<div id="v3">{v3_table(data["v3"])}</div>')
    body = body.replace("<title>ProvGuard</title>\n", "")

    (SITE / "build").mkdir(exist_ok=True)
    (SITE / "build" / "preview.html").write_text(body, encoding="utf-8")

    (SITE / "public").mkdir(exist_ok=True)
    full = (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
        f"<title>{html.escape(TITLE)}</title>\n"
        + head_tags() +
        "<style>*,*::before,*::after{box-sizing:border-box}body{margin:0}[hidden]{display:none!important}</style>\n"
        "</head>\n<body>\n" + body + "\n</body>\n</html>\n"
    )
    (SITE / "public" / "index.html").write_text(full, encoding="utf-8")
    print(json.dumps(data["oracle"], indent=1))
    print(f"live runs: {len(data['live'])}, v3 suites: {len(data['v3'])}")


if __name__ == "__main__":
    main()
