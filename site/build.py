"""Build the ProvGuard site from site/page.html and the committed results.

    python site/build.py

Writes:
  site/public/index.html   full document, deploy this folder (e.g. Vercel)
  site/build/preview.html  page body only, for an Artifact preview

Every number on the page comes from results/, so the site cannot drift from
the evaluation.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
SUITES = ["banking", "slack", "travel", "workspace"]


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


def live_summary() -> list[dict]:
    rows = []
    for path in sorted((ROOT / "results").glob("*/*/*-r*.json")):
        if path.parent.parent.name == "oracle":
            continue
        r = json.loads(path.read_text(encoding="utf-8"))

        def rate(d: dict) -> float | None:
            return sum(d.values()) / len(d) if d else None

        rows.append({
            "suite": r["suite"], "defense": r["defense"], "model": r["model"],
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
    data = {"oracle": summary, "live": live_summary()}

    body = (SITE / "page.html").read_text(encoding="utf-8")
    body = body.replace("/*DATA*/null", json.dumps(data))

    (SITE / "build").mkdir(exist_ok=True)
    (SITE / "build" / "preview.html").write_text(body, encoding="utf-8")

    (SITE / "public").mkdir(exist_ok=True)
    full = (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
        '<meta name="description" content="ProvGuard: provenance-based tool-call guard for LLM agents, '
        'evaluated on AgentDojo.">\n'
        "<style>*,*::before,*::after{box-sizing:border-box}body{margin:0}[hidden]{display:none!important}</style>\n"
        "</head>\n<body>\n" + body + "\n</body>\n</html>\n"
    )
    (SITE / "public" / "index.html").write_text(full, encoding="utf-8")
    print(json.dumps(data["oracle"], indent=1))
    print(f"live runs: {len(data['live'])}")


if __name__ == "__main__":
    main()
