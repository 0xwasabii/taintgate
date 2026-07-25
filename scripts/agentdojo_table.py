"""Aggregate results/agentdojo/*.json into a markdown table (pooled over suites)."""
import json
from pathlib import Path

ORDER = ["none", "tool_filter", "spotlighting_with_delimiting", "repeat_user_prompt", "taintgate", "taintgate (executed only)", "taintgate-flow", "taintgate-flow (executed only)"]
rows = {}
files = [(f, "") for f in sorted(Path("results/agentdojo").glob("*-*.json"))]
files += [(f, " (executed only)") for f in sorted(Path("results/agentdojo-executed").glob("*-*.json"))]
for f, tag in files:
    r = json.loads(f.read_text())
    key = r["defense"] + (tag if r["defense"].startswith("taintgate") else "")
    if tag and not r["defense"].startswith("taintgate"):
        continue
    d = rows.setdefault(key, {"suites": {}, "ca": 0, "cn": 0, "aa": 0, "an": 0, "ua": 0})
    ok_clean = round(r["utility_no_attack"] * r["n_clean"] / 100)
    d["cn"] += r["n_clean"]; d["ca"] += ok_clean
    d["an"] += r["n_attack"]
    d["aa"] += sum(p["attack_success"] for p in r["pairs"])
    d["ua"] += sum(p["utility"] for p in r["pairs"])
    d["suites"][r["suite"]] = r["attack_success"]
pct = lambda a, n: f"{100 * a / n:.1f}" if n else "n/a"
print("| Defense | Attack success % | Utility, no attack % | Utility under attack % | ASR banking | ASR slack | n clean / n attack |")
print("|---|---|---|---|---|---|---|")
for k in ORDER:
    if k in rows:
        d = rows[k]
        print(f"| {k} | {pct(d['aa'], d['an'])} | {pct(d['ca'], d['cn'])} | {pct(d['ua'], d['an'])} | "
              f"{d['suites'].get('banking', 'n/a')} | {d['suites'].get('slack', 'n/a')} | {d['cn']} / {d['an']} |")
