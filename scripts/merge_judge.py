import json
from taintgate.evalkit import report
for mode in ("static", "adaptive"):
    old = [r for r in json.load(open(f"results-{mode}.json")) if r["defense"] != "judge"]
    recs = old + json.load(open(f"judge-{mode}.json"))
    order = ["none", "allowlist", "judge", "taintgate", "taintgate-flow"]
    recs.sort(key=lambda r: order.index(r["defense"]))
    json.dump(recs, open(f"results-{mode}.json", "w"), indent=1)
    md = report.to_markdown(report.summarize(recs))
    open(f"results-{mode}.md", "w").write(md)
    print(mode); print(md.split("\n\n")[0])
