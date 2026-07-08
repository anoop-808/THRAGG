import json

with open("thragg_results/thragg_report_20260708_095617.json") as f:
    report = json.load(f)

for rel in report["artifacts"]["relationships"]:
    print(f"{rel['source']} -> {rel['type']} -> {rel['target']}")
