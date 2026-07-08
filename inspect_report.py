import json

with open("thragg_results/thragg_report_20260708_095750.json") as f:
    report = json.load(f)

for mod in report["modules"]:
    if mod["metadata"]["module"] == "identity":
        for f in mod["details"].get("users", []):
            print(f"Title: {f['title']}, Asset: {f['asset']}, Entity Type: {f.get('entity_type')}")
