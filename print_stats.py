import json
import os
import glob

reports = glob.glob("thragg_results/thragg_report_*.json")
latest = max(reports, key=os.path.getctime)

with open(latest) as f:
    report = json.load(f)

intel = report["details"]["intelligence"]
snapshot = intel["framework_snapshot"]

print(f"Correlations: {len(snapshot.get('correlations', []))}")
print(f"Attack Chains: {len(snapshot.get('attack_chains', []))}")
print(f"Risk Assessments: {len(snapshot.get('risk_assessments', []))}")
