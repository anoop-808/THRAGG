from thragg import THRAGGOrchestrator
import json

orchestrator = THRAGGOrchestrator()
report = orchestrator.run("static_findings")
print("Total Attack Chains:", len(report.get("details", {}).get("attack_chains", [])))
