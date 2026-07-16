from thragg import THRAGGOrchestrator
import logging

logging.basicConfig(level=logging.DEBUG)

orchestrator = THRAGGOrchestrator()
report = orchestrator.run("static_findings")
print("Total Attack Chains:", len(report.get("details", {}).get("attack_chains", [])))
print("Total Risk Assessments:", len(report.get("details", {}).get("risk_assessments", [])))
