import json
from thragg import THRAGGOrchestrator
orch = THRAGGOrchestrator()
report = orch.run("sample_evidence")
for finding in orch._correlation.relationship_repository.knowledge_base.get_findings():
    if "userPrincipalName" in finding.evidence or "mfa_registered" in finding.evidence:
        print(finding.evidence)
        break
