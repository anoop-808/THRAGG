import json
from thragg import THRAGGOrchestrator
orch = THRAGGOrchestrator()
report = orch.run("/home/karna/Projects/THRAGG/sample_evidence")
for finding in orch._correlation.relationship_repository.knowledge_base.get_findings():
    print(finding.evidence)
