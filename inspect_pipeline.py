from thragg import THRAGGOrchestrator
import pprint
orch = THRAGGOrchestrator()
orch.run("sample_evidence")
resolved = orch._correlation.entity_registry.repository.list()
relationships = orch._correlation.relationship_repository.list()
for r in relationships:
    print(f"{r.source_entity_type.name} -> {r.relationship_type.name} -> {r.target_entity_type.name}")
