from thragg import THRAGGOrchestrator
orch = THRAGGOrchestrator()
orch.run("sample_evidence")
relationships = orch._correlation.relationship_repository.list()
count = 0
for r in relationships:
    if r.relationship_type.name == "RELATED_TO":
        print(f"{r.source_entity_type.name} -> {r.relationship_type.name} -> {r.target_entity_type.name}")
        count += 1
print(f"Total RELATED_TO: {count}")
