from thragg import THRAGGOrchestrator
orch = THRAGGOrchestrator()
orch.run("sample_evidence")
resolved = orch._correlation.entity_registry.repository.list()
for e in resolved:
    if e.entity_type.name == "HOST":
        print(f"HOST id={e.id} primary={e.primary_identifier}")
