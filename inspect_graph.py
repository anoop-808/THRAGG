from thragg import THRAGGOrchestrator, _contract_from_result

orch = THRAGGOrchestrator()
results = orch._dispatch_and_run(orch._discover("sample_evidence"))
contracts = tuple(_contract_from_result(r) for r in results)

orch._correlation.run_contracts(contracts)

kb = orch._correlation.relationship_repository.knowledge_base
entities = list(orch._correlation.entity_registry.repository.list())
relationships = list(kb.get_relationships())

print(f"Entities: {len(entities)}")
print(f"Relationships: {len(relationships)}")

for e in entities:
    if e.entity_type.name in ('HOST', 'USER', 'SERVICE', 'CLOUD_RESOURCE', 'STORAGE'):
        print(f"Entity: {e.entity_type.name} {e.id}")
        print(f"  Attrs: {e.attributes}")

for r in relationships:
    if r.relationship_type.name in ('EXPOSES', 'AUTHENTICATED_TO', 'OWNS'):
        print(f"Rel: {r.source_entity_type.name} --{r.relationship_type.name}--> {r.target_entity_type.name}")
        print(f"  Evidence: {r.supporting_evidence}")
