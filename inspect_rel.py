from thragg import THRAGGOrchestrator
orch = THRAGGOrchestrator()
orch.run("sample_evidence")
inferencer = orch._correlation.inferencer
registry = orch._correlation.entity_registry

for rule in inferencer.rules:
    print(f"Rule: {rule.rule_id} -> Source: {rule.source_entity_type}, Target: {rule.target_entity_type}, Req: {rule.required_evidence_keys}")

