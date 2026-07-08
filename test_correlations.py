from thragg import THRAGGOrchestrator
orch = THRAGGOrchestrator()
orch.run("sample_evidence")
correlations = orch._correlation.repository.list()
print(f"Total Correlations in repository: {len(correlations)}")
for c in correlations:
    print(c.rule_id, len(c.matched_entities))
