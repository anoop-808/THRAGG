from thragg import THRAGGOrchestrator
orch = THRAGGOrchestrator()
orch._evidence.ingest("sample_evidence")
orch._evidence.process()
orch._foundation.process(orch._evidence.findings)
orch._correlation.process(orch._evidence.findings, orch._foundation.entity_repository, orch._foundation.relationship_repository)

rels = orch._correlation.relationship_repository.list()
from collections import Counter
rel_types = Counter([r.relationship_type.name for r in rels])
print("Rels:", rel_types)

correlations = orch._correlation.correlation_engine._correlate(orch._evidence.findings)

# Check attack pattern matcher manually
from thragg.core.attack_chain.attack_pattern_matcher import AttackPatternMatcher
matcher = AttackPatternMatcher()
from thragg.core.attack_chain.relationship_traverser import RelationshipTraverser
traverser = RelationshipTraverser(orch._foundation.relationship_graph, orch._foundation.entity_repository._store, matcher._templates, max_path_length=4)
paths = list(traverser.find_attack_paths())
print("Paths found:", len(paths))
if paths:
    print("Path 0 entities:", [e for e in paths[0].entity_ids])
    candidate = matcher._candidate_from_path(paths[0], correlations)
    print("Candidate:", candidate)
    if candidate:
        print("Match:", matcher.match_candidate(candidate, correlations))

