import json

with open("thragg_results/thragg_report_20260708_095018.json") as f:
    r = json.load(f)

# relationships are not in framework_snapshot but in .artifacts.relationships ? Wait!
# The orchestrator generates `resolved` and `relationships` but doesn't put them in framework_snapshot?
# Ah! In thragg.py:
#         dashboard = self._dashboard.generate(
#             ...
#             relationships=relationships,
#             resolved_entities=resolved,
#             ...
#         )
# The dashboard HTML has them. But we can print the relationship attributes directly from python:

from core.foundation.knowledge_base import KnowledgeBase
from thragg import THRAGGOrchestrator
report = THRAGGOrchestrator().run("sample_evidence")
intel = report["details"]["intelligence"]
resolved = report["artifacts"]["dashboard"]["metrics"] # Wait, how to get relationships?
import pprint
snapshot = intel["framework_snapshot"]
print("Correlations:", snapshot.get("correlations", []))

# We can intercept or just look at `thragg_results/...` since maybe we can print from a fresh run.
