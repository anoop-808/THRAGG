# Root Cause Analysis: THRAGG Dashboard Empty Metrics

## 1. Execution Trace

The pipeline execution begins with `python thragg.py sample_evidence`:

1.  **Discovery & Dispatch**: `THRAGGOrchestrator` successfully discovers 5 evidence files (e.g., `auth.log`, `scan.xml`, `users.json`) and correctly dispatches them to their respective modules (logs, nmap, cloud, identity, zap).
2.  **Module Execution**: The modules successfully execute, parse the evidence, and produce a large number of valid findings (e.g., the logs module produces 167 findings).
3.  **Result Aggregation**: Modules return `ModuleResult` objects. The `ResultMerger` correctly combines them into a `UnifiedReport`. At this stage, the findings are safely stored in the `details` dictionary, grouped by category (e.g., `details["authentication"] = [...]`, `details["privilege"] = [...]`).
4.  **Intelligence Pipeline**: `_run_intelligence` transforms `ModuleResult` instances into contracts and passes them to the Foundation layer (`CorrelationEngine.run_contracts`).
5.  **Failure Point**: When `CorrelationEngine` attempts to parse findings from these contracts, it looks for them under the hardcoded key `"findings"` (`contract["details"].get("findings", [])`).
6.  **Domino Effect**: Because most modules (like `logs`, `identity`, `cloud`, `zap`) group their findings under dynamic category keys rather than a single `"findings"` key, the extraction yields `0` findings for them. Nmap is the only module that happens to output to `details["findings"]`, which is why exactly 23 findings are tracked in the snapshot.
7.  **Downstream Impact**: With effectively `0` findings entering the Foundation layer, no entities are extracted, no relationships are built, the `RelationshipGraph` remains empty, and the `AttackChainEngine` generates `0` attack chains.
8.  **Dashboard Rendering**: The `RiskEngine` calculates `0` risk based on `0` attack chains. The `ExecutiveAssessmentBuilder` faithfully records a `HEALTHY` state with no risks. The generated `dashboard.html` receives a correctly populated JSON object, but the object legitimately contains zero metrics because the underlying data structures were starved at the correlation ingestion phase.

## 2. Answers to Specific Questions

*   **Do the modules produce findings?**
    Yes. The logs alone show that 167 findings are produced. 
*   **Which layer first becomes empty?**
    The **Foundation / Correlation layer** is the first to become empty. Specifically, the data is dropped when `CorrelationEngine._findings_from_contracts` attempts to extract findings from the module contracts.
*   **Is the dashboard reading the wrong object?**
    No. The dashboard is reading the correct objects (the `FrameworkSnapshot` and `ExecutiveAssessment`), which were correctly populated by the pipeline.
*   **Is the generated dashboard.html missing populated JSON?**
    No. The JSON is properly populated and injected into the HTML. The JSON merely reflects the empty state of the underlying intelligence graph.
*   **What is the smallest fix that preserves the architecture?**
    The smallest fix is to iterate through all values within the `details` dictionary to extract findings, rather than hardcoding the extraction to look for a specific `"findings"` key.

## 3. The Exact File, Function, and Transformation

*   **File:** `core/correlation/correlation_engine.py`
*   **Function:** `_findings_from_contracts(contracts)`
*   **Transformation / Root Cause:**

```python
# INCORRECT TRANSFORMATION:
for raw in contract["details"].get("findings", []):
    finding = CorrelationEngine._coerce_finding(raw, source_module)
```
This hardcoded `.get("findings", [])` bypasses the actual findings, which are grouped under categories (e.g., `"authentication"`, `"privilege"`).

*   **Secondary File:** `thragg.py`
*   **Function:** `_finding_count(contracts)`
*   **Transformation:**
```python
return sum(len(contract["details"].get("findings", ())) for contract in contracts)
```

## 4. Smallest Fix Recommendation

Update `_findings_from_contracts` in `core/correlation/correlation_engine.py` to extract findings from all category lists:

```python
for category_list in contract["details"].values():
    if isinstance(category_list, list):
        for raw in category_list:
            finding = CorrelationEngine._coerce_finding(raw, source_module)
            if finding is not None:
                findings.append(finding)
```

And similarly update `_finding_count` in `thragg.py`:

```python
def _finding_count(contracts: tuple[dict[str, Any], ...]) -> int:
    return sum(
        len(lst) for contract in contracts 
        for lst in contract["details"].values() if isinstance(lst, list)
    )
```

This respects the architecture's rule that "Findings live inside details" and gracefully supports both Nmap's approach and the category-based approach of the other modules.
