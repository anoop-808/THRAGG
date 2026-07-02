# THRAGG Development Roadmap
**Version:** 1.0  
**Status:** Active  
**Document Type:** Framework Development Roadmap

---

# Purpose

This roadmap defines the architectural evolution of THRAGG.

Unlike the Architecture Specification, this document is expected to evolve throughout the lifetime of the framework.

Every milestone represents a stable architectural increment.

No milestone is considered complete until:

- Architecture has been approved.
- Architecture has been frozen.
- Implementation is production-ready.
- Tests pass successfully.
- Documentation has been updated.
- Engineering review is complete.
- Backward compatibility has been preserved.

---

# Framework Progress

```
=========================================================
                 THRAGG FRAMEWORK PROGRESS
=========================================================

Layer 1 — Analysis
██████████████████████████████████ 100%

Layer 2 — Knowledge
█████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 20%

Layer 3 — Correlation
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0%

Layer 4 — Intelligence
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0%

Layer 5 — Presentation
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0%

Overall Framework Completion

██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 12%
```

---

# Architectural Dependency Graph

```
Evidence
      │
      ▼
Findings
      │
      ▼
Entities
      │
      ▼
Entity Resolution
      │
      ▼
Context Enrichment
      │
      ▼
Relationship Graph
      │
      ▼
Correlation Rules
      │
      ▼
Attack Chains
      │
      ▼
Risk Scoring
      │
      ▼
Executive Intelligence
      │
      ▼
Report Builder
```

Each stage depends on the successful completion of the previous stage.

No stage may bypass another.

---

# Layer 1 — Analysis Layer

---

## Milestone 1 — Findings Standardization

### Goal

Provide a unified language for all security modules.

### Input

Normalized evidence.

### Output

Standardized Findings.

### Deliverables

- Shared Finding Model
- Finding Builder
- Finding Validator
- Standardized Finding Contract
- Deterministic Finding IDs
- EntityType support

### Acceptance Criteria

- Every module produces Findings.
- Shared schema implemented.
- Shared validation implemented.
- Backward compatibility maintained.

### Status

✅ Completed

---

# Layer 2 — Knowledge Layer

---

## Milestone 2 — Entity Extraction

### Goal

Extract reusable security entities from Findings.

### Input

Findings.

### Output

Entities.

### Deliverables

- Entity Model
- Entity Extractor
- Entity Validator
- Entity Contract

### Acceptance Criteria

- Shared Entity model exists.
- Every module produces entities.
- Shared extractor used.
- Multiple entities may originate from one finding.

### Depends On

Milestone 1

### Status

🚧 In Progress

---

## Milestone 3 — Entity Resolution

### Goal

Merge multiple entity representations into one canonical entity.

### Input

Entities.

### Output

Resolved Entities.

### Deliverables

- Resolution Engine
- Alias Resolution
- Canonical Entity IDs
- Duplicate Detection

### Acceptance Criteria

- Equivalent entities merge correctly.
- Original entities remain traceable.
- Deterministic resolution.

### Depends On

Milestone 2

### Status

⬜ Planned

---

## Milestone 4 — Context Enrichment

### Goal

Attach business and environmental context to resolved entities.

### Input

Resolved Entities.

### Output

Enriched Entities.

### Deliverables

- Entity metadata
- Criticality
- Ownership
- Environment
- Cloud metadata

### Acceptance Criteria

- Context remains modular.
- No modification of original entities.
- Context layer reusable.

### Depends On

Milestone 3

### Status

⬜ Planned

---

# Layer 3 — Correlation Layer

---

## Milestone 5 — Relationship Graph

### Goal

Represent relationships between entities.

### Input

Enriched Entities.

### Output

Relationship Graph.

### Deliverables

- Graph Nodes
- Graph Edges
- Relationship Types
- Graph Builder

### Acceptance Criteria

- Deterministic graph generation.
- Shared graph model.
- No duplicate relationships.

### Depends On

Milestone 4

### Status

⬜ Planned

---

## Milestone 6 — YAML Correlation Engine

### Goal

Detect attack patterns using declarative correlation rules.

### Input

Relationship Graph.

### Output

Correlated Security Events.

### Deliverables

- YAML Rule Loader
- Rule Validator
- Rule Engine
- Pattern Matcher

### Acceptance Criteria

- Rules remain data-driven.
- Framework requires no code changes to add new rules.
- Correlation operates only on graph objects.

### Depends On

Milestone 5

### Status

⬜ Planned

---

## Milestone 7 — Attack Chain Builder

### Goal

Construct realistic attack paths.

### Input

Correlated Events.

### Output

Attack Chains.

### Deliverables

- Attack Chain Model
- Timeline Builder
- Kill Chain Mapping
- MITRE ATT&CK Mapping

### Acceptance Criteria

- Chains remain deterministic.
- Multiple attack paths supported.
- Complete evidence traceability.

### Depends On

Milestone 6

### Status

⬜ Planned

---

# Layer 4 — Intelligence Layer

---

## Milestone 8 — Unified Risk Scoring

### Goal

Calculate risk across complete attack chains.

### Input

Attack Chains.

### Output

Risk Scores.

### Deliverables

- Risk Engine
- Severity Weighting
- Confidence Weighting
- Entity Criticality
- Chain Complexity

### Acceptance Criteria

- Repeatable scoring.
- Transparent calculations.
- Explainable output.

### Depends On

Milestone 7

### Status

⬜ Planned

---

## Milestone 9 — Executive Intelligence

### Goal

Transform technical data into analyst-ready intelligence.

### Input

Risk Scores.

### Output

Executive Intelligence.

### Deliverables

- Executive Summary
- Threat Narrative
- Timeline
- MITRE Mapping
- Recommendations
- Security Posture Summary

### Acceptance Criteria

- Technical and executive outputs available.
- Evidence traceability maintained.
- Human-readable narrative generated.

### Depends On

Milestone 8

### Status

⬜ Planned

---

# Layer 5 — Presentation Layer

---

## Milestone 10 — Report Builder

### Goal

Generate standardized reports.

### Input

Executive Intelligence.

### Output

Framework Reports.

### Deliverables

- JSON Reports
- Markdown Reports
- HTML Reports
- Machine-readable Exports
- Executive Reports

### Acceptance Criteria

- Multiple report formats.
- Consistent structure.
- Extensible exporters.

### Depends On

Milestone 9

### Status

⬜ Planned

---

# Engineering Gates

Every milestone must satisfy all engineering gates before being marked complete.

```
Architecture Approved
        │
        ▼
Architecture Frozen
        │
        ▼
Implementation Complete
        │
        ▼
Testing Complete
        │
        ▼
Documentation Updated
        │
        ▼
Engineering Review
        │
        ▼
Backward Compatibility Verified
        │
        ▼
Milestone Approved
```

---

# Future Enhancements

The following capabilities are considered future extensions rather than architectural milestones.

- Plugin SDK
- Web Dashboard
- Enterprise Authentication
- Multi-Tenant Support
- Visualization Engine
- Cloud Deployment
- Distributed Processing
- Additional Evidence Sources
- Community Rule Packs

Future enhancements must extend the framework without modifying completed architecture.

---

# Roadmap Maintenance Policy

This document is a living engineering document.

Whenever a milestone changes:

- Update its status.
- Update framework progress.
- Update dependency graph if required.
- Update acceptance criteria if architecture changes.
- Create an Architecture Decision Record (ADR) when necessary.

The roadmap must always reflect the current engineering state of THRAGG.

---

# Closing Statement

THRAGG evolves through stable architectural milestones rather than isolated feature development.

Every milestone strengthens the framework while preserving its architecture, ensuring that future capabilities build upon a consistent, extensible, and production-oriented foundation.
