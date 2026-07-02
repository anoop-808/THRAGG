# THRAGG Framework Specification
**Version:** 1.0  
**Status:** Active  
**Document Type:** Framework Object Specification

---

# Purpose

This document defines every core object used inside THRAGG.

It acts as the internal language of the framework.

Every architectural layer communicates using these standardized objects.

No component should invent its own object definitions.

The Architecture Specification explains *why* these objects exist.

This document defines *what they are.*

---

# Framework Object Hierarchy

```
Evidence
      │
      ▼
Finding
      │
      ▼
Entity
      │
      ▼
Resolved Entity
      │
      ▼
Relationship
      │
      ▼
Correlation
      │
      ▼
Attack Chain
      │
      ▼
Risk Assessment
      │
      ▼
Executive Report
```

Each object increases the level of abstraction.

Earlier objects remain immutable.

Later objects enrich previous objects without modifying them.

---

# 1. Evidence

## Purpose

Evidence represents raw security data collected from external systems.

Evidence is the foundation of THRAGG.

It is never modified.

---

## Sources

Examples include

- Nmap XML
- OWASP ZAP JSON
- OWASP ZAP HTML
- Azure JSON
- Microsoft Graph JSON
- Linux auth.log
- Syslog
- journalctl
- Future supported evidence

---

## Responsibility

Evidence only contains data.

Evidence contains no security intelligence.

---

# 2. Finding

## Purpose

A Finding represents a standardized security observation.

Every module transforms raw evidence into Findings.

Findings are the first normalized security object.

---

## Created By

Module Rule Engines

---

## Consumed By

Entity Extraction

Reporting

Future analytics

---

## Characteristics

- Standardized
- Deterministic
- Traceable
- Immutable

---

## Required Information

- Identifier
- Title
- Description
- Severity
- Confidence
- Category
- Type
- Entity Type
- Source Module
- Source Rule
- Evidence
- Recommendation

---

# 3. Entity

## Purpose

Entities represent real-world security objects extracted from Findings.

Entities answer the question

"What does this Finding refer to?"

---

## Examples

Host

User

Identity

Service

Database

Application

Cloud Resource

Network

Container

Storage

---

## Created By

Entity Extractor

---

## Consumed By

Entity Resolution

Relationship Builder

---

## Characteristics

- Independent
- Reusable
- Traceable
- Immutable

---

## Required Information

- Identifier
- Entity Type
- Primary Identifier
- Aliases
- Attributes
- Source Module
- Source Finding
- Confidence

---

# 4. Resolved Entity

## Purpose

A Resolved Entity represents the canonical identity of one or more related Entities.

Multiple Entity objects may describe the same logical asset.

Resolution merges these representations while preserving traceability.

---

## Example

```
10.0.0.5

↓

web01

↓

Azure VM vm-web01

↓

Resolved Entity
```

---

## Created By

Entity Resolution Engine

---

## Consumed By

Relationship Builder

---

# 5. Relationship

## Purpose

Relationships connect Resolved Entities.

Relationships describe how assets interact.

---

## Examples

```
HOST

runs

SERVICE
```

```
USER

authenticated_to

HOST
```

```
HOST

belongs_to

SUBNET
```

---

## Created By

Relationship Builder

---

## Consumed By

Correlation Engine

---

## Characteristics

Directed

Typed

Time-aware

Traceable

---

# 6. Correlation

## Purpose

Correlation identifies meaningful patterns across relationships.

Correlation does not analyze evidence.

Correlation analyzes graph structures.

---

## Examples

SSH exposed

+

Public VM

+

Repeated failed logins

+

No MFA

↓

Possible initial access path

---

## Created By

Correlation Engine

---

## Consumed By

Attack Chain Builder

---

# 7. Attack Chain

## Purpose

An Attack Chain represents a plausible sequence of attacker activity.

Attack Chains combine multiple correlated events into one narrative.

---

## Characteristics

Chronological

Evidence-backed

MITRE mapped

Explainable

Traceable

---

## Created By

Attack Chain Builder

---

## Consumed By

Risk Engine

Executive Reporting

---

# 8. Risk Assessment

## Purpose

Risk Assessment measures the security impact of complete attack chains.

Risk is calculated using multiple factors.

---

## Possible Inputs

Severity

Confidence

Criticality

Relationship density

Attack complexity

Asset sensitivity

Exposure

---

## Output

Unified Risk Score

Risk Level

Analyst Explanation

---

# 9. Executive Report

## Purpose

Executive Reports communicate framework intelligence.

Reports should be understandable by both technical analysts and management.

---

## Contents

Executive Summary

Attack Narrative

Risk Summary

Affected Assets

MITRE ATT&CK Mapping

Timeline

Recommendations

Supporting Evidence

---

# Object Lifecycle

```
Evidence

↓

Finding

↓

Entity

↓

Resolved Entity

↓

Relationship

↓

Correlation

↓

Attack Chain

↓

Risk Assessment

↓

Executive Report
```

Every object has one producer.

Every object has one primary consumer.

This guarantees architectural consistency.

---

# Framework Guarantees

Every framework object must satisfy the following properties.

Consistency

Every module produces standardized objects.

---

Determinism

The same evidence produces the same objects.

---

Traceability

Every object can be traced back to its originating evidence.

---

Immutability

Objects are enriched by creating new objects.

Existing objects are never modified.

---

Extensibility

New object types may be introduced without redesigning existing objects.

---

Backward Compatibility

Public object contracts remain stable.

Extensions should add capabilities rather than remove fields.

---

# Object Ownership

| Object | Owner |
|----------|-----------------------------|
| Evidence | Modules |
| Finding | Finding Builder |
| Entity | Entity Extractor |
| Resolved Entity | Resolution Engine |
| Relationship | Relationship Builder |
| Correlation | Correlation Engine |
| Attack Chain | Attack Chain Builder |
| Risk Assessment | Risk Engine |
| Executive Report | Report Builder |

Ownership clearly defines responsibility inside the framework.

---

# Closing Statement

The Framework Specification defines the language spoken by every architectural component inside THRAGG.

All future development should extend this object model rather than creating parallel representations.

Consistency of objects is fundamental to the long-term maintainability and extensibility of the framework.
