# THRAGG Architecture Specification
**Version:** 1.0  
**Status:** Active  
**Document Type:** Architecture Constitution

---

# 1. Project Identity

## Name

**THRAGG**

**Threat Hunting, Recon & Automated Gap Analysis Gateway**

---

## Vision

THRAGG exists to unify fragmented security evidence into a single, coherent security assessment.

Modern organizations rely on multiple security tools to monitor different parts of their infrastructure. While each tool provides valuable insights, they typically operate independently, making it difficult to understand how isolated security findings relate to one another.

THRAGG provides an architecture that bridges these isolated findings into meaningful security intelligence while remaining modular, extensible, and tool-agnostic.

---

## Mission

Create an orchestration framework capable of:

- Collecting security evidence
- Normalizing heterogeneous security data
- Producing standardized findings
- Extracting meaningful security entities
- Correlating evidence across security domains
- Building realistic attack narratives
- Delivering actionable executive intelligence

THRAGG is designed to answer one question:

> **"What is the overall security story being told by all of my security evidence?"**

---

## Scope

THRAGG focuses on evidence orchestration and security intelligence generation.

It intentionally separates:

- Evidence Collection
- Evidence Analysis
- Correlation
- Reporting

into independent architectural layers.

---

# 2. Problem Statement

Modern security tooling suffers from fragmentation.

Network scanners discover exposed services.

Identity systems detect authentication risks.

Cloud platforms identify misconfigurations.

Log analysis tools reveal suspicious behavior.

Web scanners discover application vulnerabilities.

Each tool operates within its own domain.

As a result:

- Security findings remain isolated.
- Relationships between findings are lost.
- Analysts manually correlate evidence.
- Cross-domain attack paths are often missed.

THRAGG exists to solve this architectural problem.

Instead of replacing existing security tools, THRAGG consumes their evidence, standardizes their outputs, and constructs a unified understanding of the security posture.

---

# 3. Design Philosophy

THRAGG is built upon the following principles.

## Evidence First

Evidence is the foundation of every architectural decision.

THRAGG never invents evidence.

It consumes evidence produced by trusted sources.

---

## Tool Agnostic

THRAGG is independent of any specific vendor.

Supported evidence may originate from:

- Nmap
- OWASP ZAP
- Azure
- Microsoft Graph
- Linux Logs
- Syslog
- Journalctl
- Future integrations

The framework is designed to support additional tools without architectural changes.

---

## Normalize Before Analysis

Raw evidence is never analyzed directly.

Every evidence source is normalized before any intelligence is produced.

Normalization creates consistency.

Consistency enables correlation.

---

## Single Source of Truth

Every processing stage has one canonical representation.

No duplicated processing paths exist.

Every downstream component consumes standardized objects.

---

## Framework First

THRAGG is a framework rather than a collection of scripts.

Reusable architecture takes precedence over feature-specific implementations.

---

## Modular by Design

Every module is independently responsible for its own evidence domain.

Modules never depend on each other.

Shared behavior belongs in the framework core.

---

## Backward Compatibility

Stable interfaces remain stable.

Extensions are preferred over redesigns.

Existing public APIs must remain compatible unless an architectural decision explicitly states otherwise.

---

# 4. Architectural Principles

The following rules are mandatory.

## Rule 1

Modules never communicate directly.

---

## Rule 2

Modules never correlate findings.

---

## Rule 3

Modules never perform entity resolution.

---

## Rule 4

Modules never depend on implementation details of other modules.

---

## Rule 5

Security analysis belongs inside modules.

Framework intelligence belongs inside THRAGG.

---

## Rule 6

Every shared object follows the same architectural pattern.

Data Model

↓

Builder / Extractor

↓

Validator

---

## Rule 7

Evidence is parsed once.

Normalized once.

Consumed many times.

---

## Rule 8

Correlation never consumes raw evidence.

Only standardized framework objects.

---

## Rule 9

Architecture is extended through new layers rather than modifying completed layers.

---

# 5. Layered Architecture

THRAGG is organized into six logical layers.

```
Evidence Layer
        │
        ▼
Analysis Layer
        │
        ▼
Knowledge Layer
        │
        ▼
Correlation Layer
        │
        ▼
Intelligence Layer
        │
        ▼
Presentation Layer
```

Each layer has a single responsibility.

No layer bypasses another.

---

## Evidence Layer

Responsible for collecting security evidence.

Examples:

- XML
- JSON
- HTML
- Log files

No security analysis occurs here.

---

## Analysis Layer

Transforms evidence into standardized Findings.

Security detection logic belongs exclusively to this layer.

---

## Knowledge Layer

Transforms Findings into reusable security objects.

Examples:

- Entities
- Relationships

This layer creates structured knowledge without performing correlation.

---

## Correlation Layer

Discovers relationships between security objects.

Produces attack paths.

Produces cross-domain intelligence.

---

## Intelligence Layer

Assigns meaning to correlated information.

Produces:

- Risk Scores
- Attack Narratives
- Executive Intelligence

---

## Presentation Layer

Responsible for communicating intelligence.

Examples:

- Reports
- Dashboards
- JSON exports
- Executive summaries

Presentation never performs analysis.

---

# 6. Core Object Model

THRAGG transforms evidence through progressively richer representations.

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
Attack Chain
        │
        ▼
Executive Report
```

Each object represents a higher level of abstraction.

Earlier objects remain immutable.

Later objects enrich earlier objects without modifying them.

---

# 7. Framework Data Flow

The complete THRAGG processing pipeline is:

```
Evidence
        │
        ▼
Parser
        │
        ▼
Normalization
        │
        ▼
Rule Engine
        │
        ▼
Finding Builder
        │
        ▼
Entity Extraction
        │
        ▼
Entity Resolution
        │
        ▼
Relationship Graph
        │
        ▼
Correlation Engine
        │
        ▼
Attack Chain Builder
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

Every stage consumes the output of the previous stage.

No stage bypasses the architecture.

---

# 8. THRAGG Contracts

All framework communication occurs through standardized contracts.

Contracts exist to guarantee interoperability between architectural layers.

Every contract must be:

- Predictable
- Versionable
- Extensible
- Backward Compatible

Core contracts include:

- Finding
- Entity
- Relationship
- Attack Chain
- Executive Report

No component should rely on module-specific internal structures.

---

# 9. Operational Modes

Every module supports three operational modes.

## Mode 1

Offline Evidence Analysis

This is the canonical execution path.

All security analysis occurs here.

---

## Mode 2

CLI Collection

Responsible only for collecting evidence through command-line interfaces.

Collected evidence is forwarded to Mode 1.

No security logic exists inside Mode 2.

---

## Mode 3

REST API Collection

Responsible only for collecting evidence through APIs.

Collected evidence is forwarded to Mode 1.

No security logic exists inside Mode 3.

---

Mode 1 remains the single source of truth.

---

# 10. Architectural Constraints

The following constraints protect architectural consistency.

Future contributors must never:

- Duplicate framework logic.
- Parse raw evidence inside intelligence layers.
- Introduce module dependencies.
- Bypass normalization.
- Perform correlation inside modules.
- Modify completed architecture without an Architecture Decision Record.
- Introduce tool-specific assumptions into shared components.

Architecture consistency always takes precedence over implementation convenience.

---

# 11. Extension Model

THRAGG is designed for continuous extension.

New capabilities should integrate into the existing architecture rather than replacing it.

Adding a new evidence source should require:

New Module

↓

Standardized Findings

↓

Automatic participation in framework intelligence

Existing framework layers should remain unchanged.

---

# 12. Non-Goals

THRAGG intentionally does not attempt to become:

- A SIEM
- An EDR
- A SOAR platform
- A Vulnerability Scanner
- A Network Scanner
- A Cloud Security Platform
- A Real-Time Streaming Engine

THRAGG complements existing security tooling.

It does not replace it.

---

# 13. Glossary

### Evidence

Raw security data produced by external tools.

---

### Finding

A standardized security event derived from normalized evidence.

---

### Entity

A security object extracted from one or more Findings.

---

### Entity Resolution

The process of identifying multiple Entity representations as the same logical object.

---

### Relationship

A connection between two or more Entities.

---

### Correlation

The discovery of meaningful security patterns across multiple Findings and Entities.

---

### Attack Chain

A sequence of correlated security events representing a plausible attack path.

---

### Executive Intelligence

Human-readable security insight generated from correlated security knowledge.

---

# Closing Statement

THRAGG is designed as a framework for transforming isolated security evidence into unified security intelligence.

Its architecture emphasizes consistency, modularity, extensibility, and long-term maintainability.

Every future capability must strengthen these architectural principles rather than replace them.
