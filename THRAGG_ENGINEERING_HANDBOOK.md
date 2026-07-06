> **Required Reading for Contributors**
>
> Before modifying any part of THRAGG, every human contributor and every AI coding assistant (Claude Code, Codex, Gemini CLI, Roo Code, Cline, Aider, OpenCode, or similar) should read this handbook completely.
>
> This document is the single source of truth for THRAGG's architecture, engineering philosophy, development workflow, and contribution standards.
# THRAGG Engineering Handbook

Version: 1.0
Status: Living Architecture Document

---

# 1. Introduction

Welcome to the THRAGG project.

THRAGG stands for

Threat Hunting
Recon
Automated
Gap
Analysis
Gateway

THRAGG is an open-source cybersecurity intelligence framework designed to transform isolated security evidence into meaningful security intelligence.

It is not a vulnerability scanner.

It is not a SIEM.

It is not an EDR.

Instead, THRAGG acts as an orchestration framework that consumes evidence produced by many security tools, normalizes the evidence into a common format, correlates findings across different security domains, evaluates environmental risk, and generates actionable security intelligence.

The long-term vision is to provide an extensible framework where additional security tools can be integrated without requiring architectural redesign.

---

# 2. Vision

Most cybersecurity tools answer one specific question.

Nmap answers:

"What network services are exposed?"

OWASP ZAP answers:

"What web vulnerabilities exist?"

Linux logs answer:

"What authentication events occurred?"

Cloud assessments answer:

"What cloud security weaknesses exist?"

Identity assessments answer:

"Who has excessive permissions or weak identity controls?"

THRAGG answers a different question.

"How are all of these pieces connected?"

THRAGG exists to connect evidence across multiple security domains into one unified security assessment.

Instead of producing five unrelated reports, THRAGG should explain the complete security story.

---

# 3. Core Philosophy

The following principles are the foundation of THRAGG.

These principles should never change.

## Principle 1

Evidence First

THRAGG never invents information.

Everything must originate from real evidence.

Evidence always comes before intelligence.

---

## Principle 2

Normalize Before Analyze

Every evidence source must first become a standardized THRAGG contract.

No intelligence layer should ever consume raw XML, JSON, HTML, log files, or proprietary formats.

Modules are responsible for normalization.

Higher layers are responsible for intelligence.

---

## Principle 3

One Responsibility Per Layer

Every architectural layer has exactly one responsibility.

Modules analyze evidence.

Correlation connects evidence.

Attack Chains explain relationships.

Risk evaluates exposure.

Executive Assessment summarizes intelligence.

Dashboard visualizes results.

No layer should perform another layer's responsibilities.

---

## Principle 4

Architecture Before Code

Every major feature follows the same workflow.

Architecture

↓

Discussion

↓

Review

↓

Freeze

↓

Implementation

↓

Testing

↓

Hardening

↓

Freeze

Only after the architecture is approved should implementation begin.

---

## Principle 5

Framework Over Scripts

THRAGG is a framework.

Every new capability should extend the framework rather than introduce isolated scripts.

Reusable components are preferred over one-off implementations.

---

## Principle 6

Backward Compatibility

Stable interfaces should never be broken.

When functionality expands, extend existing components instead of replacing them.

---

## Principle 7

Tool Independence

THRAGG should never depend on one specific security tool.

The framework should consume standardized evidence regardless of which scanner generated it.

Future integrations should require only new modules, not architectural redesign.

---

# 4. High-Level Architecture

The complete framework follows this pipeline.

Evidence

↓

Modules

↓

Standard THRAGG Contracts

↓

Entity Resolution

↓

Relationship Graph

↓

Correlation Engine

↓

Attack Chain Engine

↓

Risk Engine

↓

Executive Assessment

↓

Reporting

↓

Dashboard

Every layer depends only on the layer immediately below it.

Dependencies must always flow downward.

No layer should bypass another layer.

---

# 5. Architectural Boundaries

## Evidence Layer

Consumes external evidence only.

Examples include:

- Nmap XML
- OWASP ZAP Reports
- Azure Security Exports
- Microsoft Graph Exports
- Linux Authentication Logs
- Syslog
- Journalctl

This layer never performs intelligence.

---

## Module Layer

Each module performs two responsibilities.

1.

Evidence collection

2.

Evidence normalization

Every module produces the same THRAGG contract.

Modules never communicate with each other.

Modules never perform correlation.

---

## Foundation Layer

The foundation layer creates standardized entities.

Examples include:

Host

Identity

Service

Cloud Resource

Application

Port

IP Address

These entities become reusable across the entire framework.

---

## Correlation Layer

Consumes only standardized entities.

Never consumes raw evidence.

Never consumes raw files.

Its purpose is to discover relationships.

---

## Attack Chain Layer

Consumes correlation results.

Builds logical attack narratives.

Never parses evidence.

Never performs scanning.

---

## Risk Layer

Consumes attack chains.

Evaluates overall environmental risk.

Risk is not equivalent to finding severity.

---

## Executive Layer

Converts technical intelligence into executive language.

Focuses on decision support.

Not technical implementation.

---

## Dashboard Layer

Contains zero business logic.

Displays only information already calculated by previous layers.

---

# 6. Data Flow

Every object should move through the same lifecycle.

Raw Evidence

↓

Module Parser

↓

Normalized Finding

↓

Entity Extraction

↓

Entity Resolution

↓

Relationship Graph

↓

Correlation

↓

Attack Chain

↓

Risk Assessment

↓

Executive Assessment

↓

Dashboard

This flow must never be violated.

---

# 7. THRAGG Contract Philosophy

Every module produces the same contract.

metadata

summary

details

artifacts

errors

This contract is the public interface between modules and the intelligence layers.

Changing this contract affects the entire framework.

Changes require architectural review.

---

# 8. Layer Responsibilities

Evidence

Acquire evidence.

Modules

Normalize evidence.

Foundation

Create reusable entities.

Correlation

Discover relationships.

Attack Chains

Explain attack progression.

Risk

Measure environmental exposure.

Executive

Summarize findings.

Dashboard

Present intelligence visually.

If a responsibility belongs to another layer, do not implement it.

---

# 9. Architectural Rules

The following rules are mandatory.

Never parse raw evidence outside modules.

Never bypass standardized contracts.

Never duplicate entity definitions.

Never duplicate relationship definitions.

Never hardcode attack chains.

Never hardcode risk calculations.

Never mix visualization with analysis.

Never redesign stable architecture without architectural review.

Never introduce circular dependencies.

Prefer extension over replacement.

Prefer composition over duplication.

Prefer reusable engines over specialized scripts.

---

# 10. Long-Term Goals

The long-term vision of THRAGG is to evolve into an extensible cybersecurity intelligence framework capable of supporting multiple security domains without architectural redesign.

Future integrations may include:

Windows Event Logs

Sysmon

Sigma Rules

Suricata

Burp Suite

Nessus

OpenVAS

AWS

Google Cloud

Microsoft Defender

Elastic

CrowdStrike

Additional integrations should require only new modules while preserving the existing architecture.

The architecture itself should remain stable regardless of how many evidence sources are supported.

# THRAGG Engineering Handbook

# Part 2

## Framework Structure, Engineering Standards & Current Project State

---

# 11. Repository Structure

The THRAGG repository is organized into independent architectural layers.

Every layer has exactly one responsibility.

No layer should perform another layer's work.

```

THRAGG/

```
│
├── core/
│
│ ├── foundation/
│ ├── correlation/
│ ├── attack_chain/
│ ├── risk/
│ ├── executive/
│ ├── dashboard/
│ ├── reporting/
│ └── shared/
│
├── modules/
│
│ ├── logs.py
│ ├── nmap.py
│ ├── cloud.py
│ ├── identity.py
│ └── zap.py
│
├── tests/
│
├── docs/
│
├── data/
│
├── static_findings/
│
├── rules/
│
├── schemas/
│
├── thragg.py
│
└── README.md

```

Every folder should remain independent.

---

# 12. Module Philosophy

Every module follows exactly the same architecture.

Mode 1

↓

Offline Analysis

↓

Mode 2

↓

CLI Collection

↓

Mode 3

↓

REST API Collection

Mode 2 and Mode 3 NEVER perform security analysis.

They only collect evidence.

They always invoke Mode 1.

Therefore,

Mode 1 becomes the single source of truth.

This rule must never change.

---

# 13. Supported Modules

Currently implemented modules include

Network Analysis

Nmap

System Log Analysis

Linux Authentication Logs

Cloud Security

Azure

Identity Security

Microsoft Entra ID

Web Security

OWASP ZAP

Future modules should follow exactly the same architecture.

---

# 14. Standard Module Contract

Every module returns the same contract.

```

metadata

summary

details

artifacts

errors

```

No module may introduce custom top-level fields.

If additional information is required,

it should be placed inside the existing contract.

Maintaining one standardized contract is critical to framework stability.

---

# 15. Engineering Layers

The framework is divided into layers.

Each layer accepts only the previous layer's output.

Evidence

↓

Modules

↓

Foundation

↓

Correlation

↓

Attack Chains

↓

Risk

↓

Executive

↓

Reporting

↓

Dashboard

Every layer must consume structured objects.

No layer may consume raw evidence except Modules.

---

# 16. Foundation Layer

Purpose

Create standardized reusable security entities.

Examples

Host

Identity

Cloud Resource

Service

Application

IP Address

Port

Future

Process

Registry Key

Certificate

Domain

Entity resolution occurs here.

Duplicate entities should become one logical object.

---

# 17. Correlation Layer

Purpose

Discover relationships between entities.

The Correlation Layer never parses files.

It accepts

THRAGG Contracts

↓

Resolved Entities

↓

Relationship Graph

↓

Correlation Objects

The Correlation Layer prepares intelligence.

It does not generate reports.

---

# 18. Relationship Graph

The Relationship Graph is the backbone of THRAGG.

It represents

Nodes

Entities

Edges

Relationships

Example

Host

↓

runs

↓

SSH Service

↓

used by

↓

Identity

↓

belongs to

↓

Cloud Resource

The graph should be implemented using lightweight in-memory structures.

Avoid unnecessary external infrastructure.

---

# 19. Attack Chain Layer

Purpose

Convert correlated entities into attack narratives.

Attack chains explain

How

Why

What happened

Attack chains are not merely grouped findings.

They represent logical attacker progression.

Future attack chains should support

MITRE ATT&CK

CAPEC

CWE

OWASP

without redesign.

---

# 20. Risk Layer

Purpose

Evaluate environmental exposure.

Risk is different from severity.

Severity describes one finding.

Risk describes the environment.

Risk should combine

Correlation

Attack Chains

Asset Exposure

Identity Weakness

Cloud Exposure

Confidence

into one environmental assessment.

---

# 21. Executive Layer

Purpose

Translate technical intelligence into executive language.

Outputs should answer questions such as

Overall Security Posture

Most Critical Assets

Primary Attack Paths

Highest Business Risk

Priority Recommendations

This layer is designed for managers rather than analysts.

---

# 22. Dashboard Layer

Purpose

Visualize intelligence.

The Dashboard Layer contains zero business logic.

It visualizes only

Attack Chains

Risk

Entities

Correlations

Recommendations

No calculations should occur inside dashboard code.

---

# 23. Shared Components

Shared utilities belong in

core/shared/

Examples

Logging

Configuration

Constants

Version Information

Utilities

Priority Ranking

Stable IDs

Traceability

Reusable helper functions belong here.

---

# 24. Frozen Components

The following architecture is considered stable.

Modules

THRAGG Contract

Mode Architecture

Foundation Layer

Entity Model

Relationship Model

Correlation Architecture

These components should not be redesigned.

They may only be extended.

---

# 25. Completed Milestones

The following milestones are complete.

✓ Repository Architecture

✓ Documentation

✓ Module Framework

✓ Logs Module

✓ Nmap Module

✓ Cloud Module

✓ Identity Module

✓ ZAP Module

✓ Standard Contract

✓ Entity Extraction

✓ Entity Resolution

✓ Foundation Layer

✓ Correlation Foundation

✓ Relationship Graph

✓ Rule Framework

✓ Confidence Model

✓ Validation

✓ Engineering Hardening

These milestones are considered frozen unless a critical issue is discovered.

---

# 26. Current Development Status

Current Phase

Intelligence Layer

Next Component

Attack Chain Engine

After Attack Chain

Risk Engine

After Risk

Executive Assessment

After Executive

Dashboard Generator

These phases build directly on the Correlation Foundation.

---

# 27. Remaining Roadmap

The remaining engineering roadmap is

Attack Chain Engine

↓

Risk Engine

↓

Executive Assessment

↓

Dashboard Generator

↓

Reporting Framework

↓

Knowledge Base

↓

Evidence Adapters

↓

Production Hardening

↓

Version 1.0 Release

Each phase must be completed before beginning the next.

---

# 28. Engineering Standards

All code should follow

PEP8

Type Hints

Dataclasses where appropriate

Small focused classes

Single Responsibility Principle

High Cohesion

Low Coupling

Builder Pattern where appropriate

Repository Pattern where appropriate

Avoid giant classes.

Avoid duplicated logic.

Avoid global mutable state.

---

# 29. AI Contributor Workflow

Every AI contributor must follow this process.

1.

Read this handbook completely.

2.

Inspect the existing repository.

3.

Reuse existing implementations whenever possible.

4.

Do not duplicate code.

5.

Preserve architecture.

6.

Preserve backward compatibility.

7.

Implement only the requested phase.

8.

Do not redesign frozen components.

9.

Document architectural decisions.

10.

Explain all major changes before implementation.

---

# 30. Definition of Completion

A phase is considered complete only when

Architecture is frozen.

Implementation matches architecture.

Tests pass.

No duplicated logic exists.

Documentation is updated.

Backward compatibility is preserved.

The phase passes engineering review.

Only then should development continue to the next milestone.


# THRAGG Engineering Handbook

# Part 3

## AI Contributor Guide, Engineering Standards & Future Governance

---

# 31. AI Contributor Contract

Every AI agent contributing to THRAGG must follow this contract before modifying any code.

The workflow is mandatory.

1.

Read the complete THRAGG Engineering Handbook.

2.

Inspect the current repository.

3.

Understand the architecture before implementation.

4.

Reuse existing implementations whenever possible.

5.

Never duplicate existing logic.

6.

Never redesign frozen components.

7.

Implement only the requested milestone.

8.

Preserve backward compatibility.

9.

Explain architectural decisions before code generation.

10.

Keep every layer independent.

Failure to follow these rules creates technical debt.

---

# 32. Coding Philosophy

THRAGG is designed as an engineering framework.

Every implementation should prioritize

Readability

Maintainability

Extensibility

Consistency

Reusability

Correctness

Performance improvements are welcome only after architecture remains clean.

Readable code is preferred over clever code.

---

# 33. Engineering Principles

Every component should follow

Single Responsibility Principle

Open / Closed Principle

Dependency Inversion

Composition over inheritance

High cohesion

Low coupling

Immutable data where practical

Reusable abstractions

Avoid large classes.

Avoid hidden side effects.

Avoid unnecessary complexity.

---

# 34. Code Style

All Python code should follow

PEP8

Type hints

Meaningful docstrings

Dataclasses where appropriate

Enums instead of magic strings

Constants instead of hardcoded values

Meaningful exception handling

Avoid wildcard imports.

Avoid deeply nested functions.

Avoid duplicated validation logic.

---

# 35. Repository Design Rules

Every new feature should integrate into the existing architecture.

Never create

random helper.py files

duplicate repositories

duplicate builders

duplicate schemas

duplicate validators

If similar functionality already exists,

extend it.

Do not replace it.

---

# 36. Layer Dependency Rules

Dependency direction is fixed.

Modules

↓

Foundation

↓

Correlation

↓

Attack Chain

↓

Risk

↓

Executive

↓

Reporting

↓

Dashboard

Dependencies must only point downward.

No circular imports.

No layer may skip another layer.

No visualization layer may perform analysis.

---

# 37. Module Extension Guide

Every new evidence source should become its own module.

Example future modules

Windows EVTX

Sysmon

Suricata

Sigma

Burp Suite

Nessus

OpenVAS

AWS

Google Cloud

Microsoft Defender

Elastic Security

Adding a module should never require changing

Correlation

Attack Chain

Risk

Executive

Dashboard

Only the new module should understand its native evidence format.

Everything else consumes standardized THRAGG contracts.

---

# 38. Data Contract Rules

The THRAGG contract is the public API between layers.

The contract consists of

metadata

summary

details

artifacts

errors

No new top-level fields should be introduced without architectural review.

Existing fields should never change meaning.

---

# 39. Entity Rules

Entities represent real-world security objects.

Examples

Host

Identity

Service

Cloud Resource

Application

Port

IPAddress

Future entity types should extend the entity model rather than replacing it.

Duplicate entities should always resolve into one logical entity.

---

# 40. Relationship Rules

Relationships describe how entities interact.

Examples

authenticated_via

runs_on

hosted_in

contains

owns

targets

uses

depends_on

belongs_to

related_to

Relationships should always be strongly typed.

Never invent relationship names inside implementation logic.

---

# 41. Rule Framework

Security logic should be data-driven.

Avoid

if

else

chains for attack detection.

Instead

store rules as configuration

load rules

evaluate rules

produce results

This allows future rule packs without modifying engine code.

---

# 42. Confidence Model

Confidence should always be reproducible.

Never output arbitrary confidence values.

Confidence should be calculated using

Evidence Quality

Entity Resolution Strength

Relationship Confidence

Rule Confidence

Cross-module Corroboration

Every confidence score should be explainable.

---

# 43. Testing Philosophy

Every new feature requires tests.

Tests should verify

Normal behavior

Invalid input

Boundary conditions

Error handling

Regression prevention

The framework should remain stable as new modules are added.

---

# 44. Documentation Standards

Every public class should explain

Purpose

Inputs

Outputs

Responsibilities

Avoid documenting implementation details.

Document architectural intent.

Documentation should help future contributors understand design decisions.

---

# 45. Code Review Checklist

Before accepting any implementation verify

Architecture preserved

No duplicated logic

No unnecessary dependencies

No circular imports

Naming consistency

Type hints

Tests updated

Documentation updated

Backward compatibility maintained

If any item fails,

the implementation is not complete.

---

# 46. Architecture Review Checklist

Every major phase must answer

Does it have exactly one responsibility?

Does it consume only the previous layer?

Can future modules use it without redesign?

Can existing modules continue working unchanged?

Can it be tested independently?

Is it reusable?

If not,

the architecture should be reviewed before implementation.

---

# 47. Definition of Production Ready

A component is production ready when

Architecture is frozen

Implementation matches architecture

Tests pass

Documentation updated

No duplicated code

Public APIs documented

Backward compatibility preserved

Logging implemented

Validation implemented

Error handling implemented

Configuration centralized

Only then may the component be considered complete.

---

# 48. Future Roadmap

Future work after Version 1.0 may include

Live Event Streaming

Real-time Correlation

Threat Intelligence Feeds

Sigma Rule Execution

Graph Visualizations

REST API

Plugin Marketplace

Distributed Processing

Cloud Deployment

Machine Learning Assisted Correlation

These features should extend the framework rather than redesign it.

---

# 49. Release Philosophy

Every release follows

Architecture

↓

Discussion

↓

Freeze

↓

Implementation

↓

Testing

↓

Hardening

↓

Documentation

↓

Review

↓

Release

No release should skip architectural review.

---

# 50. Final Engineering Principle

THRAGG is not a collection of cybersecurity scripts.

THRAGG is a modular cybersecurity intelligence framework.

Every contribution should move the framework toward

greater modularity

greater maintainability

greater extensibility

greater engineering quality

rather than simply adding more code.

When in doubt,

choose the solution that keeps the architecture clean.

The architecture is the product.

The code is only one implementation of that architecture.

End of Handbook.

