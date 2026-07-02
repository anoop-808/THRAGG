# THRAGG Engineering Guide
**Version:** 1.0  
**Status:** Active  
**Document Type:** Engineering Handbook

---

# 1. Purpose

This document defines the engineering standards, development workflow, and contribution process for THRAGG.

Every contributor should understand this guide before implementing new functionality.

The objective is to ensure THRAGG evolves with consistent architecture, predictable behavior, and maintainable code.

This document complements the Architecture Specification.

If a conflict exists between this guide and the Architecture Specification, the Architecture Specification always takes precedence.

---

# 2. Engineering Philosophy

THRAGG is engineered as a framework.

The objective is not simply to implement features.

The objective is to build a reusable, extensible architecture.

Every implementation should improve the framework without compromising its existing design.

Framework quality is valued over implementation speed.

---

# 3. Development Lifecycle

Every feature follows the same engineering lifecycle.

```
Architecture Discussion
        │
        ▼
Architecture Design
        │
        ▼
Architecture Review
        │
        ▼
Architecture Freeze
        │
        ▼
Implementation Prompt
        │
        ▼
Implementation
        │
        ▼
Testing
        │
        ▼
Code Review
        │
        ▼
Targeted Fixes
        │
        ▼
Merge
```

No implementation begins before architecture has been approved.

---

# 4. Architecture Freeze

Once a design has been approved it becomes frozen.

Implementation may improve:

- Readability
- Error handling
- Testing
- Performance
- Documentation

Implementation must not change:

- Public APIs
- Core architecture
- Framework philosophy
- Data flow
- Contracts

Architectural changes require a new Architecture Decision Record (ADR).

---

# 5. Repository Structure

The repository is organized by responsibility.

```
core/
```

Contains reusable framework components.

Examples:

- Models
- Builders
- Validators
- Extractors
- Shared utilities

---

```
modules/
```

Contains evidence-specific modules.

Each module is independent.

Modules never communicate with each other.

---

```
tests/
```

Contains framework and module tests.

Every milestone must include appropriate tests.

---

```
docs/
```

Contains architectural documentation.

Documentation is considered part of the framework.

---

# 6. Responsibilities

## Core

Responsible for reusable framework logic.

Examples:

- Finding Builder
- Entity Extractor
- Validators
- Shared Models

Core never performs evidence collection.

---

## Modules

Responsible for:

- Evidence collection
- Parsing
- Normalization
- Rule execution

Modules never perform:

- Correlation
- Entity Resolution
- Risk Scoring

Modules produce standardized framework objects.

---

## Report Builder

Responsible only for presentation.

No analysis should occur here.

---

# 7. Coding Standards

Every function should have one responsibility.

Keep functions small.

Prefer composition over duplication.

Avoid deeply nested logic.

Use descriptive naming.

Use type hints consistently.

Write docstrings for public functions and classes.

Document architectural decisions rather than implementation details.

---

# 8. Builder Pattern

Shared framework objects follow a common pattern.

```
Model

↓

Builder / Extractor

↓

Validator
```

Examples:

```
Finding

↓

Finding Builder

↓

Finding Validator
```

```
Entity

↓

Entity Extractor

↓

Entity Validator
```

Future framework objects should follow the same architecture.

---

# 9. Error Handling Philosophy

Warnings indicate recoverable situations.

Examples:

- Optional evidence missing
- Missing export
- Missing optional field

Warnings never stop execution.

Errors indicate execution failure.

Examples:

- Invalid JSON
- Invalid XML
- Import failure
- Parser failure
- Permission denied

Errors may stop module execution.

Malformed individual records should be skipped whenever possible.

Entire evidence sources should only fail when recovery is impossible.

---

# 10. Testing Standards

Every milestone must include tests.

Tests should verify:

- Correct behavior
- Backward compatibility
- Public API stability
- Error handling
- Edge cases

New functionality must not break previous milestones.

Regression testing is mandatory.

---

# 11. Code Review Standards

Every implementation is reviewed for:

Architecture consistency

Code readability

Maintainability

Backward compatibility

Contract compliance

Security considerations

Error handling

Test coverage

Review focuses on long-term framework quality rather than implementation speed.

---

# 12. Implementation Rules

Contributors should:

Extend existing components whenever appropriate.

Avoid introducing unnecessary abstractions.

Avoid premature optimization.

Keep shared logic inside the framework core.

Preserve module independence.

Use deterministic behavior whenever possible.

Do not redesign completed architecture.

---

# 13. Prompt Engineering Workflow

AI-assisted development follows a structured workflow.

```
Architecture Discussion

↓

Architecture Freeze

↓

Implementation Prompt

↓

Implementation

↓

Testing

↓

Review

↓

Targeted Fix

↓

Approval
```

Implementation prompts should:

- Describe the architecture.
- Define constraints.
- Identify files to modify.
- Define acceptance criteria.
- Preserve backward compatibility.

Review prompts should focus on implementation quality rather than architectural redesign.

---

# 14. Backward Compatibility Policy

Backward compatibility is mandatory.

Completed milestones are considered stable.

Future work should extend existing behavior instead of replacing it.

Breaking changes require:

- Architectural discussion
- Architecture Decision Record
- Migration strategy

---

# 15. Documentation Standards

Documentation is treated as production code.

Every major architectural change should update:

- Architecture Specification
- Engineering Guide
- Roadmap
- Relevant ADR

Documentation must remain synchronized with implementation.

---

# 16. Contribution Checklist

Before submitting any implementation verify:

✓ Architecture preserved

✓ Public APIs unchanged

✓ Contracts unchanged

✓ No duplicated logic

✓ Tests added or updated

✓ Existing tests pass

✓ Documentation updated

✓ Code reviewed

✓ Backward compatibility maintained

---

# Closing Statement

THRAGG is engineered as a long-term cybersecurity framework.

Every contribution should strengthen the architecture, improve maintainability, and preserve the consistency of the framework.

Engineering decisions should prioritize simplicity, modularity, and extensibility over short-term convenience.
