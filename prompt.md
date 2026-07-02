The architecture review has been completed.

Implement ONLY the approved improvements listed below.

APPROVED CHANGES

1. Replace the Entity stable ID algorithm with the same deterministic algorithm used by the Finding subsystem.
   - Use the same hashing strategy and ID format for consistency.
   - Do not introduce a new ID scheme.

2. Populate the aliases field when multiple identifiers for the same entity exist within a single Finding.
   Example:
   host = web01
   ip = 10.0.0.5
   Primary identifier may remain the IP, but "web01" should become an alias.

3. Remove dead code identified in the review.
   - Remove impossible EntityType None checks.
   - Remove unnecessary Confidence isinstance() guards.
   - Remove any other unreachable code discovered during implementation.

4. Export the Entity subsystem through core/__init__.py.

5. Expand the internal entity mapping to support all EntityType values defined by the framework where appropriate.

6. Create a comprehensive test suite for the Entity subsystem.
   Include:
   - Entity model
   - Serialization
   - Validation
   - Stable ID generation
   - Alias handling
   - Entity extraction
   - Batch extraction
   - Empty input
   - Invalid input
   - Edge cases

REJECTED CHANGES

Do NOT introduce an EntityBuilder.

The architecture intentionally defines EntityExtractor as the construction layer for Entity objects.

Do NOT redesign the architecture.

Do NOT rename public APIs.

Do NOT change the Finding subsystem.

Do NOT modify Milestone 1.

Preserve backward compatibility.

After implementation:

1. Run the complete test suite.
2. Fix any failing tests.
3. Summarize:
   - Files modified
   - Why each file changed
   - Test results
   - Remaining known limitations
