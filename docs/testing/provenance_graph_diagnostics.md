# Provenance graph diagnostics

The provenance graph is the system's primary data-flow tracking and
visualization artifact. It is not compressed into a separate final score.

Final evaluation uses the remaining metrics:

- capture completeness;
- process certification;
- normal completion;
- normal completion drop;
- normal injection false positives;
- attack detection recall;
- attack field coverage;
- attack blocking.

The graph remains available for audit and visualization. It records:

- APP and tool activities;
- DomainData and AIModelInvocation nodes;
- `produces`, `informed`, and `wasDerivedFrom` relations;
- argument source paths and parameter provenance;
- sensitive values, egress sinks, and policy events;
- missing required edges, unexpected edges, ambiguous sources, and unplanned
  actions through the process-conformance diagnostics.

A strict "minimal reference call path" is intentionally not a final metric.
It penalizes equivalent tool use such as a broader search query that still
returns the required object, and therefore measures path style rather than
task correctness, traceability, or security. Reference steps remain useful as
diagnostic metadata for frontend explanation and case analysis, but do not
produce a headline score.

Legacy fields such as `expected_task_flow_coverage`,
`flow_link_completeness`, and `provenance_reconstruction_accuracy` may remain
inside historical trace payloads for backward compatibility. They are not
part of the final metric projection.
