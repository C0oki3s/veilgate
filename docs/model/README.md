# Model Card

VeilGate includes online ML-assisted scoring. The ML signal is one input to the
overall detector; it is not the only decision-maker.

## Purpose

The ML layer helps identify request patterns that look agent-generated even when
static rules do not fire strongly enough on their own.

It is designed for:

- local adaptation to an operator's traffic,
- weak-label learning from existing detector decisions,
- surfacing candidate rules for human review.

It is not designed to be a standalone bot detector or a replacement for
operator-reviewed rules.

## Inputs

Feature extraction uses request metadata such as:

- method and path shape,
- path n-grams after redaction,
- user-agent tokens,
- header presence,
- timing buckets,
- TLS fingerprint features when available.

Path redaction replaces common sensitive or high-cardinality values such as
UUIDs, long numeric IDs, hex strings, and base64-like tokens before they become
features.

## Outputs

The ML scorer can emit:

```text
ml_agent_score
```

The signal contributes points to the total detector score when confidence is
high enough under `rules/ml.yaml`.

## Learning

VeilGate uses weak labels from the existing scoring path:

- requests above the configured agent threshold train as agent-like,
- requests below that threshold train as human-like.

This makes the model adaptive, but it also means bad thresholds can teach bad
labels. Run in `observe` and review metrics before trusting ML-heavy behavior.

## Rule Mining

The miner proposes high-confidence feature buckets into `rules/learned.yaml`.
Candidates are inactive by default unless auto-promotion is explicitly configured.

Review learned rules before promotion.

## Limitations

- ML quality depends on local traffic quality.
- Weak labels can amplify false positives.
- Small deployments may not have enough traffic for useful learning.
- Attackers can adapt request shape over time.
- The ML signal should be treated as evidence, not proof.

## Operator Guidance

- Keep path redaction enabled.
- Start with conservative ML settings.
- Review `rules/learned.yaml` before activating candidates.
- Keep capture and persistence data under normal privacy controls.
- Prefer explicit rules for known bad behavior and ML for discovery.
