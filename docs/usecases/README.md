# Use Cases

VeilGate is a single-host reverse proxy that detects and tarpits AI-driven
pentest agents. The deployment shape is always the same — a hardened
systemd service in front of an upstream application. **What changes is the
operator's primary objective.**

This section is one page per objective. Each page covers:

- the problem, in concrete terms,
- the VeilGate config that addresses it,
- the metrics that prove it's working,
- the operational gotchas to know going in.

| Use case | Primary buyer | Read time |
| --- | --- | --- |
| [Bug-bounty noise reduction](bug-bounty-triage.md) | AppSec lead at a B2B SaaS | 6 min |
| [LLM-agent defence](llm-agent-defense.md) | Security architect | 8 min |
| [API recon blocking](api-recon-blocking.md) | Platform / API team | 6 min |
| [Compliance & audit evidence](compliance-evidence.md) | CISO / GRC | 7 min |
| [Replace your WAF with VeilGate](replace-your-waf.md) | Platform engineer / SecOps | 10 min |

## Reading order

If you're new to VeilGate, read the use case closest to your role first,
then skim the others to understand the secondary value. The configuration
patterns overlap heavily — once you've configured for one objective, the
others are mostly threshold tuning.

## Related

- [Why VeilGate](../product/why-veilgate.md) — case study for why the project exists
- [Business case](../product/business-case.md) — analytical framing
- [How-to guides](../how-to/README.md) — task-oriented walk-throughs
- [Configuration reference](../config/README.md) — every YAML setting

---

*Previous: [Documentation home](../README.md) · Next: [Bug-bounty triage](bug-bounty-triage.md)*
