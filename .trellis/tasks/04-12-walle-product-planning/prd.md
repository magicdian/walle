# brainstorm: walle product planning

## Goal

Define the MVP product scope and technical direction for `walle`, a Rust-first Linux CLI firewall tool built around eBPF/XDP. The product should prioritize host-level threat mitigation with low overhead and predictable operational behavior.

## What I already know

* The project is still in the requirements planning stage and has no application code yet.
* Product name: `walle`, derived from `wall` (firewall) and `e` (eBPF).
* The product is intended to be a CLI application and is currently biased toward Rust as the implementation language.
* Core feature idea 1: provide Fail2ban-like SSH auditing and blacklisting, but with eBPF-based enforcement for higher performance.
* Core feature idea 2: provide ICMP disable / allowlist capability. When enabled, the system should drop ICMP as early as possible, ideally in XDP, while optionally allowing payload-based exceptions using exact match or regex match.
* Desired future feature: blacklist malicious HTTP access, preferably by dropping traffic in XDP if maliciousness can be determined early enough.
* Current repository state is bootstrap-only:
  * [`README.md`](E:/coding/github_projects/walle/README.md) only says "eBPF based firewall".
  * There is no existing Rust crate or implementation directory yet.

## Assumptions (temporary)

* Target platform is Linux with sufficient kernel support for eBPF/XDP.
* The first official support baseline should target Linux kernel `5.15` and above.
* Initial delivery target is a single-node / host firewall CLI, not a Kubernetes or distributed control plane product.
* "Blacklisting" means maintaining a dynamic denylist keyed primarily by source IP or source network prefix.
* MVP should favor clear, deterministic rules over heuristic-heavy "AI-like" traffic classification.

## Open Questions

* None for current MVP definition.

## Requirements

* Provide a CLI-oriented product with explicit commands to enable, disable, inspect, and manage policy state.
* Support SSH brute-force / abuse mitigation with:
  * a user-space detection service that identifies abusive sources from SSH-related signals
  * a dynamic denylist stored in eBPF maps
  * XDP fast-path enforcement for denied sources
  * a first implementation based on configurable fixed thresholds and ban duration
  * a policy model that can later expand to escalation tiers and permanent bans without redesigning shared state
* Support ICMP control with:
  * full ICMP drop mode
  * allow rules based on exact raw-byte payload match in MVP
  * a rule model that can later expand to string and regex matching without redesigning the configuration surface
* Keep eBPF/XDP as the primary packet-path enforcement layer where appropriate.
* Prefer Rust for the control-plane CLI and orchestration logic.
* Reserve an extension point for future protocol-specific detectors, including HTTP-related sources of IP blacklist / whitelist updates.
* Future HTTP handling should initially focus on source-IP allow / deny outcomes, not on promising full application-layer threat inspection at XDP.
* Support distinct access-control operating modes rather than a single hard-coded allow/deny path.
* Store access-control mode and feature flags in a configuration-oriented BPF map, separate from whitelist / blacklist data maps.
* Package the product so normal users do not need to compile eBPF programs on target machines.
* Treat kernel capability checks, including BTF availability when required by the selected program path, as a first-class runtime compatibility concern.

## Acceptance Criteria

* [ ] A product-level MVP scope is defined with explicit in-scope and out-of-scope items.
* [ ] The SSH mitigation flow defines both detection and enforcement stages.
* [ ] The ICMP feature defines matching semantics and the intended enforcement layer.
* [ ] The design clearly states what can and cannot realistically be done at XDP for HTTP traffic.
* [ ] The initial CLI surface is defined at a high level.
* [ ] The architecture reserves a clean path for future detectors to publish IP decisions into shared maps.
* [ ] Access-control modes are explicitly defined and mapped to data-plane behavior.
* [ ] ICMP rule representation is future-proofed for later string and regex matching modes.
* [ ] Product distribution assumptions are explicit about when BTF or equivalent compatibility data is required at runtime.

## Definition of Done (team quality bar)

* Product scope is clear enough to begin repository scaffolding.
* Technical constraints are written down before implementation begins.
* Out-of-scope items are explicit, so future work does not silently expand MVP.
* Follow-up implementation tasks can be split into small, independent milestones.

## Out of Scope

* Full HTTP/WAF-style threat detection in MVP.
* TLS decryption or application-layer inspection for encrypted HTTP in MVP.
* Cluster-wide coordination, distributed denylist sync, or multi-host management.
* GUI or web console.
* Windows or macOS support.

## Technical Notes

* Local repo inspection:
  * [`README.md`](E:/coding/github_projects/walle/README.md) is minimal and does not yet define product architecture.
  * There is no existing app code, so product decisions should be captured before scaffolding.

## Research Notes

### What similar tools / ecosystems do

* OpenSSH already includes source-based penalty controls such as `PerSourcePenalties`, `PerSourceMaxStartups`, and grouped source tracking via `PerSourceNetBlockSize`, which indicates that SSH abuse handling naturally separates detection events from source-based enforcement.
* XDP programs operate on packet data between `data` and `data_end` and are invoked on ingress packets with a context representing a single packet. This strongly favors simple packet-level decisions over stateful application-layer inspection.
* Cilium's documentation shows that HTTP layer 7 visibility is handled with L7 proxy support rather than plain XDP packet inspection, and TLS-aware HTTP visibility requires additional proxy/TLS integration rather than relying on raw XDP alone.

### Constraints from our project direction

* We want a CLI firewall product, not a generic observability system.
* We want high-performance enforcement, which points toward XDP for coarse-grained allow/drop decisions.
* We do not yet have code or a runtime architecture, so preserving extension points now is cheaper than retrofitting them later.
* The user has explicitly chosen MVP scope to be SSH mitigation plus ICMP control, while reserving HTTP-related IP decision inputs for later phases.

### Feasible approaches here

**Approach A: Split detection and enforcement** (Recommended)

* How it works:
  * Detect SSH abuse in user space using SSH-related signals, then push offending source IPs into denylist maps used by an XDP fast path for early drops.
  * Handle ICMP with direct XDP packet inspection and drop / allow decisions.
* Pros:
  * Fits the technical limits of XDP well.
  * Keeps SSH logic accurate while still getting high-performance blocking.
  * Makes future protocol-specific detection pluggable.
* Cons:
  * Requires multiple hook points instead of "everything in XDP".

**Approach B: Try to detect everything at XDP**

* How it works:
  * Use XDP to infer SSH abuse, ICMP policy, and HTTP maliciousness directly from ingress packets.
* Pros:
  * Conceptually simple story: one enforcement layer.
  * Fast path everywhere when it works.
* Cons:
  * Likely unrealistic for accurate SSH and HTTP threat classification.
  * Hard to support TLS or multi-packet context.
  * Higher risk of false positives and fragile heuristics.

## Expansion Sweep

### Future evolution

* Generalize from SSH-only denylist feeds to a reusable detector-to-map pipeline for multiple protocols.
* Reserve a rule-engine abstraction so later features can add TCP/UDP protocol filters without redesigning the CLI.

### Related scenarios

* IPv4 and IPv6 should be considered early because denylist semantics and ICMP handling differ.
* Users will likely expect allowlist, denylist, and status introspection commands to feel consistent across features.

### Failure & edge cases

* Regex matching at XDP may be too expensive or too constrained for safe MVP use.
* Payload-based ICMP rules must define whether matching applies to the full payload, decoded payload, or raw bytes.
* SSH bans need expiration / unban semantics to avoid permanent accidental lockouts.
* Mode switches must have deterministic precedence when an IP appears in both whitelist and blacklist.
* NAT and IP churn weaken source-IP identity for some SSH clients, but any replacement identifier must be evaluated for spoofability before it influences allow decisions.

## Decision (ADR-lite)

**Context**: The product needs high-performance enforcement but must start from a practical MVP with no existing codebase.

**Decision**: MVP scope is limited to SSH abuse mitigation and ICMP control. Enforcement is centered on eBPF/XDP maps and packet-path drop logic. SSH abuse detection is handled outside the XDP fast path, with the resulting IP decisions written into shared maps. HTTP is not an MVP detection target, but the architecture will reserve a future extension point so later HTTP detectors can publish IP allow/deny decisions into the same shared data plane. The first SSH policy is configurable fixed-threshold banning, while the policy model should leave room for escalation tiers and permanent bans. Access control is modeled as explicit runtime modes backed by a separate configuration map.
ICMP allow rules in MVP use exact raw-byte matching only, but the rule model should preserve a clean expansion path to future string and regex-based match types.

**Consequences**:

* The product story stays honest about what XDP can do well.
* We preserve the core performance value proposition by moving blocking decisions into XDP.
* We avoid overcommitting to fragile application-layer detection in the first version.
* We keep packet-path logic flexible enough to support future mode changes without replacing map layouts.
* We constrain first delivery to match types that are realistic in XDP while still reserving room for richer detectors and control-plane rule compilation later.

## Technical Approach

The current leading design is:

* Rust CLI for operator commands and lifecycle management.
* A user-space detector service for SSH abuse identification.
* Shared eBPF maps holding:
  * whitelist state
  * blacklist state and ban metadata
  * configuration state such as access-control mode and feature switches
* XDP program(s) that:
  * enforce source-IP allow / deny decisions
  * enforce ICMP drop / allow rules
  * remain generic enough for future detectors to reuse

For SSH detection, the first implementation should prefer stable user-space signal sources over trying to infer abuse from generic file-write activity. In practice, this means an event-driven user-space service that subscribes to `journald` or another append-style log source and extracts abusive source IPs, then updates the shared BPF maps. Later versions can evaluate whether more direct instrumentation of `sshd` or PAM hooks is worth the additional complexity.

Reading logs via eBPF is not the preferred MVP path. eBPF can attach to low-level hooks, but using it to observe generic file writes and reconstruct SSH authentication outcomes from raw log text would be indirect and brittle. The performance-sensitive win should come from XDP enforcement, while the detector should optimize for correctness and stable integration points.

For ICMP matching, the first version should define rule entries with an explicit match type field even if only `raw-bytes-exact` is initially supported. That keeps the control-plane schema and internal evaluator extensible when string or regex modes are added later.

## Access-Control Modes (draft)

Current intended modes:

* `whitelist-only`
  * only sources in whitelist are allowed
  * all other sources are dropped
* `blacklist-only`
  * sources in blacklist are dropped
  * all other sources are allowed
* `blacklist-with-whitelist-exception`
  * blacklist is active
  * whitelist has higher priority for explicit allow behavior

This implies at least one configuration map storing mode and feature toggles, plus separate data maps storing source-IP entries.

Conflict precedence decision:

* If the same IP exists in both whitelist and blacklist, whitelist wins.

## SSH Identity / Fingerprint Notes (draft)

Potential SSH-side identifiers fall into different trust levels:

* Source IP
  * easy to enforce in XDP
  * weak identity under NAT, IP churn, or shared egress
* SSH client implementation fingerprint
  * can be derived from pre-auth handshake properties such as the client identification string and algorithm negotiation behavior
  * useful as a heuristic or correlation signal
  * should not be treated as a strong device identity
* Client authentication key or certificate identity
  * much stronger than network fingerprinting
  * only available once the client attempts authenticated SSH identity mechanisms
  * not suitable as the sole basis for pre-auth fast-path allow decisions

Design implication:

* MVP data plane should remain IP-centric.
* If we later store SSH fingerprint-like signals, they should feed a detector-side reputation model or operator visibility, not unconditional XDP allow decisions.
* Automatic allowlisting solely because a new IP matches a previously seen client fingerprint is risky and should not be the default behavior.

## CLI Direction (draft)

The CLI should likely separate data-plane management from detector management, for example:

* `walle run`
* `walle status`
* `walle map list`
* `walle ban add <ip>`
* `walle ban remove <ip>`
* `walle ban list`
* `walle ssh protect enable`
* `walle ssh protect disable`
* `walle ssh policy set ...`
* `walle icmp drop enable`
* `walle icmp drop disable`
* `walle icmp allow add ...`
* `walle icmp allow list`
* `walle access-mode set <mode>`
* `walle access-mode get`
