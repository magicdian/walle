# Cross-Layer Thinking Guide

> **Purpose**: Think through data flow across layers before implementing.

---

## The Problem

**Most bugs happen at layer boundaries**, not within layers.

Common cross-layer bugs:
- API returns format A, frontend expects format B
- Database stores X, service transforms to Y, but loses data
- Multiple layers implement the same logic differently

---

## Before Implementing Cross-Layer Features

### Step 1: Map the Data Flow

Draw out how data moves:

```
Source → Transform → Store → Retrieve → Transform → Display
```

For each arrow, ask:
- What format is the data in?
- What could go wrong?
- Who is responsible for validation?

### Step 2: Identify Boundaries

| Boundary | Common Issues |
|----------|---------------|
| API ↔ Service | Type mismatches, missing fields |
| Service ↔ Database | Format conversions, null handling |
| Backend ↔ Frontend | Serialization, date formats |
| Component ↔ Component | Props shape changes |

### Step 3: Define Contracts

For each boundary:
- What is the exact input format?
- What is the exact output format?
- What errors can occur?

---

## Common Cross-Layer Mistakes

### Mistake 1: Implicit Format Assumptions

**Bad**: Assuming date format without checking

**Good**: Explicit format conversion at boundaries

### Mistake 2: Scattered Validation

**Bad**: Validating the same thing in multiple layers

**Good**: Validate once at the entry point

### Mistake 3: Leaky Abstractions

**Bad**: Component knows about database schema

**Good**: Each layer only knows its neighbors

### Mistake 4: Assuming Signal Exit Behaves Like Normal Return

**Bad**: Relying on process exit after `Ctrl+C` and assuming kernel hooks, background listeners, or pinned runtime state will clean themselves up.

**Good**: Treat signal handling as part of the cross-layer contract when user-space manages kernel or network resources. Define how shutdown requests propagate from OS signal -> control loop -> resource teardown.

### Mistake 5: Treating Kernel Error Codes As Stable Across Attach Paths

**Bad**: Hard-coding one errno interpretation (for example only `ENOTSUP`) and assuming all kernels/drivers report unsupported capabilities the same way.

**Good**: Define an explicit errno-classification contract at the user-space/kernel boundary (for example mode-not-supported set for XDP driver attach), and validate fallback behavior against each accepted errno variant.

---

## Checklist for Cross-Layer Features

Before implementation:
- [ ] Mapped the complete data flow
- [ ] Identified all layer boundaries
- [ ] Defined format at each boundary
- [ ] Decided where validation happens
- [ ] If packet handling spans multiple hook points such as XDP and tc, verified the execution order and ensured earlier hooks do not block later redirect/translation steps
- [ ] If boundary handling depends on OS/kernel errno values, defined an explicit classification matrix and fallback behavior for each accepted errno

After implementation:
- [ ] Tested with edge cases (null, empty, invalid)
- [ ] Verified error handling at each boundary
- [ ] Checked data survives round-trip
- [ ] For mixed enforcement states like deny + contain, verified precedence with tests in the earliest hook that can short-circuit traffic
- [ ] If user-space owns kernel hooks, listeners, or pinned runtime state, verified `SIGINT` / `SIGTERM` takes the same cleanup path as an ordinary graceful return

---

## When to Create Flow Documentation

Create detailed flow docs when:
- Feature spans 3+ layers
- Multiple teams are involved
- Data format is complex
- Feature has caused bugs before
