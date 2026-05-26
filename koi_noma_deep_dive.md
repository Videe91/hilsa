# How Protective We Will Be + How We Compare to Koi (as of May 26, 2026)

## Direct answer

We are building a platform designed to be **highly protective in real time**, not just informative:

- It verifies every agent identity,
- grants only short-lived permissions,
- evaluates each sensitive action before execution,
- and automatically contains suspicious chains across systems.

Compared to Koi, our goal is to go deeper into **transaction-level authorization and cross-system containment** for AI agent actions.

---

## 1) How protective this architecture can be

## What “protective” means in practice

Protection is not “we detected something later.”
Protection is “the risky step never completed.”

Our architecture protects at four layers:

1. **Pre-action prevention**
   - Policy decision before high-risk execution.
   - JIT scoped token required for each critical step.

2. **In-action control**
   - Allow with constraints (read-only, redaction, narrowed scope).
   - Step-up approvals for elevated actions.

3. **Post-action containment**
   - If a chain turns risky: revoke, quarantine, rotate, isolate.

4. **Recovery + proof**
   - Deterministic replay to prove what happened and why.

---

## Expected protection envelope (realistic)

If implemented well and integrated deeply, we should be able to achieve:

- Very high prevention on known high-risk patterns,
- Fast containment on novel multi-step chains,
- Strong blast-radius reduction even when one control fails,
- Better auditability than point tools.

What no vendor can promise:

- 100% prevention of all unknown attack paths.

So the goal is **defense-in-depth with rapid containment**, not perfection claims.

---

## Protection KPIs we should commit to

1. **Privileged action mediation rate**
   - Target: >90% of privileged agent actions mediated by policy + JIT.

2. **Mean time to detect (MTTD)**
   - Target: <30 seconds for validated high-risk behavior classes.

3. **Mean time to contain (MTTC)**
   - Target: <2 minutes for defined attack-chain scenarios.

4. **Cross-system chain interruption rate**
   - Target: >85% in recurring adversarial simulation tests.

5. **Enforcement false-positive rate**
   - Target: <2–3% in steady production environments.

6. **Standing credential reduction**
   - Target: large reduction in long-lived agent credentials in protected workflows.

These are the numbers that determine whether we are truly protective.

---

## 2) How we compare to Koi

## Where Koi is strong

Koi’s public positioning has been strong around:

- endpoint software/extension/package visibility,
- modern agentic endpoint risk identification,
- policy and control narratives tied to endpoint context.

That is meaningful strength, especially for endpoint-centric exposure.

---

## Our intended differentiation vs Koi

### Koi (publicly known orientation)

- Stronger orientation toward endpoint software risk and discovery/control at endpoint layer.

### Us (target orientation)

- Stronger orientation toward **transaction-level agent authorization** across endpoint + SaaS + cloud + MCP tools,
- Real-time step-level decisions before privileged execution,
- Cross-system automated containment as first-class architecture,
- Deterministic replay for incident proof and compliance evidence.

In short:

- **Koi:** “What risky software/agent surface exists and how do we govern it?”
- **Us:** “Should this exact agent action happen right now, and if risky, can we stop the full chain immediately?”

---

## Side-by-side (simple)

1. **Primary control point**
   - Koi: endpoint-centric control and visibility.
   - Us: per-action transaction control across systems.

2. **Main prevention unit**
   - Koi: software/entity risk and policy controls.
   - Us: action authorization with JIT scoped capability.

3. **Containment model**
   - Koi: endpoint/control-plane actions.
   - Us: cross-system revoke/quarantine/rollback orchestration.

4. **Proof layer**
   - Koi: risk and governance outputs.
   - Us: deterministic action replay + chain evidence.

---

## Where we should still keep parity with Koi

To win enterprise evaluations, we still need solid:

- discovery/inventory,
- endpoint context ingestion,
- policy UX,
- operational integrations.

Differentiation cannot excuse weak fundamentals.

---

## 3) Honest risk assessment

We only beat Koi if we execute on:

1. low-latency policy decisions,
2. reliable connectors across core enterprise systems,
3. low false-positive enforcement,
4. fast deployment and clear operator UX.

If we miss these, we become a strategy deck, not a protective platform.

---

## Final answer

How protective will we be? **Potentially very protective** if we hit the KPI targets above—because we are designed to prevent and contain in real time, not just observe.

How do we compare to Koi? **Koi is stronger in endpoint-centric agent software risk; we aim to be stronger in transaction-level, cross-system agent action control and containment.**
