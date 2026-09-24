# SafeStack Zero Trust — Threat Model & Trust Boundaries

## 1. Scope & Trust Boundaries

The primary trust boundary is the local node's policy store (`zero-trust.db`) and its local operator.
In accordance with the SafeStack Root Canon and Control Architecture:
- The node evaluates all intentions and access attempts locally.
- There are no central command-and-control backdoors or remote kill-switches.
- The observer layer is strictly read-only; no control commands can be injected via observer interfaces.

---

## 2. Threat Analysis & Mitigations

| Threat | Risk Level | Engine Mitigation |
| :--- | :--- | :--- |
| **Accidental Over-Permission** | High | Default deny is enforced globally; authorization requires explicit matching rules. |
| **Policy Ambiguity** | Medium | Explicit deny takes strict precedence over any allow policy matching the criteria. |
| **Compromised / Degraded Node** | High | Posture gating blocks devices with degraded or unknown health from compliant resources. |
| **Silent Policy Tampering** | High | Ed25519 cryptographic signing (`safestack-zt sign / verify`) ensures policy bundle integrity. |
| **Audit Log Repudiation** | Medium | All authorization decisions are committed in an append-only SQLite table with ISO-8601 UTC timestamps. |
| **Central C2 Takeover** | Critical | Architecturally eliminated: each node operates autonomously without remote execution pathways. |

---

## 3. Operational Requirements for Production

For hardened production deployments on SafeStack nodes (e.g. Raspberry Pi 5):
1. SQLite database files must reside on encrypted storage (LUKS / encrypted ext4) with file permissions restricted to `0600`.
2. Private signing keys must be protected with offline storage or hardware security module (HSM/TPM) isolation.
3. Node posture evaluations must incorporate hardware health telemetry (e.g. NVMe SMART status, Lynis audit score).
4. In the event of confirmed physical compromise or forced canonical violation, nodes execute Autonomy Severance (trust erasure and voluntary self-termination).
