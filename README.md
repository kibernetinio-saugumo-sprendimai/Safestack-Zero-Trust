# SafeStack Zero Trust

Local-first, autonomous policy decision engine for devices, users, resources, and actions across the SafeStack ecosystem.

It enforces **default deny**, checks cryptographic device posture gates, maintains an append-only decision audit ledger in SQLite, and provides Ed25519 cryptographic signing for policy bundles and telemetry assertions.

---

## Canonical Alignment & Governance

- **Ecosystem:** SafeStack Decentralized Security Framework
- **Root Canon Compliance:** [`safestack-canon`](https://github.com/kibernetinio-saugumo-sprendimai/safestack-canon) v1.0.0
- **Technical Canon Compliance:** [`safestack-technical-canon`](https://github.com/kibernetinio-saugumo-sprendimai/safestack-technical-canon) v1.0.0
- **Control Architecture:** Layer 5 (Identity & Access Control) in [`safestack-control-architecture`](https://github.com/kibernetinio-saugumo-sprendimai/safestack-control-architecture)
- **Project Identity:** Registered as `project-014` in [`safestack-project-public-keys`](https://github.com/kibernetinio-saugumo-sprendimai/safestack-project-public-keys)
  - Public Key: `riMRZ7qIs9V90nbjo61vB+qD/etrU/MYy6CnB7b1wMk=`
  - Key Fingerprint: `SHA256:8c7f6e91f092a482d3b250e97b8d5ea4302bc771b101346f8ba2d4ee460c7259`
- **Validation Registry:** [`safestack-validation-registry`](https://github.com/kibernetinio-saugumo-sprendimai/safestack-validation-registry)

---

## Architectural Principles

1. **Local-First Autonomy:** Evaluation occurs strictly on the local node. There are no central command-and-control dependencies or telemetry phone-home channels.
2. **Default Deny:** In the absence of an explicit matching allow policy, access is denied (`reason: default_deny`).
3. **Explicit Deny Precedence:** Any explicit deny policy matching the request immediately overrides any allow policy (`reason: explicit_deny`).
4. **Device Posture Gates:** Requests require the device posture (`compliant`, `degraded`, `unknown`) to meet or exceed the policy minimum.
5. **Cryptographic Discipline:** Ed25519 keys are used to sign and verify policy manifests and state attestations.

---

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Or install requirements:
```bash
pip install -r requirements.txt # cryptography>=42,<50
```

---

## CLI Usage

### 1. Register a Device
```bash
safestack-zt device-add --id laptop-1 --name "Workstation" --owner alice --posture compliant
```

### 2. Register a Policy
```bash
safestack-zt policy-add --effect allow --subject alice --resource vpn --action connect --min-posture compliant
```

### 3. Evaluate Authorization Request
```bash
safestack-zt authorize --device laptop-1 --subject alice --resource vpn --action connect
```
- Returns JSON decision with exit code `0` on allow, or exit code `2` on denial.

### 4. Cryptographic Keypair Generation & Signing
```bash
# Generate Ed25519 keypair
safestack-zt keygen node.key node.pub

# Sign an artifact or policy bundle
safestack-zt sign --key node.key --file policy.json --sig-out policy.json.sig

# Verify a signature
safestack-zt verify --key node.pub --file policy.json --sig policy.json.sig
```

---

## Testing

Run unit tests:
```bash
python3 -m unittest discover -s tests
```

---

## Threat Model

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for full trust boundary definitions, threat mitigations, and operational requirements.

---

## License

Released under the [MIT License](LICENSE).
