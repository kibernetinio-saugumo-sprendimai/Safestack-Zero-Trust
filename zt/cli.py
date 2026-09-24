import argparse
import base64
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .store import Store
from .engine import evaluate
from .signing import keygen, sign, verify


def main(argv=None):
    p = argparse.ArgumentParser(prog='safestack-zt', description='SafeStack Zero Trust Policy & Decision Engine')
    s = p.add_subparsers(dest='cmd', required=True)

    # device-add
    d = s.add_parser('device-add', help='Register a device')
    d.add_argument('--db', default='zero-trust.db')
    d.add_argument('--id', default=None)
    d.add_argument('--name', required=True)
    d.add_argument('--owner', required=True)
    d.add_argument('--posture', choices=['unknown', 'degraded', 'compliant'], default='unknown')

    # policy-add
    pol = s.add_parser('policy-add', help='Register an access policy')
    pol.add_argument('--db', default='zero-trust.db')
    pol.add_argument('--id', default=None)
    pol.add_argument('--effect', choices=['allow', 'deny'], required=True)
    pol.add_argument('--subject', required=True)
    pol.add_argument('--resource', required=True)
    pol.add_argument('--action', required=True)
    pol.add_argument('--min-posture', choices=['unknown', 'degraded', 'compliant'], default='compliant')

    # authorize
    e = s.add_parser('authorize', help='Evaluate access request against local policies')
    e.add_argument('--db', default='zero-trust.db')
    e.add_argument('--device', required=True)
    e.add_argument('--subject', required=True)
    e.add_argument('--resource', required=True)
    e.add_argument('--action', required=True)

    # keygen
    k = s.add_parser('keygen', help='Generate Ed25519 keypair for policy bundles')
    k.add_argument('private', help='Path to output private key file')
    k.add_argument('public', help='Path to output public key file')

    # sign
    sgn = s.add_parser('sign', help='Sign a payload or policy file')
    sgn.add_argument('--key', required=True, help='Path to private key')
    sgn.add_argument('--file', required=True, help='Path to file to sign')
    sgn.add_argument('--sig-out', help='Path to save signature (default: stdout)')

    # verify
    vrf = s.add_parser('verify', help='Verify a signature against a payload file')
    vrf.add_argument('--key', required=True, help='Path to public key')
    vrf.add_argument('--file', required=True, help='Path to file to verify')
    vrf.add_argument('--sig', required=True, help='Base64 signature or path to signature file')

    x = p.parse_args(argv)

    if x.cmd == 'keygen':
        keygen(x.private, x.public)
        print(f"Generated keypair: {x.private} (private), {x.public} (public)")
        return 0

    if x.cmd == 'sign':
        with open(x.file, 'rb') as f:
            data = f.read()
        sig_bytes = sign(data, x.key)
        b64_sig = base64.b64encode(sig_bytes).decode('ascii')
        if x.sig_out:
            with open(x.sig_out, 'w') as f:
                f.write(b64_sig + '\n')
            print(f"Signature written to {x.sig_out}")
        else:
            print(b64_sig)
        return 0

    if x.cmd == 'verify':
        with open(x.file, 'rb') as f:
            data = f.read()
        sig_str = x.sig.strip()
        if Path(sig_str).is_file():
            with open(sig_str, 'r') as f:
                sig_str = f.read().strip()
        try:
            sig_bytes = base64.b64decode(sig_str.encode('ascii'))
        except Exception:
            print("Invalid base64 signature format", file=sys.stderr)
            return 2
        is_valid = verify(data, sig_bytes, x.key)
        if is_valid:
            print("Signature valid")
            return 0
        else:
            print("Signature INVALID", file=sys.stderr)
            return 2

    db = Store(x.db)
    if x.cmd == 'device-add':
        dev_id = x.id or str(uuid.uuid4())
        db.add_device((dev_id, x.name, x.owner, x.posture, datetime.now(timezone.utc).isoformat()))
        print(f"device registered: {dev_id}")
        return 0

    if x.cmd == 'policy-add':
        pol_id = x.id or str(uuid.uuid4())
        db.add_policy((pol_id, x.effect, x.subject, x.resource, x.action, x.min_posture))
        print(f"policy registered: {pol_id}")
        return 0

    if x.cmd == 'authorize':
        result = evaluate(db, x.device, x.subject, x.resource, x.action)
        print(json.dumps(result.as_dict(), indent=2))
        return 0 if result.allowed else 2

    return 0


if __name__ == '__main__':
    sys.exit(main())
