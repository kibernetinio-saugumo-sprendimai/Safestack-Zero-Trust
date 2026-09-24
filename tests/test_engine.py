import os
import sys
from pathlib import Path
import tempfile
import unittest

# Ensure zt package is importable regardless of working directory
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zt.store import Store
from zt.engine import evaluate
from zt.signing import keygen, sign, verify
from zt.cli import main


class EngineTests(unittest.TestCase):
    def test_default_deny_and_allow(self):
        with tempfile.NamedTemporaryFile() as f:
            db = Store(f.name)
            db.add_device(('d1', 'laptop', 'alice', 'compliant', 'now'))
            self.assertFalse(evaluate(db, 'd1', 'alice', 'vpn', 'connect').allowed)
            db.add_policy(('p1', 'allow', 'alice', 'vpn', 'connect', 'compliant'))
            self.assertTrue(evaluate(db, 'd1', 'alice', 'vpn', 'connect').allowed)

    def test_posture_blocks(self):
        with tempfile.NamedTemporaryFile() as f:
            db = Store(f.name)
            db.add_device(('d1', 'laptop', 'alice', 'degraded', 'now'))
            db.add_policy(('p1', 'allow', 'alice', 'vpn', 'connect', 'compliant'))
            res = evaluate(db, 'd1', 'alice', 'vpn', 'connect')
            self.assertFalse(res.allowed)
            self.assertEqual(res.reason, 'device_posture_below_policy')

    def test_explicit_deny_precedence(self):
        with tempfile.NamedTemporaryFile() as f:
            db = Store(f.name)
            db.add_device(('d1', 'laptop', 'alice', 'compliant', 'now'))
            db.add_policy(('p1', 'allow', 'alice', 'vpn', 'connect', 'compliant'))
            db.add_policy(('p2', 'deny', 'alice', 'vpn', 'connect', 'compliant'))
            res = evaluate(db, 'd1', 'alice', 'vpn', 'connect')
            self.assertFalse(res.allowed)
            self.assertEqual(res.reason, 'explicit_deny')

    def test_unregistered_device(self):
        with tempfile.NamedTemporaryFile() as f:
            db = Store(f.name)
            res = evaluate(db, 'unknown-device', 'alice', 'vpn', 'connect')
            self.assertFalse(res.allowed)
            self.assertEqual(res.reason, 'device_not_registered')

    def test_signing_and_verification(self):
        with tempfile.TemporaryDirectory() as td:
            priv_p = os.path.join(td, 'test.key')
            pub_p = os.path.join(td, 'test.pub')
            keygen(priv_p, pub_p)
            self.assertTrue(os.path.exists(priv_p))
            self.assertTrue(os.path.exists(pub_p))

            payload = b"SafeStack Zero Trust Canonical Test Data"
            signature = sign(payload, priv_p)
            self.assertTrue(verify(payload, signature, pub_p))
            self.assertFalse(verify(b"Tampered Data", signature, pub_p))

    def test_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            db_p = os.path.join(td, 'test.db')
            self.assertEqual(main(['device-add', '--db', db_p, '--id', 'dev-1', '--name', 'node1', '--owner', 'operator', '--posture', 'compliant']), 0)
            self.assertEqual(main(['policy-add', '--db', db_p, '--id', 'pol-1', '--effect', 'allow', '--subject', 'operator', '--resource', 'node', '--action', 'sync', '--min-posture', 'compliant']), 0)
            self.assertEqual(main(['authorize', '--db', db_p, '--device', 'dev-1', '--subject', 'operator', '--resource', 'node', '--action', 'sync']), 0)
            # Unauthorized action should exit 2
            self.assertEqual(main(['authorize', '--db', db_p, '--device', 'dev-1', '--subject', 'operator', '--resource', 'node', '--action', 'reboot']), 2)


if __name__ == '__main__':
    unittest.main()
