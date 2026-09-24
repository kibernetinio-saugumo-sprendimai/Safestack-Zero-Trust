import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


def keygen(private_path: str, public_path: str) -> None:
    """Generate Ed25519 keypair and save to specified file paths."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    
    priv_file = Path(private_path)
    pub_file = Path(public_path)
    
    priv_file.parent.mkdir(parents=True, exist_ok=True)
    pub_file.parent.mkdir(parents=True, exist_ok=True)
    
    priv_bytes = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(priv_file, 'wb') as f:
        f.write(priv_bytes)
    os.chmod(priv_file, 0o600)
    
    with open(pub_file, 'wb') as f:
        f.write(pub_bytes)


def sign(data: bytes, private_path: str) -> bytes:
    """Sign data bytes using an Ed25519 private key file."""
    with open(private_path, 'rb') as f:
        sk = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("Private key must be Ed25519")
    return sk.sign(data)


def verify(data: bytes, signature: bytes, public_path: str) -> bool:
    """Verify data signature using an Ed25519 public key file."""
    try:
        with open(public_path, 'rb') as f:
            pk = serialization.load_pem_public_key(f.read())
        if not isinstance(pk, Ed25519PublicKey):
            return False
        pk.verify(signature, data)
        return True
    except Exception:
        return False
