from cryptography.hazmat.primitives.asymmetric import ed25519
from pathlib import Path

def load_private_key(path: Path) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(path.read_bytes())

def load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(path.read_bytes())

def sign_message(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)

def verify_signature(public_key: ed25519.Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False
