from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
import os

KEY_DIR = os.path.join(os.path.dirname(__file__), '../keys')
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, 'private.pem')
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, 'public.pem')

def load_private_key(path=PRIVATE_KEY_PATH):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

def load_public_key(path=PUBLIC_KEY_PATH):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def sign_message(message: bytes, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(message)

def verify_signature(message: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False

# Optional: quick CLI test
if __name__ == '__main__':
    message = b"test message"
    priv = load_private_key()
    pub = load_public_key()
    sig = sign_message(message, priv)
    assert verify_signature(message, sig, pub)
    print("✅ Signature verified.")
