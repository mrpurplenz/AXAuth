import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os

KEY_DIR = os.path.join(os.path.dirname(__file__), '../keys')
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, 'private.pem')
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, 'public.pem')

os.makedirs(os.path.dirname(PRIVATE_KEY_PATH), exist_ok=True)

def generate_keypair():
    private_key = Ed25519PrivateKey.generate()

    # Save private key
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"✅ Keypair generated:\n  🔑 Private: {PRIVATE_KEY_PATH}\n  📢 Public:  {PUBLIC_KEY_PATH}")

if __name__ == '__main__':
    generate_keypair()
