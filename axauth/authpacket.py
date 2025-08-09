import os
import json
import base64
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Constants
PROTOCOL_VERSION = "1.0"
BEGIN_MARKER = "-----BEGIN CHATTERVOX SIGNED MESSAGE-----"
END_MARKER = "-----END CHATTERVOX SIGNED MESSAGE-----"
#KEY PATHS should have a single default location found in say crypto but be checked from config file
KEYRING_PATH = os.path.expanduser("~/.chattervox/known_keys.json")
KEY_DIR = os.path.join(os.path.dirname(__file__), '../keys')
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, 'private.pem')

class AuthPacket:
    def __init__(self, callsign: str, message: str, version: str = PROTOCOL_VERSION):
        self.callsign = callsign
        self.message = message
        self.version = version
        self.signature_b64 = None  # base64 encoded

    def sign(self, private_key: Ed25519PrivateKey):
        data = self._signing_string().encode("utf-8")
        signature = private_key.sign(data)
        self.signature_b64 = base64.b64encode(signature).decode("utf-8")

    def has_signature(self):
        return self.signature_b64 is not None

    def has_public_key(self):
        keyring = load_keyring()
        return self.callsign.upper() in keyring

    def is_valid(self, public_key: Ed25519PublicKey) -> bool:
        if not self.signature_b64:
            return False
        data = self._signing_string().encode("utf-8")
        try:
            public_key.verify(base64.b64decode(self.signature_b64), data)
            return True
        except InvalidSignature:
            return False

    def _signing_string(self) -> str:
        return f"ver:{self.version}\nfrom:{self.callsign}\nmsg:\n{self.message.strip()}"

    def to_data(self, signed: bool):
        text = self.to_text(signed)
        return text.encode("utf-8")

    def to_text(self, signed: bool) -> str:
        if signed:
            self.sign(load_private_key(PRIVATE_KEY_PATH))
            if not self.signature_b64:
                raise ValueError("Message must be signed before exporting.")
            return (
                f"{BEGIN_MARKER}\n"
                f"ver:{self.version}\n"
                f"sig:{self.signature_b64}\n"
                f"from:{self.callsign}\n"
                f"msg:\n{self.message.strip()}\n"
                f"{END_MARKER}\n"
            )
        else:
            return f"{self.message.strip()}\n"

    @classmethod
    def from_text(cls, text: str):
        if not text.strip().startswith(BEGIN_MARKER) or not text.strip().endswith(END_MARKER):
            pkt = cls(
                callsign=None,
                message=text.strip(),
                version=PROTOCOL_VERSION,
            )
            pkt.signature_b64 = None
            return pkt

        lines = text.strip().splitlines()
        header_data = {}
        message_lines = []
        in_msg = False

        for line in lines[1:-1]:
            if in_msg:
                message_lines.append(line)
            elif line.startswith("ver:"):
                header_data["version"] = line[4:].strip()
            elif line.startswith("sig:"):
                header_data["signature"] = line[4:].strip()
            elif line.startswith("from:"):
                header_data["callsign"] = line[5:].strip()
            elif line.startswith("msg:"):
                in_msg = True
            else:
                continue

        pkt = cls(
            callsign=header_data.get("callsign", ""),
            message="\n".join(message_lines),
            version=header_data.get("version", PROTOCOL_VERSION),
        )
        pkt.signature_b64 = header_data.get("signature") 
        return pkt

    @classmethod
    def from_data(cls, data: bytes):
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            text = data.decode('utf-8', errors='replace')

        if not text.strip().startswith(BEGIN_MARKER) or not text.strip().endswith(END_MARKER):
            # Unsigned message — construct with defaults, set signature later
            pkt = cls(
                callsign=None,
                message=text.strip(),
                version=PROTOCOL_VERSION
            )
            pkt.signature_b64 = None
            return pkt
        return cls.from_text(text)

    def check_version(self):
        if self.version != PROTOCOL_VERSION:
            raise ValueError(f"Incompatible protocol version: {self.version}")


# === Key Loading Utilities ===

def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_keyring() -> dict:
    if not os.path.exists(KEYRING_PATH):
        return {}
    with open(KEYRING_PATH, "r") as f:
        return json.load(f)


def save_keyring(keyring: dict):
    os.makedirs(os.path.dirname(KEYRING_PATH), exist_ok=True)
    with open(KEYRING_PATH, "w") as f:
        json.dump(keyring, f, indent=2)


def get_public_key_from_keyring(callsign: str) -> Optional[Ed25519PublicKey]:
    keyring = load_keyring()
    pub_b64 = keyring.get(callsign.upper())
    if not pub_b64:
        return None
    key_bytes = base64.b64decode(pub_b64)
    return serialization.load_der_public_key(key_bytes)


def add_public_key_to_keyring(callsign: str, pubkey: Ed25519PublicKey):
    keyring = load_keyring()
    key_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    keyring[callsign.upper()] = base64.b64encode(key_bytes).decode("utf-8")
    save_keyring(keyring)
