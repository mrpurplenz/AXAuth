# axsocket.py
import ax25
import ax25.ports
import ax25.socket
import threading
import queue
import errno
import select
from blessed import Terminal
import json
from pathlib import Path
from typing import Optional
from crypto import load_private_key, sign_message

#KEYRING_PATH = Path.home() / ".config" / "axauth" / "keys.json"

#def load_keyring() -> dict[str, str]:
#    if not KEYRING_PATH.exists():
#        return {}
#    with open(KEYRING_PATH, 'r') as f:
#        return json.load(f)

#def get_public_key(callsign: str) -> str | None:
#    return keyring.get(callsign.upper())

class AX25Session:
    def __init__(self, sock, remote_call, local_call):
        self.sock = sock
        self.remote_call = remote_call
        self.local_call = local_call
        self.recv_queue = queue.Queue()
        self.running = True
        self.thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.thread.start()
        self.recv_queue.put(("info",f'[info] Connection from {local_call} to {remote_call} created'))
        #self.keyring = load_keyring()
        self.private_key = load_private_key()
    def is_signed(self, message: str) -> bool:
        self.recv_queue.put(("info","[info] Determining if received messaged is signed"))
        return "-----BEGIN CHATSIG-----" in message and "-----END CHATSIG-----" in message

    #def extract_signature_and_payload(message: str) -> tuple[str, str]:
    #    self.recv_queue.put(("info","[info] Extracting sig"))
    #    lines = message.splitlines()
    #    begin = lines.index("-----BEGIN CHATSIG-----")
    #    end = lines.index("-----END CHATSIG-----")
    #    signature = "\n".join(lines[begin+1:end]).strip()
    #    payload = "\n".join(lines[end+1:]).strip()
    #    return signature, payload

    #def get_public_key(callsign: str) -> Optional[str]:
    #    self.recv_queue.put(("info","[info] Getting public key"))
    #    # Replace this with real keyring lookup
    #    return self.keyring.get(callsign)

    def verify_signature(payload: str, signature: str, pubkey: str) -> bool:
        self.recv_queue.put(("info","[info] attempting signature verification"))
        try:
            decoded_sig = base64.b64decode(signature)
            verifier = nacl.signing.VerifyKey(pubkey, encoder=nacl.encoding.Base64Encoder)
            verifier.verify(payload.encode('utf-8'), decoded_sig)
            return True
        except Exception:
            return False

    def normalize_message(self, data: bytes) -> tuple[str, str]:
        text = data.decode("utf-8", errors="replace")
        normal_text = text.replace('\r\n', '\n').replace('\r', '\n').strip()
        #lines = normal_text.split('\n')
        if self.is_signed(normal_text):
            # Extract components
            try:
                signature, signed_payload = self.extract_signature_and_payload(normal_text)
            except ValueError:
                return [("recv_signed_failed_verification", "[error] Malformed signature block")]

             # Check if we know the sender's public key
            pubkey = self.get_public_key(self.remote_call)
            if not pubkey:
                lines = signed_payload.split('\n')
                result = []
                for line in lines:
                    result.append(("recv_signed_nopub", line))
                return result

            # Attempt to verify the signature
            if self.verify_signature(signed_payload, signature, pubkey):
                lines = signed_payload.split('\n')
                result = []
                for line in lines:
                    result.append(("recv_signed_verified", line))
                return result
            else:
                return [("recv_signed_failed_verification", "[error] Signature could not be verified")]
        else:
            lines = normal_text.split('\n')
            result = []
            for line in lines:
                result.append(("recv_unsigned", line))
            return result

    def has_queue(self):
        return not self.recv_queue.empty()

    def has_data(self):
        rlist, _, _ = select.select([self.sock], [], [], 0)  # non-blocking
        return bool(rlist)

    def recv_one(self, timeout=0.1):
        try:
            return self.recv_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _receive_loop(self):
        while self.running:
            try:
                data = self.sock.recv(1024)
                if not data:
                    self.recv_queue.put(("info","[info] Connection closed by remote."))
                    self.running = False
                    break
                messages = self.normalize_message(data)
                for message in messages:
                    self.recv_queue.put(message)
            except OSError as e:
                if e.errno == errno.ENOTCONN:
                    self.recv_queue.put(("info","[info] Remote disconnected (socket closed)."))
                else:
                    self.recv_queue.put(("info",f"[error] Receive error: {e}"))
                self.running = False
                break
            except Exception as e:
                self.recv_queue.put(("error",f"[error] Unexpected receive error: {e}"))
                self.running = False
                break

    def send(self, data):
        self.recv_queue.put(("info",f"[info] Send request received"))
        try:
            #self.recv_queue.put(("info",f"[info] Send request received"))
            self.sock.send(data)
        except Exception as e:
            self.recv_queue.put(("error",f"[error] Send {data} failed: {e}"))
    def send_signed(self, data):
        self.recv_queue.put(("info",f"[info] Signed send request received"))

        # Sign the data
        signature = sign_message(data, self.private_key)

        # Wrap it in a standard format
        # We'll use a simple signature block format for now
        signed_payload = (
            b"-----BEGIN CHATSIG-----\n"
            + signature.hex().encode() + b"\n"
            + b"-----END CHATSIG-----\n"
            + data
        )

        # Send the signed payload
        try:
            self.sock.send(signed_payload)

        except Exception as e:
            self.recv_queue.put(("error",f"[error] Send {data} failed: {e}"))

    def close(self):
        self.running = False
        self.sock.close()


def start_ax25_socket_connection(local_call: str, remote_call: str) -> AX25Session:
    s = ax25.socket.Socket()
    try:
        s.bind(local_call, "ax25")
    except Exception as e:
        raise RuntimeError(f"Failed to bind socket to {local_call}: {e}")

    try:
        result = s.connect_ex(remote_call)
        if result != 0:
            raise RuntimeError(f"Connection failed with result code {result}")
    except Exception as e:
        raise RuntimeError(f"Failed to connect socket to {remote_call}: {e}")
    
    return AX25Session(sock=s, local_call=local_call, remote_call=remote_call)

