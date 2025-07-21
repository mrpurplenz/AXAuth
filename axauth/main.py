import sys
from pathlib import Path
from axauth import protocol, crypto, axcall_wrapper
import configparser
import os
import readline
from axcall_wrapper import start_ax25_connection

USER_CONFIG_PATH = os.path.expanduser("~/.config/axauth/axauth.conf")
DEFAULT_CONFIG_PATH = "axauth/axauth_default.conf"

def load_config():
    config = configparser.ConfigParser()
    
    if os.path.exists(USER_CONFIG_PATH):
        config.read(USER_CONFIG_PATH)
        print(f"[info] Loaded config from {USER_CONFIG_PATH}")
    elif os.path.exists(DEFAULT_CONFIG_PATH):
        config.read(DEFAULT_CONFIG_PATH)
        print(f"[info] Loaded default config from {DEFAULT_CONFIG_PATH}")
    else:
        print("[warning] No config file found. Using built-in defaults.")
        config['axauth'] = {'mode': 'peer'}
    
    return config

def connect_to_peer(callsign):
    print(f"Connecting to {callsign}...")

    try:
        result = start_ax25_connection(callsign)
        return result  # Boolean True/False
    except Exception as e:
        print(f"Connection error: {e}")
        return False


def run_peer_terminal(local_call="N0CALL"):
    current_peer = None
    verified = False

    print(f"[{local_call}] AXAuth Terminal (peer mode). Type /exit to quit.")

    while True:
        prompt = f"[{current_peer or 'idle'}{'*' if verified else ''}] > "
        try:
            line = input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break



        if line.startswith("/exit"):
            print("Goodbye.")
            break
        elif line.startswith("/connect"):
            _, call = line.split(maxsplit=1)
            current_peer = call
            connect_to_peer(call)
            verified = True
            print(f"[info] Connected to {call} (verified).")
        elif line:
            print(f"[{local_call}] to [{current_peer}]: {line}")
        else:
            continue
def main():
    config = load_config()
    mode = config['axauth'].get('mode', 'peer').lower()
    local_call = config['axauth'].get('CALL', 'N0CALL').lower()
    if mode == 'peer':
        run_peer_terminal(local_call)
    else:
        print(f"Mode '{mode}' not yet implemented.")

def oldmain():
    if len(sys.argv) < 3:
        print("Usage: axauth <CALLSIGN> <message>")
        sys.exit(1)

    dest_call = sys.argv[1].upper()
    msg = sys.argv[2]

    priv_path = Path.home() / ".axauth" / "id_ed25519"
    pub_path = Path.home() / ".axauth" / "id_ed25519.pub"

    priv = crypto.load_private_key(priv_path)
    pub = crypto.load_public_key(pub_path)

    packet = protocol.AXAuthPacket(
        version=1,
        command="auth_request",
        payload={
            "message": msg,
            "pubkey": pub_path.read_bytes().hex()
        }
    )

    encoded = protocol.encode_packet(packet)
    sig = crypto.sign_message(priv, encoded)

    signed_payload = encoded + b"\n--SIGNATURE--\n" + sig

    response = axcall_wrapper.send_and_receive(dest_call, signed_payload)

    decoded = protocol.decode_packet(response)
    print("Received:", decoded)

if __name__ == "__main__":
    main()
