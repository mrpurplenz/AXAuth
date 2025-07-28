import sys
from pathlib import Path
from axauth import protocol, crypto, axcall_wrapper
import configparser
import os
import readline
from axsocket import start_ax25_socket_connection
from blessed import Terminal
import time

VERSION = 1.0
USER_CONFIG_PATH = os.path.expanduser("~/.config/axauth/axauth.conf")
DEFAULT_CONFIG_PATH = "axauth/axauth_default.conf"

term = Terminal()

# Define fixed zone heights (Y = number of rows, X = terminal width)
HEADER_Y       = 1
SEPARATOR_Y    = 1
LOG_Y          = 6  # Lines reserved for the input log
PROMPT_Y       = 1

# Terminal width (constant across zones)
HEADER_X       = term.width
SEPARATOR_X    = term.width
LOG_X          = term.width
PROMPT_X       = term.width

# Dynamically compute available height for messages
MESSAGES_Y     = term.height - (HEADER_Y + SEPARATOR_Y + LOG_Y + PROMPT_Y)
MESSAGES_X     = term.width

HEADER_START_Y     = 0
MESSAGE_START_Y    = HEADER_START_Y + HEADER_Y
SEPARATOR_START_Y  = MESSAGE_START_Y + MESSAGES_Y
INPUT_LOG_START_Y  = SEPARATOR_START_Y + SEPARATOR_Y
PROMPT_START_Y     = INPUT_LOG_START_Y + LOG_Y

def draw_header(current_peer = None, signing_enabled = True):
    call_label = current_peer or '-------- '
    signing_label = "Signing"+term.green+" ON" if signing_enabled else "signing" + term.red+" OFF"
    full_label = f" {call_label} | AXAuth by ZL2DRS | {signing_label}"

    # Compute visible widths
    label_len = len(full_label)

    spacer_len = max(0, HEADER_X - label_len)+1
    if signing_enabled:
         spacer_len += 15
    spacer = " " * spacer_len

    # Build the header in parts with white background
    base_header = (
        term.on_white + term.black +
        full_label + spacer
    )

    # Ensure we only print up to terminal width
    print(term.move_yx(0, 0) + base_header[:(HEADER_X+15)] + term.normal)

def draw_messages(messages):
    for i, msg in enumerate(messages[-MESSAGES_Y:]):
        
        print(term.move_yx(2 + i, 0) + term.clear_eol + msg.ljust(MESSAGES_X))

def draw_input_log(input_log):
    for i, line in enumerate(input_log[-LOG_Y:]):
        y = term.height - 3 - LOG_Y + i
        print(term.move_yx(y, 0) + term.clear_eol + f"> {line}")

def draw_separator():
    print(term.move_yx(SEPARATOR_START_Y, 0) + term.normal + '-' * SEPARATOR_X)

def draw_prompt(current_peer):
    prompt = f"{current_peer or 'unproto'}> "
    print(term.move_yx(PROMPT_START_Y, 0) + term.clear_eol + prompt, end='', flush=True)
    # Move cursor to after prompt
    print(term.move_yx(PROMPT_START_Y, len(prompt)), end='', flush=True)
    return len(prompt)

def run_peer_terminal(local_call="N0CALL"):
    current_peer = None
    verified = False
    session = None
    signing_enabled = True  # Toggle with /sign

    messages = []
    input_log = []

    with term.fullscreen(), term.cbreak():
        print(term.clear)
        input_dirty = True
        clean_input = ''
        inp=''
        while True:
            draw_header(current_peer, signing_enabled)
            #drain the session thread
            if session and session.has_queue():
                while session and session.has_queue():
                    incoming = session.recv_one()
                    if incoming:
                        messages.append(incoming)
            draw_messages(messages)
            #update separator
            draw_separator()
            # Initialise prompt 
            prompt_len = draw_prompt(current_peer)
            # Input handling
            if not input_dirty:
                inp = ''
            while True:
                ch = term.inkey(timeout=0.1)
                input_dirty=True
                if ch.name == 'KEY_ENTER':
                    input_dirty=False
                    break
                elif ch.name == 'KEY_BACKSPACE':
                    if inp:
                        inp = inp[:-1]
                        print(
                            term.move_x(prompt_len) +
                            inp.ljust(term.width - prompt_len),  # pad with spaces to erase leftovers
                            end='',
                            flush=True
                        )
                        print(term.move_x(prompt_len + len(inp)), end='', flush=True)
                elif ch.is_sequence:
                    continue
                else:
                    inp += ch
                    print(ch, end='', flush=True)
            if not input_dirty:
                line = inp.strip()
                if line == "/exit":
                    if session:
                        session.close()
                    messages.append("Goodbye.")
                    break
                elif line.startswith("/connect"):
                    try:
                        _, call = line.split(maxsplit=1)
                    except ValueError:
                        messages.append(term.red + "[error] Usage: /connect CALLSIGN" + term.normal)
                        continue
                    current_peer = call
                    #session = ("socket_object", "thread_obj")  # placeholder
                    session = connect_to_peer(local_call, call)
                    draw_header(current_peer, signing_enabled)
                    messages.append(term.cyan + f"[info] Connected to {call}" + term.normal)
                elif line.startswith("/sign"):
                    try:
                        _, state = line.split(maxsplit=1)
                        if state.lower() == "on":
                            signing_enabled = True
                            #CODE TO ENABLE SIGNING GOES HERE
                        elif state.lower() == "off":
                            signing_enabled = False
                            #CODE TO DISABLE SIGNING GOES HERE
                        else:
                            raise ValueError
                    except ValueError:
                        messages.append(term.red + "[error] Usage: /sign on|off" + term.normal)
                        continue
                    draw_header(current_peer, signing_enabled)
                    messages.append(term.cyan + f"[info] Signing {'enabled' if signing_enabled else 'disabled'}" + term.normal)
                elif line and session:
                    #Sending data to the connected session
                    if signing_enabled:
                        ###attempt to sign the line here or return error
                        try:
                            session.send((line+"\r").encode("utf-8"))
                            messages.append(term.green + f"[>{current_peer or 'unproto'}] {line}" + term.normal)
                        except BrokenPipeError:
                            messages.append(term.red +f("[error] Connection lost."))
                            session = None
                            current_peer = None
                            draw_header(current_peer, session, signing_enabled)
                    else:
                        try:
                            session.send((line+"\r").encode("utf-8"))
                            messages.append(term.white + f"[>{current_peer or 'unproto'}] {line}" + term.normal)
                        except BrokenPipeError:
                            messages.append(term.red +f("[error] Connection lost.") + term.normal)
                            session = None
                            current_peer = None
                            draw_header(current_peer, session, signing_enabled)
                elif line:
                    #Sending text as unproto (NOT YET IMPLIMENTED)
                    #TRY TO SEND UNPROTO MESSAGE THEN IF SUCCESSFUL POST THE FOLLOWING LINE
                    messages.append(term.white + f"[>{current_peer or 'unproto'}] {line}" + term.normal)
                    #IF unproto message not possible post the following warning
                    messages.append(term.yellow + "[warn] Unproto not available yet and no active session. Enable unproto or /connect CALLSIGN first." + term.normal)
                # Clear message area before re-render NEEDS ADJUSTING WITH NEW DYNAMIC ZONE SIZE CONSTANTS
                for y in range(2, term.height - 2):
                    print(term.move_yx(y, 0) + term.clear_eol)



def depriloop():
    inp = ''
    last_inp = None
    while True:
        #print(term.clear)

        #Update header
        draw_header(current_peer, signing_enabled)

        # Drain the session thread queue
        if session and session.has_queue():
            while session.has_queue():
                incoming = session.recv_one()
                if incoming:
                    messages.append(incoming)

        draw_messages(messages)
        draw_separator()
        prompt_len = draw_prompt(current_peer)

        # Poll for key input without blocking everything else
        ch = term.inkey(timeout=1)

        # Update prompt and rerender if input key depressed
        if inp != last_inp:
            print(term.move_x(prompt_len) + inp.ljust(term.width - prompt_len), end='', flush=True)
            print(term.move_x(prompt_len + len(inp)), end='', flush=True)
            last_inp = inp

        if ch:
            if ch.name == 'KEY_ENTER':
                line = inp.strip()
                inp = ''  # Reset input buffer

                if line == "/exit":
                    if session:
                        session.close()
                    messages.append("Goodbye.")
                    break

                elif line.startswith("/connect"):
                    try:
                        _, call = line.split(maxsplit=1)
                        current_peer = call
                        session = connect_to_peer(local_call, call)
                        messages.append(term.cyan + f"[info] Connected to {call}" + term.normal)
                    except ValueError:
                        messages.append(term.red + "[error] Usage: /connect CALLSIGN" + term.normal)

                elif line.startswith("/sign"):
                    try:
                        _, state = line.split(maxsplit=1)
                        if state.lower() == "on":
                            signing_enabled = True
                        elif state.lower() == "off":
                            signing_enabled = False
                        else:
                            raise ValueError
                        messages.append(term.cyan + f"[info] Signing {'enabled' if signing_enabled else 'disabled'}" + term.normal)
                    except ValueError:
                        messages.append(term.red + "[error] Usage: /sign on|off" + term.normal)

                elif line and session:
                    try:
                        session.send((line + "\r").encode("utf-8"))
                        tag = "[>" + (current_peer or "unproto") + "]"
                        color = term.green if signing_enabled else term.white
                        messages.append(color + f"{tag} {line}" + term.normal)
                    except BrokenPipeError:
                        messages.append(term.red + "[error] Connection lost." + term.normal)
                        session = None
                        current_peer = None

                elif line:
                    messages.append(term.white + f"[>{current_peer or 'unproto'}] {line}" + term.normal)
                    messages.append(term.yellow + "[warn] Unproto not available yet and no active session." + term.normal)

                # Clear message area before re-render
                for y in range(2, term.height - 2):
                    print(term.move_yx(y, 0) + term.clear_eol)

            elif ch.name == 'KEY_BACKSPACE':
                if inp:
                    inp = inp[:-1]
                    print(term.move_x(prompt_len) + inp.ljust(term.width - prompt_len), end='', flush=True)
                    print(term.move_x(prompt_len + len(inp)), end='', flush=True)

            elif not ch.is_sequence:
                inp += ch
                print(ch, end='', flush=True)



def load_config():
    config = configparser.ConfigParser()
    
    if os.path.exists(USER_CONFIG_PATH):
        config.read(USER_CONFIG_PATH)
        #print(f"[info] Loaded config from {USER_CONFIG_PATH}")
    elif os.path.exists(DEFAULT_CONFIG_PATH):
        config.read(DEFAULT_CONFIG_PATH)
        #print(f"[info] Loaded default config from {DEFAULT_CONFIG_PATH}")
    else:
        print("[warning] No config file found. Using built-in defaults.")
        config['axauth'] = {'mode': 'peer'}
    
    return config

def connect_to_peer(local_call, remote_call):
    try:
        session = start_ax25_socket_connection(local_call, remote_call)
        #messages.append(f"[info] Session established: {session}")
        #recv_thread = start_terminal_session(sock)
        return session
    except Exception as e:
        #print(f"Connection error: {e}")
        return None

    #thread = start_terminal_session(sock)
    #return (sock, thread), True

def main():
    print(f"ZL2DRS AX.25auth Connect v{VERSION}")
    print(f"Trying...")
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
