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
def render_terminal(current_peer, signing_enabled, message_stack, log_stack, term):

    message_colour_map = {
        "info": term.cyan,
        "error": term.red,
        "warn": term.yellow,
        "send_signed": term.green,
        "send_unsigned": term.white,
        "recv_unsigned": term.yellow,
        "recv_signed_nopub": term.orange,
        "recv_signed_failed_verification": term.red,
        "recv_verified": term.green,
        "system": term.magenta
    }
    log_colour_map = {
        "unconnected_not_signing": term.orange,
        "unconnected_signing": term.yellow,
        "connected_not_signing": term.orange,
        "connected_signing": term.green
    }

    CURRENT_TERM_WIDTH  = term.width
    CURRENT_TERM_HEIGHT = term.height

    # Define fixed zone heights (Y = number of rows, X = terminal width)
    HEADER_Y       = 1
    SEPARATOR_Y    = 1
    LOG_Y          = 6  # Lines reserved for the input log
    PROMPT_Y       = 1

    # Terminal width (constant across zones)
    HEADER_X       = CURRENT_TERM_WIDTH
    SEPARATOR_X    = CURRENT_TERM_WIDTH
    LOG_X          = CURRENT_TERM_WIDTH
    PROMPT_X       = CURRENT_TERM_WIDTH

    # Dynamically compute available height for messages
    MESSAGES_Y     = CURRENT_TERM_HEIGHT - (HEADER_Y + SEPARATOR_Y + LOG_Y + PROMPT_Y)
    MESSAGES_X     = CURRENT_TERM_WIDTH

    HEADER_START_Y     = 0
    MESSAGE_START_Y    = HEADER_START_Y + HEADER_Y
    SEPARATOR_START_Y  = MESSAGE_START_Y + MESSAGES_Y
    LOG_START_Y        = SEPARATOR_START_Y + SEPARATOR_Y
    PROMPT_START_Y     = LOG_START_Y + LOG_Y

    def draw_header(current_peer = None, signing_enabled = True):
        call_label = current_peer or ' -------- '
        signing_colour = term.red
        sign_string = "OFF"
        if signing_enabled:
            signing_colour = term.green
            sign_string = "ON"
        author_string = "| AXAuth by ZL2DRS | Signing "
        header_text_len = len(call_label + author_string + sign_string)
        print(term.move_yx(0,0) + term.on_white + term.black + call_label + author_string + signing_colour + sign_string + term.clear_eol)

    from textwrap import wrap

    def draw_message_stack(message_stack):
        print(term.move_yx(0, 0))
        visible_rows = []

        # First, wrap each message into lines that fit terminal width
        for msgt in message_stack:
            status, text = msgt
            #prefix = f"{callsign}: "
            ansi_colour = message_colour_map[status]

            # Wrap text (taking prefix into account for first line)
            wrapped_lines = wrap(text, width=MESSAGES_X)
            if not wrapped_lines:
                wrapped_lines = [""]

            # Build first and subsequent lines
            first_line = ansi_colour +  wrapped_lines[0]
            other_lines = [ansi_colour + line for line in wrapped_lines[1:]]

            #Restack the now-wrapped messages
            visible_rows.extend([first_line] + other_lines)

        # Trim to fit available space
        rows_to_draw = visible_rows[-MESSAGES_Y:]

        # Now render the lines on screen
        for i, line in enumerate(rows_to_draw):
            print(term.move_yx(MESSAGE_START_Y + i, 0) + term.normal + term.clear_eol + line.ljust(MESSAGES_X))

    def draw_log_stack(log_stack):
        print(term.move_yx(0, 0))

        num_log_lines = min(len(log_stack), LOG_Y)
        num_blank_lines = LOG_Y - num_log_lines  # Always ≥ 0

        # Clear and print blank lines first
        for i in range(num_blank_lines):
            print(term.move_yx(LOG_START_Y + i, 0) + term.clear_eol)

        # Now print the most recent log lines, bottom-aligned
        recent_logs = log_stack[-num_log_lines:]
        for i, logt in enumerate(recent_logs):
            ansi_colour = log_colour_map.get(logt[0], term.normal)
            line_y = LOG_START_Y + num_blank_lines + i
            print(term.move_yx(line_y, 0) + term.clear_eol + ansi_colour + logt[1].ljust(MESSAGES_X))

    def draw_separator():
        print(term.move_yx(0,0))
        print(term.move_yx(SEPARATOR_START_Y, 0) + term.normal + '-' * SEPARATOR_X)

    def draw_prompt(current_peer,signing_enabled):
        print(term.move_yx(0,0))
        prompt = f"{current_peer or 'unproto'}> "
        if current_peer:
            if signing_enabled:
                prompt_status = "connected_signing"
            else:
                prompt_status = "connected_not_signing"
        else:
            if signing_enabled:
                prompt_status = "unconnected_signing"
            else:
                prompt_status = "unconnected_not_signing"
        ansi_colour = log_colour_map.get(prompt_status, term.normal)
        print(term.move_yx(PROMPT_START_Y, 0)  + ansi_colour + prompt, end='', flush=True)
        # Move cursor to after prompt
        print(term.move_yx(PROMPT_START_Y, len(prompt)), end='', flush=True)
        return len(prompt)

    #Conduct rendering in turn
    draw_header(current_peer, signing_enabled)
    draw_message_stack(message_stack)
    draw_separator()
    draw_log_stack(log_stack)
    prompt_len = draw_prompt(current_peer,signing_enabled)

    return prompt_len, PROMPT_START_Y

def render_input_buffer(input_buffer, prompt_len, displayed_input, PROMPT_START_Y):
    if input_buffer != displayed_input:
        print(term.move_yx(0,0))
        print(term.move_yx(PROMPT_START_Y, prompt_len) + input_buffer + term.clear_eol, end='', flush=True)
        displayed_input = input_buffer
    return displayed_input


def fetch_input(input_buffer):
    process_flag = False
    ch = term.inkey(timeout=0.1)
    if ch.name == 'KEY_ENTER':
        process_flag = True
    elif ch.name == 'KEY_BACKSPACE':
        if input_buffer:
            input_buffer = input_buffer[:-1]
    elif ch.is_sequence:
        pass
        #continue
    else:
        input_buffer += ch
    return input_buffer, process_flag

def process_input(line,local_call,message_stack,session,signing_enabled,current_peer):
    if line == "/exit":
        if session:
            session.close()
        message_stack.append(("system","Goodbye."))
        return "exit", message_stack, session
    elif line.startswith("/connect"):
        try:
            _, call = line.split(maxsplit=1)
        except ValueError:
            message_stack.append(("error","[error] Usage: /connect CALLSIGN"))
            #continue
        current_peer = call
        session = connect_to_peer(local_call, call)
        message_stack.append(("info", f"[info] Connected to {call}"))
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
            message_stack.append(("error","[error] Usage: /sign on|off"))
            #continue
        message_stack.append(("info", f"[info] Signing {'enabled' if signing_enabled else 'disabled'}"))
    elif line and session:
        #Sending data to the connected session
        if signing_enabled:
            ###attempt to sign the line here or return error
            try:
                session.send_signed((line+"\r").encode("utf-8"))
                message_stack.append(("send_signed", f"[>{current_peer or 'unproto'}] {line}"))
            except BrokenPipeError:
                message_stack.append(("error",f"[error] Connection lost."))
                session = None
                current_peer = None
        else:
            try:
                session.send((line+"\r").encode("utf-8"))
                message_stack.append(("send_unsigned", f"[>{current_peer or 'unproto'}] {line}"))
            except BrokenPipeError:
                message_stack.append(("error",f"[error] Connection lost."))
                session = None
                current_peer = None
    elif line:
        #Sending text as unproto (NOT YET IMPLIMENTED)
        #TRY TO SEND UNPROTO MESSAGE THEN IF SUCCESSFUL POST THE FOLLOWING LINE
        if signing_enabled:
            message_stack.append(("send_signed", f"[>{current_peer or 'unproto'}] {line}"))
        else:
            message_stack.append(("send_unsigned", f"[>{current_peer or 'unproto'}] {line}"))
        #IF unproto message not possible post the following warning
        message_stack.append(("warn", "[warn*] Unproto not available yet and no active session. Enable unproto or /connect CALLSIGN first."))

    if session:
        return "connected", message_stack, session
    else:
        return "Success", message_stack, session

def run_peer_terminal(local_call="N0CALL"):
    current_peer = None
    verified = False
    session = None #could be stacked
    signing_enabled = True

    message_stack = []
    input_log = []
    log_stack = []
    prompt = ">"
    input_string = ""
    displayed_input = ""

    #message_stack.append(("info","information message"))
    #message_stack.append(("system","system message"))
    #log_stack.append(("unconnected_not_signing","unconnected and not signing input"))
    #log_stack.append(("unconnected_signing", "unconnected and signing input"))
    #log_stack.append(("connected_not_signing", "A connected but not signing input"))
    #log_stack.append(("connected_signing", "Signing and connected to a station"))

    with term.fullscreen(), term.cbreak():
        print(term.clear)
        input_buffer=''
        print(term.hide_cursor(), end='', flush=True)
        while True:
            #print(term.home + term.clear)
            prompt_len, PROMPT_START_Y = render_terminal(current_peer, signing_enabled, message_stack, log_stack, term)

            #draw_header(current_peer, signing_enabled)
            #draw_message_stack(message_stack)
            #draw_separator()
            #draw_log_stack(log_stack)
            #prompt_len = draw_prompt(current_peer,signing_enabled)

            input_buffer, process_flag = fetch_input(input_buffer)
            if process_flag:
                # Determine status key
                if current_peer:
                    if signing_enabled:
                        status = "connected_signing"
                    else:
                        status = "connected_not_signing"
                else:
                    if signing_enabled:
                        status = "unconnected_signing"
                    else:
                        status = "unconnected_not_signing"
                log_stack.append((status, input_buffer))
                result, message_stack, session = process_input(input_buffer,local_call,message_stack,session,signing_enabled,current_peer)
                if result == "exit":
                    break
                if result == "connected":
                    current_peer = session.remote_call
                input_buffer=""

            displayed_input = render_input_buffer(input_buffer, prompt_len, displayed_input, PROMPT_START_Y)

            #Drain the session thread
            if session and session.has_queue():
                while session and session.has_queue():
                    incoming = session.recv_one()
                    if incoming:
                        message_stack.append(incoming)

def depr_run_peer_terminal(local_call="N0CALL"):
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
            prompt_len = draw_prompt(current_peer,signing_enabled)
            # Input handling
            if not input_dirty:
                inp = ''

            while True:

                inp , break_loop, input_dirty = input_loop(inp,prompt_len)
                if break_loop:
                    break

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
                    ###draw_header(current_peer, signing_enabled)
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
                    ####draw_header(current_peer, signing_enabled)
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
                            ###draw_header(current_peer, session, signing_enabled)
                    else:
                        try:
                            session.send((line+"\r").encode("utf-8"))
                            messages.append(term.white + f"[>{current_peer or 'unproto'}] {line}" + term.normal)
                        except BrokenPipeError:
                            messages.append(term.red +f("[error] Connection lost.") + term.normal)
                            session = None
                            current_peer = None
                            ###draw_header(current_peer, session, signing_enabled)
                elif line:
                    #Sending text as unproto (NOT YET IMPLIMENTED)
                    #TRY TO SEND UNPROTO MESSAGE THEN IF SUCCESSFUL POST THE FOLLOWING LINE
                    messages.append(term.white + f"[>{current_peer or 'unproto'}] {line}" + term.normal)
                    #IF unproto message not possible post the following warning
                    messages.append(term.yellow + "[warn] Unproto not available yet and no active session. Enable unproto or /connect CALLSIGN first." + term.normal)
                # Clear message area before re-render NEEDS ADJUSTING WITH NEW DYNAMIC ZONE SIZE CONSTANTS
                for y in range(2, term.height - 2):
                    print(term.move_yx(y, 0) + term.clear_eol)


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
