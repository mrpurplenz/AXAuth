#!/home/zl2drs/venvs/axauth/bin/python
import sys, os, select, fcntl, time
from authpacket import AuthPacket, BEGIN_MARKER, END_MARKER
from crypto import load_private_key, sign_message

KEY_DIR = os.path.join(os.path.dirname(__file__), '../keys')
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, 'private.pem')
CALL = "ZL2DRS"
SSID = "11"
CALL_SSID = CALL + "-" + SSID

def flush_print(message_string, signing):
    packet = AuthPacket(CALL, message_string)
    print(packet.to_text(signing), flush=True)

def set_nonblocking(fd):
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

def main():
    signing = False
    in_packet = False
    packet_lines = []
    buffer = ""

    flush_print("Hello there from ZL2DRS-11! Welcome to the world's first authenticating AX.25 node (Still under construction)", signing)
    flush_print("Type 'quit' to disconnect, type 'help' for a list of instructions", signing)

    set_nonblocking(sys.stdin.fileno())

    while True:
        try:
            data = sys.stdin.read(1)
            if not data:
                time.sleep(0.1)
                continue

            buffer += data

            # Process line if newline received
            if data in ('\n', '\r'):
                line = buffer.strip()
                buffer = ""

                if in_packet:
                    packet_lines.append(line)
                    if line == END_MARKER:
                        try:
                            full_packet = "\n".join(packet_lines)
                            pkt = AuthPacket.from_text(full_packet)
                            flush_print(f"[recv_verified] {pkt.callsign}: {pkt.message}", False)
                        except Exception as e:
                            flush_print(f"[recv_signed_failed_verification] Failed to parse signed packet: {e}", False)
                        in_packet = False
                        packet_lines = []
                else:
                    if line == BEGIN_MARKER:
                        in_packet = True
                        packet_lines = [line]
                    elif line.lower() == "quit":
                        break
                    elif line.lower() == "sign":
                        signing = True
                    elif line.lower() == "help":
                        help_msg = (
                            "help : This list of commands\r\n"
                            "quit : Leave the node to rejoin the living\r\n"
                            "chat : Go to the authenticated chat room (UNDERCONSTRUCTION)\r\n"
                            "hunt : Go on a hunt for the 'Authentic' treasure (UNDERCONSTRUCTION)\r\n"
                            "games: Open the authenticated games room (UNDERCONSTRUCTION)\r\n"
                            "sign : Toggle node mode between signing outgoing messages (CURRENTLY UNDERCONSTRUCTION)\r\n"
                        )
                        flush_print(help_msg, signing)
                    else:
                        flush_print(f"[recv_unsigned] Unknown command or unsigned message: {line}", False)
        except BlockingIOError:
            time.sleep(0.05)
            continue

if __name__ == "__main__":
    main()
