#!/home/zl2drs/venvs/axauth/bin/python
import sys, os, select, fcntl, time
from authpacket import AuthPacket, BEGIN_MARKER, END_MARKER
from crypto import load_private_key, sign_message

KEY_DIR = os.path.join(os.path.dirname(__file__), '../keys')
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, 'private.pem')
CALL = "ZL2DRS"
SSID = "11"
CALL_SSID = CALL + "-" + SSID

def listify(text):
    normal_text = text.replace('\r\n', '\n').replace('\r', '\n').strip()
    lines = normal_text.split('\n')
    output = []
    return output.extend(lines)

def flush_print(message_string, signing):
    try:
        packet = AuthPacket(CALL, message_string)
        print(packet.to_text(signing), flush=True)
        packet = None
    except Exception as e:
        print(f"[Error] Failed to create output packet packet: {e}", flush=True)


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
    flush_print("Third line of data", signing)
    flush_print("Fourth line of data", False)
    flush_print("Fifth line of data", True)
    set_nonblocking(sys.stdin.fileno())

    while True:
        try:
            data = sys.stdin.read(1)
            if not data:
                time.sleep(0.1)
                continue

            buffer += data

            packet_call          = None
            packet_signed        = False
            packet_signature     = None
            packet_public_exists = False
            packet_verified      = False

            # Process line if newline received
            lines_to_process=[]
            if data in ('\n', '\r'):
                flush_print("[received data]",False)
                line = buffer.strip()
                buffer = ""
                if in_packet:
                    flush_print("[working on packet]",False)
                    packet_lines.append(line)
                    if line == END_MARKER:
                        try:
                            flush_print("[packet closed]",False)
                            full_packet = "\n".join(packet_lines)
                            pkt = AuthPacket.from_text(full_packet)
                            flush_print(f"[recv_verified] {pkt.callsign}: {pkt.message}", signing)
                            lines_to_process = listify(pkt.message)

                            packet_call          = pkt.callsign
                            packet_signed        = pkt.has_signature()
                            if packet_signed:
                                packet_signature = pkt.signature_b64
                            packet_public_exits  = pkt.has_public()
                            packet_verified      = pkt.is_valid()

                        except Exception as e:
                            flush_print(f"[recv_signed_failed_verification] Failed to parse signed packet: {e}", signing)
                        in_packet = False
                        packet_lines = []
                    flush_print("[still decoding packet]",False)
                else:
                    if line == BEGIN_MARKER:
                        flush_print("[signed packet 'begin' detected (1)]",False)
                        flush_print("[signed packet 'begin' detected (2)]",False)
                        flush_print("[beginning consumption  of wired data]",False)
                        in_packet = True
                        flush_print("[will read lines to packet for later decoding]",False)
                        packet_lines = [line]
                        flush_print("[added lines to packet]",False)
                    lines_to_process = [line]
                    #Process unsigned lines
            if len(lines_to_process)>0:
                flush_print("[trying to process]",False)
                quit_signal = False
                for line in lines_to_process:
                    if line.lower() == "quit":
                        quit_signal = True
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
                if quit_signal:
                    break
        except BlockingIOError:
            time.sleep(0.05)
            continue

if __name__ == "__main__":
    main()
