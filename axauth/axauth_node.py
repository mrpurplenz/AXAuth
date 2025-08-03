#!/home/zl2drs/venvs/axauth/bin/python
import sys, os, select, fcntl, time
from crypto import load_private_key, sign_message
from authpacket import AuthPacket
#def flush_print(*args):
#    print(*args, flush=True)
KEY_DIR = os.path.join(os.path.dirname(__file__), '../keys')
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, 'private.pem')
CALL = "ZL2DRS"
SSID = "11"
CALL_SSID = CALL + "-" + SSID

def flush_print(message_string,signing):
    packet = AuthPacket(CALL, message_string)
    #if signing:
    #    private_key = load_private_key(PRIVATE_KEY_PATH)
    #    message_data = message_string.encode("utf-8")
    #    signature = sign_message(message_data, private_key)
    #    signed_data = (
    #        b"-----BEGIN CHATSIG-----\n"
    #        + signature.hex().encode() + b"\n"
    #        + b"-----END CHATSIG-----\n"
    #        + message_data
    #    )
    #    signed_message = signed_data.decode("utf-8", errors="replace")
    #    output = signed_message
    #else:
    #    output = message_string
    print(packet.to_text(signing), flush=True)

def set_nonblocking(fd):
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

def main():
    signing = False
    flush_print("Hello there from ZL2DRS-11! Welcome to the world's first authenticating AX.25 node (Still under construction)",signing)
    flush_print("Type 'quit' to disconnect, type 'help' for a list of instructions",signing)
    set_nonblocking(sys.stdin.fileno())
    buffer = ""
    while True:
        try:
            data = sys.stdin.read(1)
            if not data:
                time.sleep(0.1)
                continue
            if data in ('\r', '\n'):
                if buffer.strip().lower() == "quit":
                    break #could add a goodbye line here
                elif buffer.strip().lower() == "sign":
                    signing = True
                elif buffer.strip().lower() == "help":
                    send_buff = "help : This list of commands\r"
                    send_buff += "quit : Leave the node to rejoin the living\r"
                    send_buff += "chat : Go to the authenticated chat room (UNDERCONSTRUCTION)\r"
                    send_buff += "hunt : Go on a hunt for the 'Authentic' treasure (UNDERCONSTRUCTION)"
                    flush_print(send_buff, signing)
                    flush_print("games: Open the authenticated games room (UNDERCONSTRUCTION)\r",signing)
                    flush_print("sign : Toggle node mode between signing outgoing messages (CURRENTLY UNDERCONSTRUCTION)",signing)
                else:
                    flush_print(f"receieved unkown command: {buffer}",signing)
                buffer = ""
            else:
                buffer += data
        except BlockingIOError:
            time.sleep(0.05)
            continue
if __name__ == "__main__":
    main()
