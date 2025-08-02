#!/home/zl2drs/venvs/axauth/bin/python
import sys, os, select, fcntl, time
import crypto
def flush_print(*args):
    print(*args, flush=True)
def flush_print(s):
    print(s, flush=True)
def set_nonblocking(fd):
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
def main():
    flush_print("Hello there from ZL2DRS-11! Welcome to the world's first authenticating AX.25 node (Still under construction)")
    flush_print("Type 'quit' to disconnect, type 'help' for a list of instructions")
    set_nonblocking(sys.stdin.fileno())
    buffer = ""
    signing = False
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
                    flush_print(send_buff)
                    flush_print("games: Open the authenticated games room (UNDERCONSTRUCTION)\r")
                    flush_print("sign : Toggle node mode between signing outgoing messages (CURRENTLY UNDERCONSTRUCTION)")
                else:
                    flush_print(f"receieved unkown command: {buffer}")
                buffer = ""
            else:
                buffer += data
        except BlockingIOError:
            time.sleep(0.05)
            continue
if __name__ == "__main__":
    main()
