# axsocket.py
import ax25
import ax25.ports
import ax25.socket
import socket
import threading

def start_ax25_socket_connection(local_call, remote_call):
    print(f"[debug] Creating AX.25 socket at {local_call}")
    s = ax25.socket(local_call)
    print(f"[debug] Connecting AX.25 socket to {reote_call}")
    s.connect(remote_call)
    return s

def depr_start_ax25_socket_connection(my_call, dest_call):
    #s = socket.socket(socket.AF_AX25, socket.SOCK_STREAM, socket.AX25_PROTO_DEFAULT)
    s = socket.socket(socket.AF_AX25, socket.SOCK_STREAM)

    try:
        s.bind((my_call, 0))  # 0 = default device
        s.connect((dest_call, 0))
        print(f"[info] Connected to {dest_call} via AX.25 socket.")
    except OSError as e:
        print(f"[error] AX.25 socket error: {e}")
        return None

    return s

def start_terminal_session(sock):
    def receive_loop():
        while True:
            try:
                data = sock.recv(1024)
                if not data:
                    print("\n[info] Connection closed by remote.")
                    break
                print(data.decode(errors='ignore'), end='', flush=True)
            except OSError:
                break

    thread = threading.Thread(target=receive_loop, daemon=True)
    thread.start()
    return thread
