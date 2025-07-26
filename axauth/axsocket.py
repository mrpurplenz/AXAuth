# axsocket.py
import ax25
import ax25.ports
import ax25.socket
import threading

def start_ax25_socket_connection(local_call, remote_call):
    print(f"[debug] Creating AX.25 socket")
    s = ax25.socket.Socket()

    try:
        print(f"[debug] Binding AX.25 socket to {local_call}")
        s.bind(local_call, "ax25")
    except Exception as e:
        print(f"[error] Failed to bind socket to {local_call}: {e}")
        pass

    try:
        print(f"[debug] Connecting AX.25 socket to {remote_call}")
        result=s.connect_ex(remote_call)
        print(f"[debug] Connection of AX.25 socket returned {result}")
    except Exception as e:
        print(f"[error] Failed to connect socket to {remote_call}: {e}")
        pass

    thread = start_terminal_session(s)

    return (s, thread)

def depr_start_ax25_socket_connection(my_call, dest_call):
    s = ax25.socket.Socket(socket.AF_AX25, socket.SOCK_STREAM)
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
        print("[debug] Receive thread started")
        while True:
            try:
                data = sock.recv(1024)
                if not data:
                    print("\n[info] Connection closed by remote.")
                    break
                #print(f"\n[recv] {data.decode(errors='ignore')}")
                print(data.decode(errors='ignore'), end='', flush=True)
            except OSError as e:
                print(f"[error] Receive error: {e}")
                break

    thread = threading.Thread(target=receive_loop, daemon=True)
    thread.start()
    return thread
