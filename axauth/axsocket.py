# axsocket.py
import ax25
import ax25.ports
import ax25.socket
import threading
import queue
import errno
import select
from blessed import Terminal

def normalize_message(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    return (text+"\n")
    return text.replace('\r\n', '\n').replace('\r', '\n')


class AX25Session:

    def __init__(self, sock, remote_call, local_call):
        self.sock = sock
        self.remote_call = remote_call
        self.local_call = local_call
        self.recv_queue = queue.Queue()
        self.running = True
        self.thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.thread.start()
        self.recv_queue.put(Terminal().cyan+f'[info] Connection from {local_call} to {remote_call} created')
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
                    self.recv_queue.put('[info] Connection closed by remote.')
                    self.running = False
                    break
                self.recv_queue.put(normalize_message(data))
            except OSError as e:
                if e.errno == errno.ENOTCONN:
                    self.recv_queue.put('[info] Remote disconnected (socket closed).')
                else:
                    self.recv_queue.put(f'[error] Receive error: {e}')
                self.running = False
                break
            except Exception as e:
                self.recv_queue.put(f'[error] Unexpected receive error: {e}')
                self.running = False
                break

    def send(self, data: str):
        try:
            self.sock.send(data)
        except Exception as e:
            self.recv_queue.put(f'[error] Send {data} failed: {e}')

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

