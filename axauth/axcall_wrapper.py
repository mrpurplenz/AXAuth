import subprocess
def send_and_receive(dest_call: str, message: bytes, iface: str = "ax0") -> bytes:
    print(f"[Stub] Sending to {dest_call} via {iface}:")
    print(message.decode("utf-8"))
    return b'{"version":1,"command":"ack","payload":{"status":"ok"}}'
def start_ax25_connection(remote_call):
    try:
        subprocess.run(["axcall", "ax25", remote_call], check=True)
        return True
    except subprocess.CalledProcessError:
        return False
