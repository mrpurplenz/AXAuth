# session_manager.py
from axsocket import start_ax25_socket_connection, AX25Session
from typing import Dict, List, Tuple, Optional


class SessionManager:
    """
    Manages multiple AX25Session instances.
    """
    def __init__(self):
        self.sessions: Dict[str, AX25Session] = {}  # keyed by remote_call
        self.active_peer: Optional[str] = None

    def has_active_peer(self):
        return self.active_peer is not None

    def connect(self, local_call: str, remote_call: str) -> AX25Session:
        """
        Create a new AX.25 connected session and start it.
        """
        if remote_call in self.sessions:
            raise ValueError(f"Already connected to {remote_call}")

        session = start_ax25_socket_connection(local_call, remote_call)
        self.sessions[remote_call] = session

        # Set active peer if none is set yet
        if self.active_peer is None:
            self.active_peer = remote_call
 
        return session

    def send_packet(self, message, signing=True):
        """
        Send a message to the currently active peer.
        """
        if not self.active_peer:
            raise RuntimeError("No active peer selected")
 
        session = self.sessions[self.active_peer]
        session.send_packet(message, signing)

    def get_all_inbound(self) -> List[Tuple[str, Tuple[str, str]]]:
        """
        Pulls all queued inbound messages from all sessions.
        Returns: list of (peer, (msg_type, text))
        """
        results = []
        for peer, sess in self.sessions.items():
            while sess.has_queue():
                msg = sess.recv_one()
                if msg:
                    results.append((peer, msg))
        return results

    def get_one_inbound(self):
        """
        Pulls a queued inbound messages from the first session containing a message in its queue.
        Returns: [peer, (msg_type, text)]
        """
        results = None
        for peer, sess in self.sessions.items():
            while sess.has_queue():
                msg = sess.recv_one()
                if msg:
                    results=[peer, msg]
                    break
        return results


    def has_queue(self):
        result = False
        for peer, sess in self.sessions.items():
            if sess.has_queue():
                result = True
        return result

    def set_active_peer(self, remote_call: str):
        if remote_call not in self.sessions:
            raise ValueError(f"No such peer: {remote_call}")
        self.active_peer = remote_call

    def list_peers(self) -> List[str]:
        return list(self.sessions.keys())

    def close_peer(self, remote_call: str):
        if remote_call in self.sessions:
            self.sessions[remote_call].close()
            del self.sessions[remote_call]
            if self.active_peer == remote_call:
                self.active_peer = next(iter(self.sessions), None)

    def close_all(self):
        for sess in self.sessions.values():
            sess.close()
        self.sessions.clear()
        self.active_peer = None

