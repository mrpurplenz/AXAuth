from dataclasses import dataclass
import json

@dataclass
class AXAuthPacket:
    version: int
    command: str
    payload: dict

def encode_packet(packet: AXAuthPacket) -> bytes:
    wrapped = {
        "version": packet.version,
        "command": packet.command,
        "payload": packet.payload
    }
    return json.dumps(wrapped).encode("utf-8")

def decode_packet(data: bytes) -> AXAuthPacket:
    obj = json.loads(data.decode("utf-8"))
    return AXAuthPacket(
        version=obj.get("version", 1),
        command=obj["command"],
        payload=obj["payload"]
    )
