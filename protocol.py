"""Shared RFMP packet rules (Part 1). Packets are JSON arrays plus a newline."""

import json  # Turn lists into text and text back into lists.

MAX_PACKET = 2 * 1024 * 1024  # Limit one packet to two MiB.
MAX_TEXT = 512 * 1024  # Limit UTF-8 file contents to 512 KiB.


def send_packet(connection, packet):
    """Send every byte, even when TCP needs several writes."""
    message = json.dumps(packet, ensure_ascii=True) + "\n"
    data = message.encode("ascii")
    if len(data) > MAX_PACKET:
        raise ValueError("Packet is too large")
    connection.sendall(data)


def receive_packet(reader):
    """The buffered reader remembers bytes belonging to the next packet."""
    data = reader.readline(MAX_PACKET + 1)
    if not data:
        raise EOFError("The other side disconnected")
    if len(data) > MAX_PACKET or not data.endswith(b"\n"):
        raise ValueError("Packet is too large or has no newline")
    packet = json.loads(data.decode("ascii"))
    if not isinstance(packet, list) or not packet:
        raise ValueError("A packet must be a nonempty JSON array")
    if not all(isinstance(field, str) for field in packet):
        raise ValueError("Every packet field must be a string")
    return packet
