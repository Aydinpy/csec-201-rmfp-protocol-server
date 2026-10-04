"""RFMP Python client. Start aydin_server.py before running this file."""

import socket  # Connect to the server and exchange messages.

from cryptography.exceptions import InvalidTag

# Use the same packet format and encryption functions as the server.
from protocol import MAX_TEXT, receive_packet, send_packet
from security import (decrypt_text, encrypt_session_key, encrypt_text,
                      make_rsa_keys, make_session_key)


def checked_response(reader, expected):
    """Check for an error before using a server response."""
    packet = receive_packet(reader)
    if packet[0] == "EE":
        if len(packet) != 3:
            raise ValueError("Malformed EE packet")
        print("Server error", packet[1] + ":", packet[2])
        return None
    if packet[0] != expected:
        raise ValueError("Expected " + expected + ", received " + packet[0])
    if expected in ("SC", "DP") and len(packet) != 2:
        raise ValueError("Malformed " + expected + " packet")
    return packet


def setup(connection, reader, algorithm):
    """Send SS, receive CC, and send EC if encryption was chosen."""
    secure = "0" if algorithm == "none" else "1"
    send_packet(connection, ["SS", "RFMP", "v1.0", secure])
    confirmation = checked_response(reader, "CC")
    if confirmation is None:
        raise ValueError("Server rejected the connection")
    if algorithm == "none":
        if confirmation != ["CC"]:
            raise ValueError("Expected unsecured CC")
        return b""
    if len(confirmation) != 2:
        raise ValueError("Secure CC must include the server public key")
    # The assignment requires a client RSA key pair and a session key.
    # The private key stays here; the public key is included in EC.
    private_key, public_key = make_rsa_keys()
    session_key = make_session_key(algorithm)
    # Encrypt the session key using the public key received from the server.
    encrypted_key = encrypt_session_key(confirmation[1], session_key)
    username = input("Username: ").strip()
    while not username or ":" in username:
        username = input("Enter a username without a colon: ").strip()
    send_packet(connection, ["EC", algorithm, encrypted_key, username + ":" + public_key])
    if checked_response(reader, "SC") is None:
        raise ValueError("Server rejected encryption setup")
    return session_key


def run_menu(connection, reader, algorithm, session_key):
    """Let the user send commands, read files, write files, or disconnect."""
    while True:
        print("\n1. Run a command")
        print("2. Read a file")
        print("3. Write a file")
        print("4. Exit")
        choice = input("Choose 1-4: ").strip()
        if choice == "1":
            # These are the commands supported by aydin_server.py.
            print("mkdir, cd, rmdir/rd, del, ren, dir, whoami, hostname, date, ver")
            print("Use folder names without spaces.")
            command = input("Command: ")
            send_packet(connection, ["CM", "prompt", command])
            response = checked_response(reader, "SC")
            if response is not None:
                print(response[1])
        elif choice == "2":
            # openRead returns DP with the contents, followed by SC.
            filename = input("File name: ")
            send_packet(connection, ["CM", "openRead", filename])
            data = checked_response(reader, "DP")
            if data is not None:
                text = decrypt_text(data[1], algorithm, session_key)
                print("File contents:\n" + text)
                result = checked_response(reader, "SC")
                if result is not None:
                    print(result[1])
        elif choice == "3":
            filename = input("File name: ")
            print("Enter text. Enter a line containing only . to finish.")
            lines = []
            # A line containing only a dot finishes multiline text entry.
            while True:
                line = input()
                if line == ".":
                    break
                lines.append(line)
            text = "\n".join(lines)
            if len(text.encode("utf-8")) > MAX_TEXT:
                print("Text exceeds the 512 KiB limit")
                continue
            send_packet(connection, ["CM", "openWrite", filename])
            # Wait until the server is ready before sending the file contents.
            if checked_response(reader, "SC") is not None:
                send_packet(connection, ["DP", encrypt_text(text, algorithm, session_key)])
                result = checked_response(reader, "SC")
                if result is not None:
                    print(result[1])
        elif choice == "4":
            # End closes this session after the server acknowledges it.
            send_packet(connection, ["End"])
            result = checked_response(reader, "SC")
            if result is not None:
                print(result[1])
            return
        else:
            print("Choose 1, 2, 3, or 4")


def main():
    host = "127.0.0.1"  # Same address as aydin_server.py.
    port = 5000  # Same port as aydin_server.py.
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reader = None
    try:
        print("1. No encryption")
        print("2. AES")
        print("3. Caesar")
        choice = input("Choose 1-3: ").strip()
        while choice not in ("1", "2", "3"):
            choice = input("Choose 1, 2, or 3: ").strip()
        if choice == "1":
            algorithm = "none"
        elif choice == "2":
            algorithm = "AES"
        else:
            algorithm = "Caesar"

        connection.connect((host, port))
        # Buffer incoming bytes so complete messages can be read in order.
        reader = connection.makefile("rb")
        session_key = setup(connection, reader, algorithm)
        print("Connected. Encryption:", algorithm)
        run_menu(connection, reader, algorithm, session_key)
    except (OSError, ValueError, EOFError, InvalidTag) as error:
        print("Connection ended:", str(error) or "AES authentication failed")
    except KeyboardInterrupt:
        print("\nClient stopped")
    finally:
        # Release resources whether the user exits or a connection fails.
        if reader is not None:
            reader.close()
        connection.close()


# Start the client only when this file is run directly.
if __name__ == "__main__":
    main()
