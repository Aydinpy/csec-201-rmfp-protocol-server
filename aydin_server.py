"""RFMP server for the CSEC-201 project.

Run: python aydin_server.py
Uses protocol.py for messages and security.py for RSA, AES, and Caesar.
Each client follows setup -> operations -> closing on one TCP connection.
"""

import socket  # Create the TCP server and accept connections.
import subprocess  # Run the five chosen Windows prompt commands.
import threading  # Let several clients use the server at the same time.
from pathlib import Path  # Work with files and folders.

from cryptography.exceptions import InvalidTag  # AES detected changed data.

# These existing helpers send/receive newline-terminated JSON arrays.
# TCP is a byte stream: a single recv() is not necessarily a whole message.
from protocol import MAX_TEXT, receive_packet, send_packet
from security import (
    check_session_key,
    decrypt_session_key,
    decrypt_text,
    encrypt_text,
    load_public_key,
    make_rsa_keys,
)


def allowed_path(root, current_directory, filename):
    """Resolve a requested path and reject access outside the server folder."""
    # resolve() handles '..' and symbolic links before we check the boundary.
    path = (current_directory / filename).resolve()
    if not path.is_relative_to(root):
        raise PermissionError("The path must stay inside the server folder")
    return path


def run_command(command, root, current_directory):
    """Perform only supported commands; return the directory and result."""
    words = command.split()  # Basic version: use folder names without spaces.
    if not words:
        raise ValueError("Enter a command")

    name = words[0].lower()
    arguments = words[1:]
    # The value is the exact number of arguments required by each command.
    # The document asks us to choose five additional system prompt commands.
    argument_counts = {
        "mkdir": 1, "cd": 1, "rmdir": 1, "rd": 1, "del": 1, "ren": 2,
        "dir": 0, "whoami": 0, "hostname": 0, "date": 0, "ver": 0,
    }
    if name not in argument_counts:
        raise ValueError("Unsupported command")
    if len(arguments) != argument_counts[name]:
        raise ValueError("Incorrect number of command arguments")

    # Perform file/folder actions directly so cd stays local to this client.
    if arguments:
        path = allowed_path(root, current_directory, arguments[0])
        if name in ("rmdir", "rd", "ren") and path == root:
            raise PermissionError("Cannot remove or rename the server root")

        if name == "mkdir":
            path.mkdir()
        elif name == "cd":
            if not path.is_dir():
                raise FileNotFoundError("Directory does not exist")
            # Change this client's directory, not the process-wide directory.
            current_directory = path
        elif name in ("rmdir", "rd"):
            path.rmdir()  # Only empty folders are removed.
        elif name == "del":
            path.unlink()
        elif name == "ren":
            destination = allowed_path(root, current_directory, arguments[1])
            if destination.exists():
                raise FileExistsError("The destination already exists")
            path.rename(destination)
        result = "Command completed"
    else:
        # Execute fixed commands rather than passing arbitrary client text.
        # /T makes date display the date without asking to change it.
        commands = {
            "dir": "dir", "whoami": "whoami", "hostname": "hostname",
            "date": "date /T", "ver": "ver",
        }
        completed = subprocess.run(
            ["cmd", "/c", commands[name]],
            cwd=current_directory,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise OSError(completed.stderr.strip() or "Command failed")
        result = completed.stdout.strip()

    if len(result.encode("utf-8")) > MAX_TEXT:
        raise ValueError("Command output is too large")
    return current_directory, result


def send_error(connection, error):
    """Convert a failure into one of the assignment's four error codes."""
    if isinstance(error, PermissionError):
        code = "E3"  # Forbidden path or insufficient permissions.
    elif isinstance(error, OSError):
        code = "E2"  # File, directory, or operating-system failure.
    elif isinstance(error, InvalidTag):
        code = "E4"  # AES authentication failed.
    else:
        code = "E1"  # Invalid packet, command, argument, or state.
    description = str(error) or "Encrypted data failed authentication"
    send_packet(connection, ["EE", code, description])


def handle_client(connection, address, root):
    """Handle one client's complete session in its own worker thread."""
    print("Connected:", address)
    # A buffered reader retains bytes belonging to the next RFMP message.
    reader = connection.makefile("rb")
    current_directory = root
    pending_file = None  # Set only while waiting for an openWrite data packet.
    algorithm = "none"
    session_key = b""

    try:
        # SETUP: no operations are accepted until the handshake succeeds.
        start = receive_packet(reader)
        if start not in (["SS", "RFMP", "v1.0", "0"],
                         ["SS", "RFMP", "v1.0", "1"]):
            raise ValueError("Expected SS, RFMP, v1.0, and security 0 or 1")

        if start[3] == "0":
            # Both the Python and C clients may use an unsecured connection.
            send_packet(connection, ["CC"])
        else:
            private_key, public_key = make_rsa_keys()
            # Only the public key leaves the server.
            send_packet(connection, ["CC", public_key])
            encryption = receive_packet(reader)
            if len(encryption) != 4 or encryption[0] != "EC":
                raise ValueError("Expected EC, algorithm, encrypted key, username:public key")

            algorithm = encryption[1]
            username, separator, client_key = encryption[3].partition(":")
            if not separator or not username.strip():
                raise ValueError("Client credentials need username:public key")
            # Validate the supplied key; this alone does not authenticate a user.
            load_public_key(client_key)
            try:
                # The client encrypted this key using the server's public key.
                session_key = decrypt_session_key(private_key, encryption[2])
                check_session_key(algorithm, session_key)
            except ValueError:
                send_packet(connection, ["EE", "E4", "Invalid encryption algorithm or session key"])
                return
            send_packet(connection, ["SC", "Encryption ready"])

        # OPERATIONS: read and handle requests until End or disconnection.
        while True:
            # Read one complete RFMP message before handling the operation.
            packet = receive_packet(reader)
            try:
                if packet == ["End"]:
                    # CLOSING: acknowledge and close only this client's socket.
                    send_packet(connection, ["SC", "Connection closed"])
                    break

                if pending_file is not None:
                    # An accepted openWrite must be followed by one DP packet.
                    target = pending_file
                    pending_file = None
                    if len(packet) != 2 or packet[0] != "DP":
                        raise ValueError("Expected DP after openWrite; write cancelled")
                    text = decrypt_text(packet[1], algorithm, session_key)
                    if len(text.encode("utf-8")) > MAX_TEXT:
                        raise ValueError("File text is too large")
                    # Recheck the path before writing. Decrypt before opening
                    # so rejected encrypted data cannot erase an existing file.
                    target = allowed_path(root, current_directory, str(target))
                    with target.open("w", encoding="utf-8", newline="") as file:
                        file.write(text)
                    send_packet(connection, ["SC", "File saved"])
                    continue

                if len(packet) != 3 or packet[0] != "CM":
                    raise ValueError("Expected a three-field CM packet")
                action, argument = packet[1], packet[2]

                if action == "prompt":
                    current_directory, result = run_command(argument, root, current_directory)
                    send_packet(connection, ["SC", result])
                elif action == "openRead":
                    path = allowed_path(root, current_directory, argument)
                    with path.open("r", encoding="utf-8", newline="") as file:
                        text = file.read(MAX_TEXT + 1)
                    if len(text.encode("utf-8")) > MAX_TEXT:
                        raise ValueError("File text is too large")
                    # Only file contents are encrypted, as the assignment asks.
                    send_packet(connection, ["DP", encrypt_text(text, algorithm, session_key)])
                    send_packet(connection, ["SC", "File read"])
                elif action == "openWrite":
                    path = allowed_path(root, current_directory, argument)
                    if not path.parent.is_dir() or path.is_dir():
                        raise FileNotFoundError("Choose a file in an existing directory")
                    pending_file = path
                    send_packet(connection, ["SC", "Ready for DP"])
                else:
                    raise ValueError("Unknown CM command type")
            except (ValueError, OSError, InvalidTag) as error:
                # A failed operation normally leaves the connection usable.
                send_error(connection, error)

    except EOFError:
        pass  # The client closed TCP without sending End.
    except (ValueError, OSError, InvalidTag) as error:
        try:
            send_error(connection, error)
        except OSError:
            pass  # A disconnected client cannot receive an error response.
    finally:
        # Always release both the buffered reader and the connected socket.
        reader.close()
        connection.close()
        print("Disconnected:", address)


def main():
    """Start the listening socket and give each connection a worker thread."""
    host = "127.0.0.1"  # Both clients connect to this computer.
    port = 5000  # The server and clients must use the same port.
    root = Path("server_files").resolve()
    root.mkdir(exist_ok=True)  # Store the project's files in this folder.

    # These are the basic steps for a TCP server: socket, bind, listen, accept.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((host, port))
        server.listen(10)
        print("RFMP listening on", (host, port), flush=True)
        while True:
            # accept() waits and returns a separate socket for this client.
            connection, address = server.accept()
            # The document requires multithreading: each client gets a thread.
            worker = threading.Thread(
                target=handle_client,
                args=(connection, address, root),
                daemon=True,
            )
            worker.start()
    except KeyboardInterrupt:
        print("\nServer stopped")
    finally:
        server.close()


# Importing this file does not start a server; running it directly does.
if __name__ == "__main__":
    main()
