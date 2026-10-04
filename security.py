"""Part 1 encryption helpers. The socket and file code stays in other files."""

import base64  # Represent encrypted bytes as printable packet text.
import secrets  # Generate unpredictable session keys and AES nonces.

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def make_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_bytes.decode("ascii")


def load_public_key(text):
    key = serialization.load_pem_public_key(text.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise ValueError("An RSA public key of at least 2048 bits is required")
    return key


def rsa_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt_session_key(public_text, session_key):
    public_key = load_public_key(public_text)
    encrypted = public_key.encrypt(session_key, rsa_padding())
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_session_key(private_key, encrypted_text):
    encrypted = base64.b64decode(encrypted_text, validate=True)
    return private_key.decrypt(encrypted, rsa_padding())


def make_session_key(algorithm):
    if algorithm == "AES":
        return secrets.token_bytes(32)
    if algorithm == "Caesar":
        return str(secrets.randbelow(25) + 1).encode("ascii")
    raise ValueError("Choose AES or Caesar")


def check_session_key(algorithm, session_key):
    if algorithm == "AES" and len(session_key) == 32:
        return
    if algorithm == "Caesar" and session_key in [str(n).encode("ascii") for n in range(1, 26)]:
        return
    raise ValueError("Invalid algorithm or session key")


def caesar(text, shift):
    result = ""
    for character in text:
        if "a" <= character <= "z":
            character = chr((ord(character) - ord("a") + shift) % 26 + ord("a"))
        elif "A" <= character <= "Z":
            character = chr((ord(character) - ord("A") + shift) % 26 + ord("A"))
        result += character
    return result


def encrypt_text(text, algorithm, session_key):
    if algorithm == "none":
        return text
    if algorithm == "Caesar":
        return caesar(text, int(session_key))
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, text.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_text(text, algorithm, session_key):
    if algorithm == "none":
        return text
    if algorithm == "Caesar":
        return caesar(text, -int(session_key))
    data = base64.b64decode(text, validate=True)
    return AESGCM(session_key).decrypt(data[:12], data[12:], None).decode("utf-8")
