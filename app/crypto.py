import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY_SIZE = 32
NONCE_SIZE = 12


def generate_aes_key() -> bytes:
    """
    Generate a cryptographically secure 256-bit AES key.
    """
    return secrets.token_bytes(AES_KEY_SIZE)


def generate_nonce() -> bytes:
    """
    Generate a cryptographically secure 96-bit nonce for AES-GCM.
    """
    return secrets.token_bytes(NONCE_SIZE)


def encrypt_data(
    plaintext: bytes,
    key: bytes,
    nonce: bytes | None = None,
    associated_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM.

    Returns:
        ciphertext: Encrypted data including the GCM authentication tag.
        nonce: The nonce used for encryption.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes.")

    if nonce is None:
        nonce = generate_nonce()

    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes.")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return ciphertext, nonce


def decrypt_data(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.

    Raises:
        ValueError: If the key or nonce size is invalid.
        InvalidTag: If authentication fails or the data was modified.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes.")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def calculate_sha256(data: bytes) -> str:
    """
    Calculate the SHA-256 hash of data.

    Returns:
        Hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()
