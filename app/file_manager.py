from pathlib import Path
import hashlib
import struct

from .crypto import encrypt_data, decrypt_data


# Process files in chunks instead of loading the entire file into memory.
CHUNK_SIZE = 1024 * 1024  # 1 MB

# File format marker.
MAGIC = b"HYBRIDVAULT1"

# Binary format:
# MAGIC
#   repeated:
#       chunk_index   -> 4 bytes
#       nonce         -> 12 bytes
#       ciphertext_len -> 8 bytes
#       ciphertext
#
# AES-GCM authentication tag is included in ciphertext.


def _calculate_file_sha256(file_path: Path) -> str:
    """
    Calculate SHA-256 incrementally without loading
    the entire file into memory.
    """
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file_object:
        while True:
            chunk = file_object.read(CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def calculate_file_sha256(file_path: str | Path) -> str:
    """
    Calculate the SHA-256 hash of a file.

    The file is processed incrementally so large files
    do not need to be loaded entirely into memory.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    return _calculate_file_sha256(path)


def verify_file_sha256(
    file_path: str | Path,
    expected_hash: str,
) -> bool:
    """
    Verify the SHA-256 hash of a file.

    Returns True when the calculated hash matches
    the expected hash.
    """
    actual_hash = calculate_file_sha256(file_path)

    return actual_hash.lower() == expected_hash.lower()


def _build_associated_data(chunk_index: int) -> bytes:
    """
    Build authenticated metadata for an encrypted chunk.

    The chunk index is authenticated by AES-GCM so that
    encrypted chunks cannot be silently reordered.
    """
    return struct.pack(">I", chunk_index)


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
) -> str:
    """
    Encrypt a file incrementally using AES-256-GCM.

    Each file chunk is encrypted independently.

    Returns:
        SHA-256 hash of the original plaintext file.
    """
    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.is_file():
        raise FileNotFoundError(
            f"Input file not found: {input_file}"
        )

    if input_file.resolve() == output_file.resolve():
        raise ValueError(
            "Input and output files must be different."
        )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    sha256 = hashlib.sha256()
    chunk_index = 0

    with (
        input_file.open("rb") as source,
        output_file.open("wb") as destination,
    ):
        # Write file format marker.
        destination.write(MAGIC)

        while True:
            plaintext_chunk = source.read(CHUNK_SIZE)

            if not plaintext_chunk:
                break

            # Update plaintext integrity hash.
            sha256.update(plaintext_chunk)

            # Authenticate the chunk number.
            associated_data = _build_associated_data(
                chunk_index
            )

            # AES-GCM encryption.
            ciphertext, nonce = encrypt_data(
                plaintext_chunk,
                key,
                associated_data=associated_data,
            )

            # Write chunk metadata.
            destination.write(
                struct.pack(">I", chunk_index)
            )

            destination.write(nonce)

            destination.write(
                struct.pack(">Q", len(ciphertext))
            )

            # Write encrypted chunk.
            destination.write(ciphertext)

            chunk_index += 1

    return sha256.hexdigest()


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    expected_hash: str | None = None,
) -> str:
    """
    Decrypt a chunked AES-256-GCM encrypted file.

    Each chunk is authenticated during decryption.

    If expected_hash is provided, the SHA-256 hash of the
    decrypted file is compared against it.

    Returns:
        SHA-256 hash of the decrypted plaintext file.

    Raises:
        ValueError:
            If the file format is invalid, chunks are out
            of order, authentication fails, or integrity
            verification fails.
    """
    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.is_file():
        raise FileNotFoundError(
            f"Encrypted file not found: {input_file}"
        )

    if input_file.resolve() == output_file.resolve():
        raise ValueError(
            "Input and output files must be different."
        )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    sha256 = hashlib.sha256()
    expected_chunk_index = 0

    with (
        input_file.open("rb") as source,
        output_file.open("wb") as destination,
    ):
        # Verify file format marker.
        magic = source.read(len(MAGIC))

        if magic != MAGIC:
            raise ValueError(
                "Invalid HybridVault encrypted file format."
            )

        while True:
            # Read chunk index.
            index_data = source.read(4)

            if not index_data:
                break

            if len(index_data) != 4:
                raise ValueError(
                    "Corrupted encrypted file: "
                    "incomplete chunk index."
                )

            chunk_index = struct.unpack(
                ">I",
                index_data,
            )[0]

            # Prevent chunk reordering.
            if chunk_index != expected_chunk_index:
                raise ValueError(
                    "Chunk order verification failed."
                )

            # Read AES-GCM nonce.
            nonce = source.read(12)

            if len(nonce) != 12:
                raise ValueError(
                    "Corrupted encrypted file: "
                    "invalid nonce."
                )

            # Read ciphertext length.
            length_data = source.read(8)

            if len(length_data) != 8:
                raise ValueError(
                    "Corrupted encrypted file: "
                    "invalid ciphertext length."
                )

            ciphertext_length = struct.unpack(
                ">Q",
                length_data,
            )[0]

            # Basic sanity check.
            if ciphertext_length < 16:
                raise ValueError(
                    "Corrupted encrypted file: "
                    "invalid ciphertext."
                )

            # Read encrypted chunk.
            ciphertext = source.read(ciphertext_length)

            if len(ciphertext) != ciphertext_length:
                raise ValueError(
                    "Corrupted encrypted file: "
                    "incomplete ciphertext chunk."
                )

            # Authenticate the chunk number.
            associated_data = _build_associated_data(
                chunk_index
            )

            # AES-GCM decryption.
            plaintext_chunk = decrypt_data(
                ciphertext,
                key,
                nonce,
                associated_data=associated_data,
            )

            # Update plaintext integrity hash.
            sha256.update(plaintext_chunk)

            # Write decrypted data.
            destination.write(plaintext_chunk)

            expected_chunk_index += 1

    calculated_hash = sha256.hexdigest()

    # Optional end-to-end integrity verification.
    if expected_hash is not None:
        if calculated_hash.lower() != expected_hash.lower():
            # Remove potentially corrupted output.
            try:
                output_file.unlink()
            except OSError:
                pass

            raise ValueError(
                "File integrity verification failed: "
                "SHA-256 hash does not match."
            )

    return calculated_hash
