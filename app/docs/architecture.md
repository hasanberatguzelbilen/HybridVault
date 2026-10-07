# HybridVault Architecture

## Overview

HybridVault is a secure file vault application designed to encrypt
and decrypt local files using a hybrid cryptographic architecture.

The application combines:

- AES-256-GCM for file encryption
- RSA for AES key wrapping
- SHA-256 for integrity verification
- Password entropy analysis
- Chunk-based file processing
- Graphical user interface

## Encryption Flow

1. User selects a file.
2. The application reads the file in binary mode.
3. A random AES-256 key is generated.
4. The file is encrypted using AES-256-GCM.
5. The AES key is encrypted using the user's RSA public key.
6. The original file SHA-256 hash is calculated.
7. Metadata and cryptographic information are stored with the encrypted file.
8. The encrypted file is saved with the `.enc` extension.

## Decryption Flow

1. User selects an encrypted `.enc` file.
2. The RSA private key is used to recover the AES key.
3. The encrypted file is decrypted using AES-256-GCM.
4. The SHA-256 hash of the recovered file is calculated.
5. The calculated hash is compared with the stored hash.
6. The application reports whether the file is intact or corrupted.

## Main Components

| Component | Responsibility |
|---|---|
| `main.py` | Application entry point |
| `gui.py` | Graphical user interface |
| `crypto.py` | AES encryption and decryption |
| `key_manager.py` | RSA key generation and key wrapping |
| `file_manager.py` | File reading, writing and chunk processing |
| `password_strength.py` | Password entropy calculation |

## Security Goals

- Confidentiality through AES-256-GCM
- Integrity and authenticity through authenticated encryption
- Secure AES key protection through RSA
- File integrity verification through SHA-256
- Safe handling of large files through chunk processing
- Separation of cryptographic responsibilities
