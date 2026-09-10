# Ghost Forum - Crypto Module

This module provides all the cryptographic functionality needed for the Ghost Forum application, ensuring 100% privacy and end-to-end encryption for all communications.

## Features

### 1. Core Cryptographic Operations
- **Ed25519 Key Generation**: For user identity and message signing
- **X25519 Key Exchange**: For secure key negotiation
- **AES-256-GCM Encryption**: For symmetric encryption of messages and files
- **ChaCha20-Poly1305**: Alternative encryption algorithm for additional security

### 2. Messaging Protocols
- **Double Ratchet Protocol**: Based on Signal Protocol for secure messaging
- **MLS (Messaging Layer Security)**: For group messaging with forward secrecy
- **Message Authentication**: Ensuring message integrity and authenticity

### 3. File Encryption
- **End-to-end file encryption**: For images, videos, and other media
- **Chunked encryption**: Efficient handling of large files
- **Nonce management**: Secure nonce generation for each encryption operation

### 4. Security Features
- **Forward Secrecy**: Past communications remain secure even if keys are compromised
- **Perfect Forward Secrecy**: Each message uses unique keys
- **Zero Knowledge Architecture**: No central server can decrypt user communications

## Key Components

### CryptoManager
The main entry point for all cryptographic operations:
- Key generation (Ed25519, X25519)
- Symmetric encryption/decryption (AES-GCM, ChaCha20-Poly1305)
- Digital signatures and verification
- Key derivation functions

### DoubleRatchet
Implementation of the Signal Protocol's Double Ratchet algorithm:
- Secure key exchange between parties
- Message encryption with forward secrecy
- Automatic key rotation

### FileEncryption
Handles encryption of media files:
- Chunked file encryption for efficiency
- Unique nonces for each chunk to prevent pattern recognition
- Support for large files through streaming

### MLS (Messaging Layer Security)
Group messaging implementation:
- Group creation and management
- Forward secrecy across group epochs
- Secure message distribution

## Usage Example

```kotlin
val cryptoManager = CryptoManager()
val (publicKey, privateKey) = cryptoManager.generateIdentityKeys()

// Sign a message
val signature = cryptoManager.signData("Hello World".toByteArray(), privateKey)

// Encrypt data
val key = cryptoManager.generateSymmetricKey()
val encrypted = cryptoManager.encryptAesGcm("Secret Message".toByteArray(), key)
val decrypted = cryptoManager.decryptAesGcm(encrypted, key)
```

## Security Considerations

1. **All encryption happens client-side**: No server can read user communications
2. **No metadata collection**: The system is designed to minimize detectable metadata
3. **Forward secrecy**: Past messages remain secure even if keys are compromised
4. **Key rotation**: Regular key updates for enhanced security
5. **Zero-knowledge design**: No central authority has access to user data

## Dependencies

- Bouncy Castle (Java cryptography library)
- Signal Protocol Java implementation
- Kotlin Standard Library

## Testing

The module includes comprehensive unit tests covering:
- Key generation and management
- Encryption/decryption operations
- Signature creation and verification
- Protocol implementations