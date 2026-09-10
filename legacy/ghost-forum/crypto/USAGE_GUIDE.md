# Ghost Forum Crypto Usage Guide

This guide explains how to integrate and use the cryptographic components of the Ghost Forum application in an Android environment.

## Architecture Overview

The Ghost Forum crypto module is designed with a layered architecture:

```
┌─────────────────┐
│   Application   │
│   (Android)     │
└─────────┬───────┘
          │
┌─────────▼────────┐
│  Crypto Manager  │
│ (Core functions) │
└─────────┬────────┘
          │
┌─────────▼────────┐
│ Messaging Protocols │
│ - Double Ratchet  │
│ - MLS             │
└─────────┬────────┘
          │
┌─────────▼────────┐
│   File Encryption │
│ (Media handling) │
└──────────────────┘
```

## Core Usage Patterns

### 1. User Identity Management

```kotlin
val cryptoManager = CryptoManager()

// Generate user identity keys (stored locally)
val (publicKey, privateKey) = cryptoManager.generateIdentityKeys()

// Store private key securely (encrypted with user password or device key)
// Public key can be shared for communication setup
```

### 2. Secure Messaging

```kotlin
// For direct messaging (Double Ratchet)
val doubleRatchet = DoubleRatchet()

// Initialize ratchet with your keys and peer's public key
doubleRatchet.initialize(ourPrivateKey, ourPublicKey, peerPublicKey)

// Encrypt a message
val encryptedMessage = doubleRatchet.encrypt("Hello, secure world!".toByteArray())

// Decrypt a message
val decryptedMessage = doubleRatchet.decrypt(encryptedMessage)
```

### 3. Group Messaging (MLS)

```kotlin
val mls = MLS()

// Create group with members
val member1 = MLS.Member("user1", publicKey1, listOf("chat", "media"))
val member2 = MLS.Member("user2", publicKey2, listOf("chat", "media"))

val group = mls.createGroup("forum-group-123", listOf(member1, member2))

// Encrypt group message
val encryptedMessage = mls.encryptMessage("Group message content")

// Decrypt group message
val decryptedMessage = mls.decryptMessage(encryptedMessage)
```

### 4. File Encryption

```kotlin
val fileEncryption = FileEncryption()

// Generate encryption key for file
val fileKey = fileEncryption.generateFileEncryptionKey()

// Encrypt a file (images, videos, etc.)
fileEncryption.encryptFile(
    "/path/to/input/file.jpg",
    "/path/to/encrypted/file.enc",
    fileKey
)

// Decrypt the file
fileEncryption.decryptFile(
    "/path/to/encrypted/file.enc",
    "/path/to/output/file.jpg",
    fileKey
)
```

## Security Best Practices

### Key Management
1. **Never store private keys in plain text** - always encrypt them with device-specific keys or user passwords
2. **Use secure key storage** - utilize Android Keystore System for sensitive key material
3. **Implement proper key rotation** - regularly update encryption keys for forward secrecy

### Message Security
1. **Always verify signatures** - ensure messages haven't been tampered with
2. **Use unique nonces** - never reuse nonces in encryption operations
3. **Implement proper error handling** - avoid leaking information through error messages

### File Security
1. **Encrypt all media files** - even if they're small, they contain metadata that can be exploited
2. **Chunk large files** - for efficient streaming and memory management
3. **Use secure temporary storage** - ensure intermediate files are deleted securely

## Android Integration

### Dependencies in build.gradle.kts
```kotlin
dependencies {
    implementation("com.ghost.forum:crypto:1.0.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.whispersystems:signal-protocol-java:2.8.1")
}
```

### Implementation in Android Application
```kotlin
class GhostForumService {
    private val cryptoManager = CryptoManager()
    private val doubleRatchet = DoubleRatchet()
    private val fileEncryption = FileEncryption()
    
    // Initialize user identity on app start
    fun initializeUser() {
        val (publicKey, privateKey) = cryptoManager.generateIdentityKeys()
        // Store keys securely in Android Keystore or encrypted local storage
    }
    
    // Handle secure messaging
    fun sendMessage(recipient: String, message: String): ByteArray {
        // Implementation details...
        return encryptedMessage
    }
    
    // Handle file sharing
    fun shareFile(filePath: String): ByteArray {
        val encryptionKey = fileEncryption.generateFileEncryptionKey()
        val encryptedFilePath = "$filePath.enc"
        fileEncryption.encryptFile(filePath, encryptedFilePath, encryptionKey)
        // Return encrypted file data or metadata
        return encryptedData
    }
}
```

## Privacy Considerations

### Metadata Minimization
The Ghost Forum implementation is designed to minimize metadata that could be used to identify users or their activities:

1. **Message routing**: All communication is routed through decentralized relays
2. **No user identifiers**: Users communicate using pseudonymous handles
3. **Content encryption**: Even message headers are encrypted

### Liability Protection
1. **No central storage**: All data is stored client-side and encrypted
2. **Decentralized architecture**: No single point of failure or control
3. **Zero knowledge**: No server can access user content or metadata

## Performance Optimization

### Memory Management
1. **Chunked file processing**: Large files are processed in chunks to manage memory usage
2. **Efficient key derivation**: Use optimized HKDF implementations for key generation
3. **Caching strategy**: Cache frequently used keys but ensure they're cleared when no longer needed

### Network Efficiency
1. **Compression**: Consider compressing messages before encryption (when appropriate)
2. **Batch operations**: Process multiple messages together when possible
3. **Efficient serialization**: Use compact formats for message structures

## Testing Your Implementation

The crypto module includes comprehensive tests that verify:

1. **Key generation and management**
2. **Encryption/decryption correctness**
3. **Signature verification**
4. **Protocol integrity**

Run tests using:
```bash
./gradlew :crypto:test
```

## Future Enhancements

1. **Zero-knowledge proofs**: Implement zk-proofs for referral system to maintain privacy
2. **Advanced key exchange**: Integrate more sophisticated key exchange mechanisms
3. **Quantum-resistant cryptography**: Prepare for post-quantum algorithms
4. **Cross-platform compatibility**: Ensure consistent behavior across different devices