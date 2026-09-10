# Development Setup

## Prerequisites

1. **Java 17 JDK** - Install OpenJDK 17 or Oracle JDK 17
2. **Android SDK** - For Android app development (optional for core modules)
3. **Gradle 8.5** - Will be downloaded automatically by wrapper

## Setup Instructions

### 1. Clone the repository
```bash
git clone <repository-url>
cd ghost-forum
```

### 2. Install Java
- Download and install JDK 17 from [https://adoptium.net](https://adoptium.net)
- Set `JAVA_HOME` environment variable to your JDK installation path

### 3. Verify Installation
```bash
java -version
javac -version
```

### 4. Build the project
```bash
./gradlew build
```

## Project Structure

```
ghost-forum/
├── app/              # Main Android application
├── core/             # Shared interfaces and logic
├── crypto/           # Cryptographic implementations
├── relay/            # Onion relay network
├── storage/          # Local encrypted storage
├── api/              # gRPC interfaces
├── build.gradle.kts  # Root build file
├── settings.gradle.kts # Gradle settings
└── gradle.properties # Gradle properties
```

## Module Descriptions

### Core
Contains shared constants, interfaces, and utilities used across all modules.

### Crypto
Implements encryption using libsodium, Signal Protocol (Double Ratchet), MLS protocol for group chats.
- Double Ratchet for private messaging
- MLS for group messaging with forward secrecy
- File encryption for media content
- Key management and derivation functions

### Relay
Handles onion routing for metadata privacy - hides who talks to whom.

### Storage
Local encrypted storage using SQLCipher for secure data persistence.

### API
gRPC service definitions and stubs for client-relay communication.

## Development Guidelines

1. All cryptographic operations must use well-vetted libraries (libsodium, Signal Protocol)
2. Never store sensitive information in plaintext
3. Follow Android security best practices for mobile apps
4. Use Kotlin 2.0 for all new code
5. Test all encryption and decryption flows thoroughly