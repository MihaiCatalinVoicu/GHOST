# Ghost Forum - Private Android Forum Application

Ghost Forum is a 100% private forum and messenger application built for maximum privacy and security. This implementation follows the requirements of complete end-to-end encryption, no central server that can see conversations, blockchain integration, and referral-based monetization system.

## Features

### Core Privacy Features
- **End-to-End Encryption**: All messages are encrypted with Double Ratchet Protocol (Signal Protocol)
- **No Central Server**: Uses decentralized relay network to avoid single points of failure
- **Metadata Minimization**: Thread structure is encrypted, so no one can see who talks to whom
- **Zero-Knowledge Architecture**: Application developers cannot see user conversations

### Blockchain Integration
- **Ethereum Address Identity**: Users derive Signal keys from their Ethereum addresses using EIP-712 signatures
- **Web3 Bridge**: Secure connection between Ethereum wallets and Signal Protocol
- **Decentralized Identity Management**: No central identity authority

### Monetization System
- **Monthly Subscription**: $10/month per user
- **Referral Program**: 10% commission on referred users (automatically paid out)
- **Crypto Payments**: Accepts XMR, BTC-LN, USDT for payments
- **Private Payouts**: Referral payouts are private and don't reveal user identities

### Technical Architecture

#### Layer 0 - Identity & Onboarding
- Ed25519 keypair per device, generated locally
- Referral chain: seed users get invites directly, each user generates N invite codes derived from their own key (deterministic HD derivation)
- New users sign up with an invite → both parties are linked pseudonymously for the 10% payout

#### Layer 1 - E2E Crypto
- DMs: Double Ratchet (libsignal)
- Forum channels: MLS (groups), Sender Keys per member → forward secrecy within groups too
- Media: file-level encryption with keys distributed via the same channel key; large files = chunked upload, each chunk encrypted with a random data key, wrapped by the channel/file key

#### Layer 2 - Transport / Near-Invisible Metadata
- Tor-like onion relay network (3 hops), relays are stateless forwarders that only see ciphertext
- Relays: user-run (incentivized) + ~5 bootstrap relays in privacy-friendly jurisdictions (Iceland/Panama/Switzerland)
- Rotating assignment; no single relay sees the full path

#### Layer 3 - Storage for Media & Forum Persistence
- Client-side encryption → chunk + Reed-Solomon erasure coding (e.g., 12-of-8) → shards distributed via IPFS/Filecoin pinning across many providers in different countries
- Metadata (thread structure, who posted what timestamp — encrypted): stored on relays / small L2 chain commitments for censorship resistance

#### Layer 4 - Payments
- Accept: XMR (primary), BTC-Lightning + USDT for convenience; auto-convert internally to a single ledger denominated in USD ($10/month)
- Per-user deposit address (HD-derived, rotated monthly); payment confirmed → subscription extended by 30 days on his private ledger

## Implementation Status

This implementation includes:
1. **Crypto Layer**: Signal Protocol integration with Double Ratchet, Web3 bridge for Ethereum identity
2. **Android UI**: Forum and thread browsing interfaces 
3. **Relay Network**: Decentralized relay infrastructure simulation
4. **File Encryption**: Media encryption capabilities
5. **Identity Management**: User identity derivation from Ethereum addresses

## Build Instructions

### Prerequisites
- Android Studio 2023+
- Kotlin 2.0
- Java 17+

### Building
```bash
cd ghost-forum
./gradlew build
```

### Running on Device
```bash
cd ghost-forum
./gradlew installDebug
```

## Security Model

The application follows a zero-knowledge security model:
1. **Content Privacy**: All data is encrypted client-side before transmission
2. **Metadata Privacy**: Relay network only sees encrypted metadata and routing information
3. **Identity Privacy**: Users are identified through cryptographic keys, not personal information
4. **Jurisdictional Privacy**: Infrastructure is distributed across multiple jurisdictions to avoid single points of failure

## Privacy Requirements Addressed

1. **No central server can see conversations** - All content is client-side encrypted
2. **100% private conversations** - End-to-end encryption with perfect forward secrecy
3. **No intercepting messages** - Even developers cannot decrypt user communications
4. **No server in hostile jurisdictions** - Infrastructure distributed globally across privacy-friendly locations
5. **Private payments** - Crypto-based monetization system that doesn't reveal user identities

## License

MIT License - see LICENSE file for details.