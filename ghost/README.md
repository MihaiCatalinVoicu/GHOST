# ghost/ — monorepo GHOST

Singurul cod activ al proiectului. Structura urmează `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §6.6 (Appendix B revizuit).

| Director | Conținut | Fază |
|---|---|---|
| `android/` | Client Android (Gradle, Kotlin, Compose). Module: `app`, `identity`, `crypto-bridge`, `messaging`, `storage`, `sync`, `network`, `entitlement`, `media` | 1 (schelet), 3+ |
| `relay/crates/*` | Relay blind (Rust): `api`, `storage`, `transport`, `gossip`, `prune`, `capability` | 1 (schelet), 5 |
| `issuer/` | Entitlement issuer (Rust): credențiale blind, Monero view-only, referral | 1 (schelet), 8 |
| `protocol/` | Scheme normative de wire: `relay/v1/relay.proto`, `issuer/v1/issuer.proto` | 1 |
| `scripts/gates/` | Gate-uri CI (anti-placeholder, logging, manifest, allowlist dependențe, proto, Rust, build reproductibil) + `self-test.sh` | 1 |
| `test-harness/gates/negative/` | Fixture-uri intenționat greșite care trebuie să facă gate-urile să eșueze | 1 |
| `infra/`, `docs/` | Deploy declarativ (onion services), documente de inginerie | 2+ |

Stadiu: vezi `../docs/STATUS.md`. Nicio afirmație de confidențialitate nu este permisă în acest stadiu.

## Build local

Cerințe: JDK 17 (toolchain pinuit), Android SDK cu `platforms;android-37.x` și `build-tools;37.0.0` (`ANDROID_HOME` setat), Rust 1.98.1 (`rust-toolchain.toml`), `protoc`, `cargo-deny`.

```bash
cd ghost/android && ./gradlew build
cd ghost && cargo test --workspace && cargo deny check
bash ghost/scripts/gates/run-all.sh && bash ghost/scripts/gates/self-test.sh
```

Detalii și probleme cunoscute pe Windows: `docs/DEVELOPMENT.md`.
