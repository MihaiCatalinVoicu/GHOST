# Consumer rules for :identity.
# BouncyCastle (bcprov): drop sealing (DropSeal, X25519KeyPair) uses X25519 and ChaCha20-Poly1305
# (ADR-24 amends ADR-17, deviation X15, Phase 8 design §19.12). Kept unshrunk and unmerged so the
# minified release runs exactly the classes the JVM vector tests (DropSealTest) exercise.
-keep class org.bouncycastle.crypto.agreement.X25519Agreement { *; }
-keep class org.bouncycastle.crypto.params.X25519PrivateKeyParameters { *; }
-keep class org.bouncycastle.crypto.params.X25519PublicKeyParameters { *; }
-keep class org.bouncycastle.math.ec.rfc7748.X25519 { *; }
-keep class org.bouncycastle.crypto.modes.ChaCha20Poly1305 { *; }
-keep class org.bouncycastle.crypto.engines.ChaCha7539Engine { *; }
-keep class org.bouncycastle.crypto.macs.Poly1305 { *; }
