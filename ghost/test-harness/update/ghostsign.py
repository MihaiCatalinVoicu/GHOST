#!/usr/bin/env python3
"""RFC 8032 Ed25519 signing for the UpdateWorld surgery fixtures (re-signing a patched GHRM
body with a key ghost-release-ops will not sign with). Same reference arithmetic as
gen-keys.py (self-checked against a library-verified test vector)."""
import hashlib

p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)

def xrecover(y):
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if x & 1:
        x = p - x
    return x

By = 4 * pow(5, p - 2, p) % p
B = (xrecover(By), By)

def edwards(P, Q):
    (x1, y1), (x2, y2) = P, Q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + d * x1 * x2 * y1 * y2, p - 2, p) % p
    y3 = (y1 * y2 + x1 * x2) * pow(1 - d * x1 * x2 * y1 * y2, p - 2, p) % p
    return (x3, y3)

def scalarmult(P, e):
    Q = (0, 1)
    while e > 0:
        if e & 1:
            Q = edwards(Q, P)
        P = edwards(P, P)
        e >>= 1
    return Q

def encodepoint(P):
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")

def publickey(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return encodepoint(scalarmult(B, a))

def sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    A = publickey(seed)
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % q
    R = encodepoint(scalarmult(B, r))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % q
    s = (r + k * a) % q
    return R + s.to_bytes(32, "little")

def key_id(pk):
    return hashlib.sha256(pk).digest()

if __name__ == "__main__":
    # Self-check against the cryptography library before any fixture use.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    want = sk.sign(b"ghost fixture self-check")
    got = sign(seed, b"ghost fixture self-check")
    assert got == want, "signer self-check failed"
    print("GHOSTSIGN_OK")
