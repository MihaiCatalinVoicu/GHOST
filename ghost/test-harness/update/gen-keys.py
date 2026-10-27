#!/usr/bin/env python3
"""Generates the UpdateWorld throwaway keyset (ops keygen's /dev/urandom is Linux-only; the
keyset format is 32-byte Ed25519 seeds + public keys, the RFC 8032 reference arithmetic)."""
import hashlib, secrets, sys

# RFC 8032, section 6.1 reference arithmetic (public domain).
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
Bx = xrecover(By)
B = (Bx, By)

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

def encodeint(y):
    return y.to_bytes(32, "little")

def encodepoint(P):
    x, y = P
    return ((y | ((x & 1) << 255)).to_bytes(32, "little"))

def publickey(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return encodepoint(scalarmult(B, a))

# Self-check against the RFC 8032 test vector before writing anything.
seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
want = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
got = publickey(seed).hex()
assert got == want, f"RFC 8032 self-check failed: {got}"

out = sys.argv[1]
for name in ("root-1", "release-1", "attest-1", "apk-1", "log-1", "witness-1"):
    s = secrets.token_bytes(32)
    with open(f"{out}/{name}.hex", "w") as f:
        f.write(s.hex())
    with open(f"{out}/{name}.pub", "w") as f:
        f.write(publickey(s).hex())
print("KEYS_BUILT")
