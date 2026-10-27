#!/usr/bin/env python3
"""Builds manifest-floorbad: the reachable FLOOR_INVALID case. The GHRM parser caps the floor
at the lowest release (manifest.rs), so the decision-level check (floor > attested_max,
decision.rs) needs attested_max below that cap: every release's attestation re-signed with a
key the root does not list (attest-2), floor at the lowest release. The GHRA binds the release
record only, so its statement is unchanged by the floor patch; the release block is re-signed
last, over the final body. Usage: floorbad.py <work-dir>"""
import hashlib, os, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghostsign

f = lambda b: hashlib.sha256(b).digest()
out = sys.argv[1]
d = open(f"{out}/manifest-1.ghrm", "rb").read()
assert d[:4] == b"GHRM" and d[4] == 1 and d[-97] == 1
body = bytearray(d[:-97])

keys = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
attest2 = bytes.fromhex(open(f"{keys}/attest-2.hex").read())
release1 = bytes.fromhex(open(f"{keys}/release-1.hex").read())

# Parse the release record (body offset 62: count u8, then the record; name is lp16).
pos = 62
assert body[pos] == 1
pos += 1
version_code = struct.unpack_from(">I", body, pos)[0]
pos += 4
nlen = struct.unpack_from(">H", body, pos)[0]
pos += 2 + nlen
flavor = body[pos + 1]
pos += 1 + 1  # min_sdk, flavor
anchor_root = struct.unpack_from(">I", body, pos)[0]
pos += 4 + 1  # flags
pos += 32 + 8  # apk_sha256, apk_length
unsigned_sha = bytes(body[pos:pos + 32])
pos += 32
unsigned_length = struct.unpack_from(">Q", body, pos)[0]
pos += 8
pos += 2 + 16  # rollout permille, salt
commit = bytes(body[pos:pos + 20])
pos += 20
es_seq = struct.unpack_from(">Q", body, pos)[0]
pos += 8
es_sha = bytes(body[pos:pos + 32])
pos += 32
nart = body[pos]
pos += 1
arts = []
for _ in range(nart):
    kind = body[pos]
    sha = bytes(body[pos + 1:pos + 33])
    ln = struct.unpack_from(">Q", body, pos + 33)[0]
    arts.append((kind, sha, ln))
    pos += 41

# 1. The attestation block (right after the release record) re-signed with the unknown key.
ghra = (b"GHRA" + b"\x01" + bytes([2]) + commit + struct.pack(">I", version_code) +
        bytes([flavor]) + struct.pack(">I", anchor_root) + unsigned_sha +
        struct.pack(">Q", unsigned_length) +
        struct.pack(">Q", es_seq) + es_sha + bytes([nart]) +
        b"".join(bytes([k]) + s + struct.pack(">Q", l) for k, s, l in arts))
stmt_at = b"ghost/v1/build-attestation\x00" + bytes([2]) + f(ghra)
assert body[pos] == 1  # one-entry attestation block
body[pos:pos + 97] = bytes([1]) + ghostsign.key_id(ghostsign.publickey(attest2)) + ghostsign.sign(attest2, stmt_at)

# 2. The floor at the lowest release (parse-level cap): above attested_max, which is now 0.
struct.pack_into(">I", body, 58, version_code)

# 3. Re-sign the release block with release-1, over the final body.
body = bytes(body)
stmt_rel = b"ghost/v1/release-manifest\x00" + bytes([2]) + f(body)
open(f"{out}/manifest-floorbad.ghrm", "wb").write(
    body + bytes([1]) + ghostsign.key_id(ghostsign.publickey(release1)) + ghostsign.sign(release1, stmt_rel))
print("FLOORBAD_BUILT")
