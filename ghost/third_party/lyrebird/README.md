# GHOST Phase 12 — the lyrebird pluggable-transport binary

This directory pins the pluggable-transport (PT) binary shipped as an Android asset
(`assets/pt/<abi>/lyrebird`; design `docs/design/faza12-transports.md` §4.1, ADR-61).

## Provenance

- **Source**: [lyrebird](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird),
  the Tor Project's PT bundle (the successor of obfs4proxy), tag **0.9.0**, commit
  **89d54872b176f936232ff39f7a8189b77d83d65e** (a full git commit hash, never a mutable ref).
- **Tree**: the pinned upstream tree plus the pinned minimal patch `prune-snowflake.patch`
  (applied by `BUILD.sh` immediately after checkout; part of the D2 pin): snowflake, meeklite,
  obfs2, obfs3 and scramblesuit are removed, so the binary carries exactly the approved P0
  transport set — **obfs4 and WebTunnel**. Rationale and measurements:
  `docs/design/faza12-s0-evidence.md` §10 (OA-3 resolution).
- **Toolchain**: the pinned Go release named in `pins.env` (never the host's ambient Go), same
  NDK as `scripts/build-native.sh` for the x86_64 android target (CGO external linking).
- **Build**: `BUILD.sh` — two same-path builds per target, hash-compared (the reproducible
  double build), a builder-path leak check, outputs in `out/` (git-ignored) with the recorded
  hashes in `SHA256SUMS`. `HARNESS=1` additionally builds the host binaries for the §12.3
  loopback gate (`SKIP_ANDROID=1` builds only those).

## Licence

lyrebird is © 2023 The Tor Project / 2014–2023 Yawning Angel, distributed under the
**BSD-3-Clause** licence (read at the pinned tag; no GPL in the shipped set — the pruned
tree carries obfs4/WebTunnel code only, all BSD-3-Clause). The licence text as read at the
tag:

```
Copyright (c) 2023, The Tor Project
Copyright (c) 2014-2023, Yawning Angel <yawning at schwanenlied dot me>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 * Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

The binary is shipped unmodified (byte-identical to `SHA256SUMS`) as a compressed asset and
extracted at first use; it is executed only through arti's ptmgr wiring (design §5). The
generated APK notices gain a lyrebird component row in slice S4 (the generator's third part
for asset binaries; S3-T4 in `docs/design/faza12-s3-notes.md`).

## Bump procedure

Per §4.4: a bump edits `pins.env` only (tag, commit, source-archive and patch hashes, Go
pin, version stamp), re-runs `BUILD.sh` end to end, and re-runs the whole gate set (G-T1 …
G-T8) plus the loopback harness (PT-L1/PT-L2) at the new binary. Sizes and gzip budgets are
pinned in `pins.env` (G-T3).
