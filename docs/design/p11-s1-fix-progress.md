# p11-s1: fixing the review of Phase 11 slice S1 — progress (for a fresh agent)

**Status: complete** (2026-10-04). The commit that carries this text is the final (non-WIP) commit of
the fix; nothing is in progress and nothing is left to run on this machine. Branch `p11-s1` (worktree
`D:/Forum/.claude/worktrees/p11-s1`), never pushed, never merged. This file only served the
checkpoint protocol and can be deleted when the branch is merged: the permanent record is
`docs/design/faza11-media.md` §22.2 rows 27 (the review's dispositions), 28 (left to S2) and 29 (the
runs after the review), with rows 2–3, 5–10, 13, 15–16, 18–19 and 21 amended, and `docs/STATUS.md`.

## Findings (reviewer A = format/crypto/hostile input, B = fidelity/gates/honesty)

- Fixed, each with a test, vector, fixture or mutant that fails without the fix: A1–A7, A9, B1–B5,
  B7, B8; A8 for JPEG (the video profile's free bytes declared in row 9, with options); A10's wording.
- Recorded for S2, not decided here (row 28): A10/B6 read mode (§7.4 needs reads without a pass);
  the nonce registry's rule in the worlds.
- Rejected: none.

## Decisions

- aead-stream oracle: IN (dev graph only; the lock adds exactly aead-stream 0.6.0).
- B6/A10 read mode: NOT changed; options in row 28.
- A8: JPEG tightened; PPS body, SEI 0/1/6 bodies, esds bitrates, SPS timing/HRD declared with options (row 9).

## Trap

Cargo fingerprints a workspace's own packages by workspace-relative paths, so a test binary built from
a relocated copy of the tree into the same target directory is reused here with the copy's
`CARGO_MANIFEST_DIR`; after any run from a copy, `cargo clean -p ghost-client-media` first.
