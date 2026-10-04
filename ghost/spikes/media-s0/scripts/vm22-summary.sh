#!/usr/bin/env bash
# V-M22 summary: for every transcode line of the given probe reports, the whole-file rate
# (stream bytes x 8 / duration, container and audio included) against the design's profile of
# 2.128 Mbit/s (2 000 000 video + 128 000 audio, design §6.1), the overshoot, and what a source of
# VIDEO_MAX_MS = 160 s (or VIDEO_MAX_MS_SHORT = 85 s) would weigh at that rate against the
# 50 MiB cap (52 428 800 B) and class 8's cap (28 309 824 B).
#   scripts/vm22-summary.sh results/api35/transcode-short.txt results/api35/transcode-long.txt ...
# Reports of 2026-09-25 carry the stream length as `bytes=`, later ones as `streamBytes=`.
set -euo pipefail
awk '
/^#[0-9]+ transcode/ {
  src = ""; cbr = ""; mode = ""; dur = 0; bytes = 0; vbr = 0; err = ""
  for (i = 1; i <= NF; i++) {
    n = index($i, "="); if (n == 0) continue
    k = substr($i, 1, n - 1); v = substr($i, n + 1)
    if (k == "src") src = v
    else if (k == "mode") mode = v
    else if (k == "cbrUsed") cbr = (v == "true" ? "CBR" : "VBR")
    else if (k == "durationMs") dur = v + 0
    else if (k == "streamBytes") bytes = v + 0
    else if (k == "bytes" && bytes == 0) bytes = v + 0
    else if (k == "avgVideoBitrate") vbr = v + 0
    else if (k == "error") err = v
  }
  if (err != "null:null" || dur <= 0) { printf "%-22s %-15s %s failed: %s\n", src, mode, cbr, err; next }
  rate = bytes * 8 / (dur / 1000)
  over = (rate / 2128000 - 1) * 100
  s160 = rate * 160 / 8; s85 = rate * 85 / 8
  printf "%-22s %-15s %s dur=%6.2fs bytes=%10d whole=%7.3f video=%7.3f Mbit/s overshoot=%+8.1f%% 160s->%7.1f MB (%s 50 MiB) 85s->%6.1f MB (%s class 8)\n", \
    src, mode, cbr, dur / 1000, bytes, rate / 1e6, vbr / 1e6, over, s160 / 1e6, \
    (s160 <= 52428800 ? "within" : "OVER"), s85 / 1e6, (s85 <= 28309824 ? "within" : "OVER")
}' "$@"
