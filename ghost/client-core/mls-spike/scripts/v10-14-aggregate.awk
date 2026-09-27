# V10-14 (review pass): aggregates the job table of v10-14-crawl.sh. Evidence tooling, not product
# code (docs/design/faza10-s0-evidence.md §14). Counts only jobs that ran on the self-hosted runners
# (runner name ghost-runner-*); times in UTC; minutes are runner-minutes.
#
#   gawk -f v10-14-aggregate.awk -v FROM=2026-09-17 -v TO=2026-09-26 jobs-all.tsv
#
# Sections printed:
#   DAY      per UTC day: runner-minutes by trigger and the share of the day's 4 × 1 440 runner-minutes
#   NIGHT    per night as the first crawl defined it (the UTC date of the scheduled runs' creation;
#            window = first scheduled run created → last scheduled job ended): the scheduled jobs
#            alone (jobs, runner-min, span, longest queue wait), then every job's runner-minutes
#            inside the window by trigger
#   CRON     per scheduled workflow: the delay from its cron time to the run's creation
#   HOUR     runner-minutes by UTC hour of day, and the shares 02–07, 07–20 and 20–02 UTC
#   IDLE     minutes with at least one job waiting (created, not started) and no runner busy: the
#            runners were off (the laptop off or logged out); also the busy and all-four-busy minutes
#   JOBS     per workflow and trigger: jobs and runner-minutes; the longest jobs of dm-privacy-gate
function ts(x,   y) { y = x; gsub(/[-T:Z]/, " ", y); return mktime(y, 1) }
function day(t) { return strftime("%Y-%m-%d", t, 1) }
function clip(a, b, lo, hi) { if (a < lo) a = lo; if (b > hi) b = hi; return b > a ? b - a : 0 }
BEGIN {
  FS = "\t"
  if (FROM == "") FROM = "2026-09-17"; if (TO == "") TO = "2026-09-26"
  t0 = ts(FROM "T00:00:00Z"); t1 = ts(TO "T00:00:00Z")
  # The crons of .github/workflows/*.yml (minute hour), read by hand at the crawl's commit.
  cron["dm-emulator"] = 2 * 60 + 17; cron["dm-privacy-gate"] = 4 * 60 + 11
  cron["dm-state-models"] = 2 * 60 + 53; cron["entitlement-exit-gate"] = 3 * 60 + 41
  cron["messaging-exit-gate"] = 3 * 60 + 43; cron["monero-regtest"] = 2 * 60 + 23
  cron["signer-timing"] = 3 * 60 + 41; cron["t2-exit-gate"] = 2 * 60 + 17
}
NR == 1 { next }
{
  wf = $1; ev = $2; run = $3; rc = $6; job = $8; runner = $9; jc = $10; st = $11; en = $12; res = $14
  # Scheduled runs' creation (once per run).
  if (ev == "schedule" && !(run in seenrun)) {
    seenrun[run] = 1
    c = ts(rc); d = day(c)
    if (wf in cron) {
      dl = (c - (ts(d "T00:00:00Z") + cron[wf] * 60)) / 60
      if (!(wf in dmin) || dl < dmin[wf]) dmin[wf] = dl
      if (!(wf in dmax) || dl > dmax[wf]) dmax[wf] = dl
      dn[wf]++
    }
    if (!(d in w0) || c < w0[d]) w0[d] = c
  }
  # Queued intervals (every job, whatever its runner): created → started (or → now if never).
  if (jc != "-") {
    qa = ts(jc); qb = (st != "-") ? ts(st) : ((en != "-") ? ts(en) : t1)
    if (res == "skipped") qb = qa
    nq++; QA[nq] = qa; QB[nq] = qb
  }
  if (runner !~ /^ghost-runner-/ || st == "-" || en == "-") next
  a = ts(st); b = ts(en)
  n++; A[n] = a; B[n] = b; E[n] = ev; W[n] = wf; C[n] = ts(rc); J[n] = job; R[n] = runner
  if (ev == "schedule") {
    d = day(ts(rc))
    if (b > w1[d]) w1[d] = b
    sj[d]++; sm[d] += (b - a) / 60
    q = (a - ts(rc)) / 60; if (q > sq[d]) sq[d] = q
    if (wf == "t2-exit-gate") st2[d] += (b - a) / 60
  }
  jobsw[wf SUBSEP ev]++; minw[wf SUBSEP ev] += (b - a) / 60
  if (wf == "dm-privacy-gate") { pg[n] = (b - a) / 60 }
}
END {
  # DAY
  for (t = t0; t < t1; t += 86400) {
    d = day(t); tot = 0; line = ""
    delete by
    for (i = 1; i <= n; i++) { m = clip(A[i], B[i], t, t + 86400) / 60; if (m > 0) { by[E[i]] += m; tot += m } }
    line = sprintf("DAY %s busy %5.0f runner-min = %3.0f %% of 4 x 1440", d, tot, 100 * tot / 5760)
    for (k in by) line = line sprintf("  %s %5.0f (%2.0f %%)", k, by[k], (tot > 0 ? 100 * by[k] / tot : 0))
    print line
  }
  # NIGHT
  for (d in w0) nights[++nn] = d
  asort(nights)
  for (x = 1; x <= nn; x++) {
    d = nights[x]; if (!(d in w1)) continue
    printf "NIGHT %s scheduled: %2d jobs %5.0f runner-min (T2 %2.0f %%) span %5.1f h max queue wait %5.0f min\n", d, sj[d], sm[d], (sm[d] > 0 ? 100 * st2[d] / sm[d] : 0), (w1[d] - w0[d]) / 3600, sq[d]
    delete by; tot = 0
    for (i = 1; i <= n; i++) { m = clip(A[i], B[i], w0[d], w1[d]) / 60; if (m > 0) { k = E[i]; by[k] += m; tot += m } }
    line = sprintf("NIGHT %s window %s .. %s (%4.1f h): every job %5.0f runner-min", d, strftime("%m-%dT%H:%M", w0[d], 1), strftime("%m-%dT%H:%M", w1[d], 1), (w1[d] - w0[d]) / 3600, tot)
    for (k in by) line = line sprintf("  %s %5.0f", k, by[k])
    print line
  }
  # CRON
  for (wf in dn) printf "CRON %-22s %2d scheduled runs created %4.0f … %4.0f min after the cron\n", wf, dn[wf], dmin[wf], dmax[wf]
  # HOUR
  for (i = 1; i <= n; i++) {
    for (t = A[i] - A[i] % 60; t < B[i]; t += 60) {
      if (t < t0 || t >= t1) continue
      m = clip(A[i], B[i], t, t + 60) / 60; h = strftime("%H", t, 1) + 0
      hr[h] += m; all += m
    }
  }
  for (h = 0; h < 24; h++) printf "HOUR %02d UTC %6.0f runner-min (%4.1f %%)\n", h, hr[h], (all > 0 ? 100 * hr[h] / all : 0)
  for (h = 0; h < 24; h++) { if (h >= 2 && h < 7) s1 += hr[h]; else if (h >= 7 && h < 20) s2 += hr[h]; else s3 += hr[h] }
  printf "HOUR shares: 02-07 UTC %4.1f %%, 07-20 UTC %4.1f %%, 20-02 UTC %4.1f %%\n", 100 * s1 / all, 100 * s2 / all, 100 * s3 / all
  # IDLE (per minute from FROM to TO)
  for (i = 1; i <= nq; i++) for (t = QA[i] - QA[i] % 60; t < QB[i]; t += 60) if (t >= t0 && t < t1) waiting[t] = 1
  for (i = 1; i <= n; i++) for (t = A[i] - A[i] % 60; t < B[i]; t += 60) if (t >= t0 && t < t1) busy[t]++
  for (t = t0; t < t1; t += 60) {
    if ((t in waiting) && !(t in busy)) { off++; offd[day(t)]++ }
    if (t in busy) { bz++; if (busy[t] >= 4) full++ }
  }
  printf "IDLE jobs waiting with no runner busy: %d min (%.1f h); some runner busy: %d min; all four busy: %d min (of %d min)\n", off, off / 60, bz, full, (t1 - t0) / 60
  for (d in offd) printf "IDLE %s waiting with no runner busy: %5.0f min\n", d, offd[d]
  # JOBS
  for (k in jobsw) { split(k, p, SUBSEP); printf "JOBS %-22s %-17s %4d jobs %6.0f runner-min\n", p[1], p[2], jobsw[k], minw[k] }
  for (i = 1; i <= n; i++) if (W[i] == "dm-privacy-gate" && pg[i] >= 20) printf "PRIVACY-GATE %s %s %4.0f min %s\n", strftime("%m-%dT%H:%M", A[i], 1), E[i], pg[i], substr(J[i], 1, 70)
}
