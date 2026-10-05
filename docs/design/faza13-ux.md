# GHOST Phase 13: Production UX — Design (proposed)

| Field | Value |
|---|---|
| Status | **Approved by the owner on 2026-10-05 with the proposed defaults of Q1 … Q40** (proposed 2026-10-03) (the owner's rule: an approved design before implementation). ADR-53 … ADR-57 (Appendix A, Romanian) are "propus"; they become "propus, aplicat" only if the owner approves this design or lets the question defaults of §16 stand under the standing instruction to continue between phases. Nothing in this document is a UI claim (CP-10; `docs/STATUS.md`, row "Afirmații permise în marketing/UI": "niciuna"). |
| Revision | **2** (branch `p13-design`: revision 1 is `4aee8ce` on `197b2b4`; `main` was merged at `8a480a7` for Phase 14's revision 2). Revision 1 corrected after three adversarial reviews of 2026-10-03: protocol and cryptography (22 findings, ids `CR-…` here), privacy and metadata (21, `PV-…`) and feasibility, testability and scope (18, `FE-…`). Every finding was re-checked before it was applied — in the repository at the cited lines, in the CI run history (`gh run`), in AOSP sources, or at a primary source (Appendix C) — and §19 lists each with its verdict and disposition: **none was found wrong**; three were adopted in a different form, with the reason stated. The largest corrections: **the strict lock is deferred** to its own design (it stopped every quiet run, so a paid purchase would never deliver tokens, and it changed what relays and the issuer see; §5.3, Q6); a QR scan no longer marks a contact verified by itself (D34); payment instructions follow Phase 8's `PAYMENT_READY` timing (D35); onboarding sets the PIN and the privacy mode before the words and the trial (D36); the foreground session starts at unlock, not at the lock screen (D33); Phase 11's lock duties run at every hide and lock (X-U15); links no longer stay in the OS's task records (D7); the clipboard rule accounts for the cached-app freezer (D11); the claims register gates effect sentences whatever their author called them (D20); the update screens follow Phase 14's revision 2 (no in-app "verify this app", D25); the journeys run on the JVM and the emulator tier has a defined seam and a plannable gate (D27, Q44, Q45); the effort is restated in agent-days (D32). Revision 1 was the drafting author's synthesis of five research digests (2026-10-03); four digest claims were corrected there (Appendix C.3). |
| Date | 2026-10-03 |
| Phase | 13 (plan §6.2 row 13, the authoritative scope): "UX de producție: Compose, high-privacy mode, disclosures aliniate la §4, accesibilitate, stări offline/eroare, protecția ecranului și a textului (FLAG_SECURE permanent, mesaje fără selecție sau copiere, câmpuri sensibile pentru accesibilitate, clipboard sensibil cu ștergere automată; ADR-27)" (`docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md:317`) |
| Exit gate | "usability pe călătoriile P0 (invite → identitate → plată → DM/canal/media → update); T10 și T24 verzi" (plan:317), read with the spec's usability layer ("Mnemonic, invite, payment disclosure, recovery and safety warnings — moderated test with representative users", spec §13 p.22), FR-7.1's acceptance ("Automated accessibility and theme tests pass on supported devices", p.10), FR-7.8's ("Mnemonic/seed does not appear in screenshots, recents or persistent clipboard", p.10), NFR-10 (seed recovery < 3 min median, < 5 min p95, p.12) and C-10 (UI and legal disclosures match the guarantee matrix, p.28). §1.1 states what the gate proves and what it does not |
| Depends on | Phases 9, 10, 11 (plan:317). **In fact:** the Phase 8 code (the entitlement facade, `Entitlement.kt`), the Phase 9 code on `main` (the DM facade; Phase 9's own exit gate is open, `docs/STATUS.md`), the Phase 10 `Channels` facade (design approved 2026-09-27; code only as S1a WIP on branch `p10-s1a`), the Phase 11 media facade (design **proposed, not approved**), and Phase 14's `Updates` facade (design **revision 2, proposed, not approved**: `docs/design/faza14-distribution.md` at `bab523e`, on `main` and merged into this branch) for the update leg of the gate. Phase 13 also needs additions from those phases (§3.6: Phase 10's invite preview and channel listener, Phase 11's download-pause method, Phase 14's store-flavor behaviour) and closes a Phase 9 checklist item that Phase 9's own gate counts (§18 F-U12, Q51) |
| ADR impact | New: **ADR-53** (the UI layer: `:ui` module, gateways, unidirectional flow, coroutines confined to the UI, own navigation, no sensitive saved state, sessions at unlock), **ADR-54** (screen and text protection as implemented; refines ADR-27 points 1–6), **ADR-55** (the app lock, local wipe, seed backup and restore; the strict lock deferred), **ADR-56** (claims and disclosures in the UI: the claims register and its gate), **ADR-57** (new components and permissions: notifications, camera for QR, zxing core, `ghost://` links). Deviations X-U1 … X-U17 (§0.3). **Numbering:** Phase 10 uses ADR-40 … 43, T36–T41, LIMITE L8, migrations 6 and 7; Phase 11 ADR-44 … 47, T42–T47, L9, migration 8; Phase 14 ADR-48 … 52, T48–T52, L10, migration U. This design takes **ADR-53 … 57, T53–T57, LIMITE L11** and **migration UX**, the next free schema version at merge (Phase 14's X-D12 rule) |
| Sources | Master plan v2.1; spec v2.0 PDF (text extracted with `pdftotext -table`, since the Read tool cannot render it on this host: CP-01 … CP-10 and the guarantee matrix p.6, release stages p.7, FR-1.x p.8, FR-3.x/FR-4.x p.9, FR-6.x/FR-7.x p.10, FR-8.x p.11, NFR p.12, §6.1 modules p.13, §12.2 p.21, §13 p.22, roadmap row 13 p.23, DoD p.24, risks p.25, Appendix C p.28); ADR-01 … ADR-39; THREAT_MODEL v2.1; LIMITE; INVARIANTS T1–T35; STATUS; the Phase 7, 8, 9, 10, 11 and 14 designs; `docs/reviews/2026-09-25-faza9-review.md`; the Kotlin facades and gates (code identical at `197b2b4` and `8a480a7`); the CI run history (`gh run`, 2026-10-03); AOSP `frameworks/base` sources. Repository citations are `path:line` relative to the worktree root (`ghost/…` for the monorepo). `F7` … `F11`, `F14` = `docs/design/faza7-sync-engine.md` … `faza11-media.md`, `faza14-distribution.md` (revision 2); `INV` = `ghost/test-harness/privacy/INVARIANTS.md`; `TM` = `docs/THREAT_MODEL_v2.1.md`; `LIM` = `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`. Appendix C separates verified from assumed; Appendix D lists sources with access dates |

**How to read this document.** §0 is the summary: decisions, guarantees, deviations, non-goals. §1 fixes scope, requirements, the debts other phases left to Phase 13, and the contradictions found. §2 is the threat and privacy model of the UI layer, including what each Android protection does on API 29–37. §3–§10 are normative: the architecture (§3), the protection components (§4), lock, wipe, backup and restore (§5), the journeys and every screen state (§6), modes, timers and media honesty (§7), disclosures and the claims register (§8), the design system, accessibility and localisation (§9), the one schema migration (§10). §11 lists invariants, §12 tests and the exit-gate argument, §13 gates, CI and dependencies, §14 slices and effort, §15 risks, §16 owner questions, §17 owner actions, §18 findings outside the phase, §19 the first design review's findings and what became of each. Appendix A holds the ADR drafts (Romanian), Appendix B the text changes in other documents, Appendix C the evidence and the S0 checks, Appendix D the sources. A section marked "(normative)" wins over a summary table.

**Identifier conventions.** Decisions `D1…D36`; requirements `R13-1…R13-35`; guarantees `P-U1…P-U8` (privacy) and `CS-U1…CS-U7` (correctness and safety); deviations `X-U1…X-U17`; leak channels `C1…C17`; journeys `J1…J6`; disclosures `DC-1…DC-33` (DC-26 withdrawn in revision 2); invariants `T53…T57`; gates `G-U1…G-U12`; mutants `PM-U1…PM-U39` (privacy; PM-U21 withdrawn) and `MC-U1…MC-U18` (correctness; MC-U5 withdrawn); twin worlds `NI-UI1…NI-UI5` (renamed from revision 1's `NI-U1…NI-U3`, which collided with Phase 14's `NI-U1…NI-U5`); the real-clock test `RT-UI1`; behaviour variants `BV-1…BV-3`; S0 checks `V-U1…V-U34` (V-U11 withdrawn); risks `R-U1…R-U22`; questions `Q1…Q54`; owner actions `OA-1…OA-11`; findings `F-U1…F-U17`; residues `L11-U1…L11-U23` (new LIMITE section L11); review findings by the reviewers' own numbers, prefixed `CR-`, `PV-` and `FE-` (§19). Slices `S0a`, `S0b`, `S1`, `S1b`, `S2…S12` (S8 withdrawn in revision 2).

---

## 0. Summary

### 0.1 Decisions

| # | Decision | Rejected alternatives (why) | Plan / ADR alignment |
|---|---|---|---|
| D1 | **Scope, exactly as the plan states.** P0: the six journeys J1–J6 (§6) with every state, screen and text protection of ADR-27 points 1–6, high-privacy mode, disclosures aligned with plan §4 and §7, accessibility, offline and error states, and the callers the engines are waiting for (lock, wipe, key creation, notifications, display, payment hold). **Not designed here** although earlier documents pointed them at "Phase 13": card rotation with the P1 contact backup (F9 §12.5, Q27), Invite v3 (F9 Q32), opt-in read receipts (F9 Q8), the deniable reveal (F10 Q35), the ADR-13 governance engine (F10 Q15), history transfer, the prompt-mode foreground service (F7, ADR-20), the crash-report transport (FR-8.11), in-app media capture (F11 Q15), **and the strict lock with authentication-bound keys** (LIM:31's "per deblocare"; §5.3). Each is a protocol or engine change with relay- or issuer-visible behaviour; §1.4 gives each a successor and Q6 and Q19 ask the owner | absorbing them (roughly doubles the phase and mixes UX with protocol work that the T2, T27, T31, T32 and channel privacy worlds would have to re-prove) | plan:317; spec §3 (P1 may be off in a labelled private alpha, p.7) |
| D2 | **A new `:ui` Android library** holds the screens, the design system, the protection components, the state holders, the UI models and the gateway interfaces, and **depends on no `org.ghost.*` module**; `:app` stays the composition root and adds the gateway adapters, the notifier, the lock and wipe controllers, the link intake and the settings store (§3.1) | everything in `:app` (no compile-time wall: UI code could import storage, network or a facade internal, as `:messaging`'s `api` exports of `:sync` show); per-feature modules (eleven more build files for a single-activity app) | spec §6.1 lists a `ui` module (p.13); plan Appendix B folds "Compose UI" into `app/` (plan:352; X-U7) |
| D3 | **Unidirectional data flow over blocking facades.** Composable → intent → screen model → gateway (`suspend`) → adapter in `:app` (the blocking facade call on a bounded `ghost-ui-io` executor of two threads, never the main thread, so **at most two facade calls are in flight**) → immutable `UiState` in a `StateFlow`; engine change hints arrive content-free through one `ChangeHub` (conflated, drop-oldest) and trigger re-queries; status is polled every 2 s only while INTERACTIVE (§3.2) | composables calling facades (main-thread blocking: `DmActor.call` waits on a future without timeout, `DmActor.kt:199-216`); an MVI framework (no allowlisted library; plain state holders suffice) | ADR-19 (no protocol logic in Kotlin UI); FR-7.1 |
| D4 | **Coroutines only in the UI.** `kotlinx.coroutines` (already shipped, 1.9.0) may be used in `:ui` and in `org.ghost.app.ui`; every other module keeps ADR-20's "no coroutines", now enforced for all of them by G-U9 (G-DM1 covered only `:messaging` and `:crypto-bridge`) | callbacks everywhere (Compose's effects, `StateFlow` and `InterceptPlatformTextInput` are coroutine APIs); coroutines in engines (undoes the blocking-JNI model of ADR-20) | ADR-20 point 1 (X-U8); ADR-53 |
| D5 | **UI state dies at hide and at lock.** Screen models live in an `UnlockedSession` created at unlock and closed at lock; **at every hide they drop their `UiState`** and re-query at the return, so no decrypted list or text waits in a hidden process; **no sensitive value in `rememberSaveable`, `SavedStateHandle`, `rememberTextFieldState` or any `Bundle`**, and the activity's saved-state bundle is cleared (§3.3, T54); sensitive strings are typed `SensitiveText` (redacted `toString`, one unwrap site); the mnemonic is held as 24 word indices in an `IntArray` zeroed after use | Jetpack `ViewModel` per screen with `SavedStateHandle` (the bundle leaves the process to `system_server`, outside GHOST's encryption); keeping `UiState` while hidden (revision 1: decrypted state stayed in a hidden process for the whole timeout, PV-3) | ADR-27; FR-7.8; T3 |
| D6 | **Own navigation:** a typed back stack (`sealed interface Route`) owned by the session, `AnimatedContent`, activity-compose `BackHandler` and `PredictiveBackHandler`, a two-pane layout from 600 dp; never persisted, so a new process starts at the lock or home screen (§3.4) | Navigation 3 1.2.0 (stable since 2026-09-23; its `rememberNavBackStack` and saveable-state decorator persist keys and per-entry state, which GHOST would have to disable; +2 artifacts and a `navigationevent` bump for features worth ~500 lines); Navigation Compose (bundle-based graph) | Q3 |
| D7 | **One activity, one exported component, links that leave no trace in the OS.** `MainActivity` (a `SecureActivity`) is the launcher and the only target of `ghost://invite/`, `ghost://contact/` and `ghost://channel/` links. It is `launchMode="singleTask"` and `persistableMode="persistNever"`: the default `persistRootOnly` keeps the root activity's launching intent across restarts (developer.android.com, `<activity>`), which AOSP writes, link included, to `/data/system_ce/<user>/recent_tasks/<id>_task.xml` (`Task.saveToXml`, `TaskPersister`). A link is read once into memory, the activity relaunches itself into a clean task, a link redelivered from history (`FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY`) is ignored, and every link lands on a confirmation screen after unlock, never acted on automatically (§3.4, G-U11) | an activity per flow (more exported or task surfaces; T15m allows only the launcher); `setIntent(Intent())` alone (revision 1: it clears only the app's copy, PV-9, CR-20) | ADR-05, T15m, T16 |
| D8 | **Secure windows by construction** (§4.1): `SecureActivity` sets `FLAG_SECURE` before the first frame, `setRecentsScreenshotEnabled(false)` on API 33+, decor-level `setAccessibilityDataSensitive(YES)` on API 34+ and autofill exclusion on the decor; Compose `Dialog`, `Popup` and `ModalBottomSheet` inherit the flag (`SecureFlagPolicy.Inherit`); every View-based window GHOST could open by accident (`Toast`, `PopupWindow`, `android.app.Dialog`, `Spinner`, `AutoCompleteTextView`, `PopupMenu`, Media3 `PlayerView`) is banned (G-U1) | the flag per screen (forgettable); allowing `Toast` (a text toast is drawn by SystemUI, outside GHOST's window) | ADR-27 point 1; T10 |
| D9 | **Text cannot leave through the UI** (§4.2): no `SelectionContainer` anywhere; message, post, caption and media views expose no copy, share, "Trimite către" or drag; the root replaces Compose's `LocalClipboard`, so even the composer's own copy and cut go through the sensitive clipboard; **every editable field filters Compose's text context menu to cut, copy, paste and select-all**, so no `PROCESS_TEXT` action (Translate, other apps) receives selected text; URLs in messages are plain text (no link detection, no tap, no preview) | Linkify or `LinkAnnotation` (a tap opens a clearnet browser; phishing; ADR-08 "no link previews"); Compose's default clipboard (writes without `EXTRA_IS_SENSITIVE`, invisible to a grep gate); Compose's default text menu (Compose Foundation added `ProcessTextKey` items for `PROCESS_TEXT` activities, CR-14) | ADR-27 point 3, ADR-08; T24 |
| D10 | **Accessibility without content leaks, and without excluding users** (§9.3): every window decor-level sensitive on API 34+ plus `isSensitiveData` on every content leaf; all semantics kept for accessibility tools (TalkBack, Switch Access, Voice Access); new-message announcements content-free; long-press menus replaced by custom actions; a screen lists the enabled accessibility services with their tool and system flags (API 31+); **before the PIN, the 24 words or a passphrase is typed, a warning names any enabled service that can see the key presses** (any non-system service on API 29–30, any non-tool service on API 31–33); when a non-tool or unknown service is enabled, an opt-in hides content and keypad labels from all services | hiding content from all services by default (excludes blind users; ADR-27 keeps screen readers working); doing nothing below API 34 (ADR-27 point 4 asks for the warning; the keypads' key presses reach every service there, PV-13) | ADR-27 point 4; Q8 |
| D11 | **One sensitive clipboard** (`SensitiveClipboard.kt`, the "approved module" of T24): only user-requested, non-message data (the three link kinds, the own contact link, the payment subaddress and amount); always `EXTRA_IS_SENSITIVE`; **cleared 30 s after the copy while GHOST's process runs**, at lock and at wipe, checked-if-ours with focus and unconditional without (X-U3); the clip's ownership label is persisted, so a clip that outlived a frozen or killed process is cleared at GHOST's next focus if it is still GHOST's (Android 14+ freezes a cached process 10 s after it is cached, source.android.com); a timer that fires more than 5 minutes late clears nothing unconditionally; the seed, a channel passphrase, safety digits, the PIN and message text are never copied | the share sheet (`ACTION_SEND`) for invite links (another exposure path; Phase 11's proposed G-M1 bans it too); an alarm per copy (an OS alarm record at every copy, a new activity trace, PV-11; Q10 keeps it as an option); claiming the 30 s in the background (revision 1: impossible under the freezer, CR-10, PV-10) | ADR-27 point 5 (X-U3); T24; Q10 |
| D12 | **Keyboards** (§4.5): one `InterceptPlatformTextInput` at every window root ORs `IME_FLAG_NO_PERSONALIZED_LEARNING` into every editor; **the PIN, the 24 words and the 5-word channel passphrase are typed on in-app keypads** (no system IME, no paste, no autofill; the word keypad completes a word at its unique prefix, at most four letters); a one-time warning names the default keyboard unless it is AOSP's own (`com.android.inputmethod.latin`), because preinstalled keyboards (Gboard, Samsung Keyboard) have cloud and dictation features too | the system IME for secrets (cloud keyboards, keyboard clipboard histories, the flag is only a hint); warning only for non-system keyboards (revision 1: silent for preinstalled cloud keyboards, CR-17) | ADR-08, ADR-27 point 6 (X-U4); Q15, Q30 |
| D13 | **Notifications carry nothing** (§4.6): one channel; one constant text; no sender, conversation, content or (by default) count; `VISIBILITY_SECRET` by default; no badge; no `MessagingStyle`, `RemoteInput`, shortcut, bubble or person; payment, access, update states **and a pending key change** are never notifications (the key change is a persistent in-app banner with its bound, X-U17) | the OS default (sender and text); notifying `PAYMENT_READY` (F8 §19.11, E15: a timing signal); a key-change notification (a second text tells listener apps and the notification history that a key changed) | ADR-06, ADR-27 point 2, F9 Q19; T11 (X-U13) |
| D14 | **One app lock in Phase 13, mandatory** (§5): an app PIN (6–16 digits, optional biometric), auto-lock 1 min after the app is hidden by default. At every hide the screen models drop their state and the content-lock duties run (Phase 11's media duties included, X-U15); at lock come the curtain, the session's end and the one-shot routes popped; the DM context stays open, so background receipt, sweeps and notifications continue (X-U1). **The strict lock (keys bound to device authentication, process exit at lock) is deferred to its own design** (§5.3, Q6): it stops every quiet run (a paid purchase would never deliver tokens), every update run and the background DM and channel steps, and makes the client's cadence distinguishable to relays and the issuer | revision 1's strict mode in Phase 13 (CR-1, PV-1, PV-2, FE-5); lock = `ctxClose` in the live process (F9 §2.5's wording; it stops RECV and notifications in the shared process and protects against nothing a Keystore-capable attacker cannot undo, X-U1) | FR-1.8 (a configurable policy: PIN, biometric, timeout; p.8), FR-7.13, LIM:31-32, ADR-55 |
| D15 | **PIN verifier bound to the device:** `tag = HMAC-SHA256(K_pin, label ‖ salt ‖ PIN)` with `K_pin` a non-exportable Keystore key, stored in SQLCipher; **the failure counter is committed before each check**, the back-off runs on `elapsedRealtime` and is re-armed in full at every process start, and no time is stored; no automatic wipe (duress is P2) (§5.2) | an Argon2id-only verifier (a 6-digit PIN falls offline from a database copy in about an hour on one 24-thread host at the channel-password profile, F10 E-73); the device credential as the app PIN (often shared); a stored retry time (a wall-clock value a system-clock change skips, and an activity time in a T33 table, CR-6, PV-19) | ADR-08 "PIN de aplicație"; T33 |
| D16 | **Local wipe, crypto-shred first** (§5.5): every engine stack stops (DM and channels, media, updates, sync), key envelopes deleted, Keystore aliases deleted, files deleted, process exit; an interrupted wipe finishes at the next start, keyed on the missing database-key envelope; what the shred achieves depends on flash and on the Keystore's rollback resistance, and the copy says only that (V-U29); revocation is a separate P1 screen | revoke-and-wipe as one action (revocation is staggered over 24 h, ends the identity, and needs the device online, F9 §8.5); "from here the file is ciphertext nobody can open" (revision 1, CR-11) | FR-7.13; ADR-55 |
| D17 | **Seed backup before completion, behind a lock** (§5.6): the PIN exists before the words appear (D36); the 24 words appear only after activation is `ACTIVE`, then 4 random positions are checked; **a missed position comes back in the next challenge after the words are shown again**, and a full 24-word check is offered; onboarding is incomplete until the check passes; re-display needs the typed app PIN and the device credential, never a biometric alone; never copied or exported. **Restore** only through `Entitlement.restore`, after the PIN and the mode are set, then a "what was lost" screen | showing the words during activation (backs up an identity a failed trial wipes, F8 §8.3); a skippable backup (spec R-01 "mandatory verified backup"); a fresh subset after a miss (one miscopied word escapes a 4-of-24 check with probability C(23,4)/C(24,4) = 20/24 ≈ 0.83, CR-7) | FR-1.4 (p.8), R-01 (p.25) |
| D18 | **High-privacy mode** STANDARD by default, **chosen in onboarding before the invite is activated** (the trial's activation slot is drawn in the mode current at that moment, `TrialSteps.kt:204`, `Slots.kt:30-35`) and in Settings; **persisted in SQLCipher and applied by the sync runtime at database open in every process, before any session** (§7.1) | HIGH by default (sends delayed up to 10 min, extra days before new tokens are usable); choosing it after activation (revision 1: a HIGH user's trial tokens were usable at once, the issuer-to-relay timing link HIGH exists to blur, PV-5); SharedPreferences (a plaintext file saying "HIGH"); today's in-memory default (`SyncRuntime.kt:191`), which a job process never changes | ADR-20 point 3, plan:263 |
| D19 | **Closed list of UI-caused traffic** (T53, §2.4): only the user actions of §2.4 reach relays, the issuer or a mirror; no pull-to-refresh, no "check for messages now", no read of `paymentInstructions` outside the payment screen; UI facade reads are bounded (two in flight, polls every 2 s while INTERACTIVE, re-queries at most every 250 ms per screen), and **the delay they add to a due time-triggered DM turn is measured on the production actor thread (RT-UI1) against a bound fixed from V-U17**, not assumed away | refresh affordances (a user-timed list event breaks T19); "UI reads cannot move a time-triggered step across a minute" (revision 1: unachievable for any delay above zero, and untestable in the virtual-time worlds, CR-18, PV-7, FE-13) | T19, T23, T28, T31 |
| D20 | **Claims register** (§8): every privacy or security sentence has an entry with its kind (`LIMIT`, `FEATURE`, `GOAL`, `CLAIM`), evidence IDs and residue; **a sentence that states an effect on an adversary, another device, a relay or the network is a `CLAIM` whatever its author calls it** (a reviewed keyword list in both languages triggers the check); every string of the security, payment, media, channel and trust screens has a row; a `CLAIM` reaches a release only when its evidence is in the green list, each line of which names the run, the commit and the archived report's hash; evidence IDs are globally unique; forbidden phrases are gated in Romanian and English; the "Cine vede ce" page mirrors plan §4 with an evidence status per row | copy reviewed by eye (FR-8.7 wants a signed checklist; CP-10 wants traceability); kinds chosen by the author alone (revision 1: effect sentences could ship as `FEATURE`s without evidence, CR-12) | CP-10, FR-8.7, C-10, ADR-38 point 11 |
| D21 | **Design system:** Material 3 from BOM 2026.09.00 (`material3` 1.4.0), dynamic colour on API 31+ with fixed semantic colours for warnings, system fonts only, light, dark and system themes, bundled vector icons, no image library (§9.1) | bundled fonts (licence review, size); `ui-text-google-fonts` (a Google Play services font provider); `material-icons-extended` (size) | FR-7.1; ADR-06 |
| D22 | **Romanian and English at launch** (`values-ro` written first, `values` English as the fallback), informal "tu"; per-app language through `LocaleManager` on API 33+; BIP-39 words stay English (§9.4) | AppCompat for per-app language on API 29–32 (a large dependency for a settings convenience); Romanian only | Q9 |
| D23 | **QR through zxing core 3.5.4** (Apache-2.0, no runtime dependency) for encoding and decoding, with scanning on the platform Camera2 API inside GHOST's secure window (§4.7); **the 8-character check sum shown on a link detects damage, not substitution** | CameraX (adds `libimage_processing_util_jni.so` and several artifacts); ML Kit (Google Play services); zxing-cpp (native); the system camera intent (a third-party app sees the frame); a 32-bit code presented as protection against a substituted link (it can be ground with about 2³² work, CR-8) | FR-7.7 (p.10, P1), ADR-05; X-U10 |
| D24 | **Media UI on Phase 11's facade**: the platform photo picker (on a device without it, `ACTION_OPEN_DOCUMENT` directly, **never the `ACTION_SYSTEM_FALLBACK_PICK_IMAGES` route that the AndroidX contract prefers there and that Google Play services implements on GMS devices**, §19 FX-1), a Compose player over Media3 `media3-ui-compose` (no View popups), a `TextureView` surface inside the secure window, view-once and ephemeral copy that claims nothing the engine does not do; the pause-download switch, which needs a Phase 11 method (F-U9), says that relays see it (§6.6, §7.3) | Media3 `PlayerView` (its settings menu is a `PopupWindow`, outside `FLAG_SECURE`); the AndroidX picker contract as is (a Binder call to Google Play services on devices without the platform picker, ADR-06) | F11 §6.5, §11; L9-M3 |
| D25 | **Update UI on Phase 14's `Updates` facade (revision 2)**: user-requested check and download; install through `PackageInstaller` with the "Install unknown apps" prompt **after the Play Protect and developer-verification disclosure** (DC-28); the age of the release information (`manifestIssuedDay`); alarms for `CONFLICT`, `ROOT_CONFLICT`, `STALE`, `UNSUPPORTED`, `SDK_UNSUPPORTED`, `NO_MANIFEST` and `NO_CHANNEL`; **no in-app "verify this app"** (Phase 14 removed it: an APK reports whatever it likes; verification is `ghost-verify` on another device); a flavor without the updater shows the version only; nothing at app start (§6.7) | a check at start (X-D1 of F14: the mirror would see app opens); revision 1's in-app signer fingerprint (PV-4) | F14 §2.6, §7.3, §8.5, §9.5, F-D8 |
| D26 | **No foreground service in Phase 13** (neither prompt mode nor an upload service); Doze delays are declared | `remoteMessaging` or `dataSync` FGS now (needs its own ADR, unmeasured battery, `dataSync` capped at 6 h per 24 h on Android 15+, and it changes the relay-visible cadence) | F7 §5.4, F11 Q30 (Q16, Q17) |
| D27 | **Three test tiers with a defined seam** (§12). **JVM** (Robolectric 4.17 at SDK ≤ 35 on JDK 17): the protection suites, the recording gateways, the twins, the crash enumerations and **the journeys J1–J6 end to end over the real engines** (SQLite JDBC, the host DM library, the Phase 7–9 model relay and issuer, shared into `:app`'s tests as `storage/src/testShared` already is, `app/build.gradle.kts:102`). **Emulator:** the platform suites on the `gate` variant, whose gateways a build-type twin fills from a fixture (`src/gate`; the release twin has the real wiring and no switch, G-DM5's existing rule), run by a new test-only module with `AndroidJUnitRunner`, plus a black-box `adb` pass on the R8-shrunk release APK. **Devices:** two phones. Plus moderated usability rounds | emulator journeys (revision 1: no composition root existed for them, the model peers are JVM test classes, and a seam in release code is refused by G-DM5, FE-1); emulator only (CI blind until the KVM fix); Paparazzi or Roborazzi (new groups, no interaction, no dialogs) | FR-7.1 acceptance; INV T10, T24; Q45 |
| D28 | **Twelve gates G-U1 … G-U12** on the shared lexer (`source-text.pl`), the merged release manifest and the R8 mapping, each failing on an empty scan, each with a negative fixture, near-miss positives and an exact `self-test.sh` hit count, **and an adversarial evasion review before they count** (§13.1) | line greps (the §22.33 evasion review broke 27 of 27) | ADR-10; the Phase 9 gate practice |
| D29 | **Usability protocol** (§12.5): a formative round (5 participants, after S4) and a summative round (≥ 8, on the release candidate); **thresholds proposed for the owner to fix** (Q42): per journey ≥ 80 % unassisted completion, no critical error in more than one participant, comprehension items; NFR-10 timed; observation and audio with consent, no screen recording (`FLAG_SECURE` forbids it) | an expert walkthrough only (the spec asks for representative users) | spec §13 p.22, NFR-10 |
| D30 | **One schema migration (UX)**: `ui_settings`, `ui_lock` (no time column), `ui_crash`; nothing else of the UI is persisted (§10) | SharedPreferences or DataStore (plaintext files; T20's discipline extended by T54) | T20, T33 |
| D31 | **Facade additions are the minimum the screens need** (§3.6): F9 §13.2's designed-but-unbuilt `setListener` and contact names, conversation summaries without text, the conversation timer, per-message timer and expiry, reactions; entitlement `inspectInvite`, `openPurchases` **with a state that follows `PAYMENT_READY`**, `invites`, `activateGenesis`; identity mnemonic indices and the word list; a typed Keystore-loss status; Phase 10's invite preview and listener and Phase 11's download pause (coordination items); each re-runs its phase's gates | screens that persist ids of their own (a second store of state the engine owns) | F9 §13.2, F8 §11.2, §19.11 |
| D32 | **Effort, calibrated on Phase 9:** about **45–70 agent-days** to "implemented and tested locally" (about 4–7 calendar weeks at two parallel sessions); **the gate has no date this design can promise**: it waits on owner actions (the KVM runner, two phones, participants, counsel, staging) and on Phases 10, 11 and 14 delivering their facades (§14.2) | revision 1's "10–13 calendar weeks for a team of 5–6" (an uncalibrated team model that the Phase 10 and Phase 11 reviews had already withdrawn, FE-4); the plan's 4–6 weeks | plan:317 (X-U6, Q26) |
| D33 | **Sessions start at unlock.** The foreground session and the pending trial's retry start when the app is visible **and unlocked** (INTERACTIVE), not when a window becomes visible; an open whose intent carries a link waits a further U[0, 2 min] after the unlock, unless the user first takes an action of §2.4 (the moment is then the user's); hiding or locking ends the session. Any app can open GHOST at a moment it picks ("regardless of whether that app is visible to your app", developer.android.com, package visibility), and the launcher intent proves nothing about who sent it (`getLaunchedFromPackage` names the caller only if it opted in), so no open is trusted to start traffic; the user's unlock is | sessions at VISIBLE with the lock screen counting as visible (revision 1, Q31: an app or a web page could time a session start, PV-6); treating launcher opens as trusted (unauthenticated) | T19, T53; F7 §5.4, F8 §8.3 (X-U14) |
| D34 | **A scanned card is "in person" only when the user says so.** After a contact card is scanned, the app asks where the code was shown; only "on the person's own phone, in front of me" records `QR_IN_PERSON` (which starts the contact verified, `ContactSteps.kt:441-445`); "a photo, a message, a video call or another screen" and "I don't know" (preselected) record `LINK`, with the safety-number prompt | every scan as `QR_IN_PERSON` (revision 1: a forwarded or substituted code became a pinned, "verified" man in the middle, and falsified T35's PQ-R8 listing, CR-2) | F9 §8.4 (X-U16), T35 |
| D35 | **Payment screens follow Phase 8's timing.** The disclosures and the instructions open only for a purchase whose state is `READY` (the `PAYMENT_READY` predicate: at least U[1 h, 6 h] after the invoice arrived) or that was already shown and is not expired; "Cere factura acum" says the invoice still appears 1–6 hours later; an underpaid purchase returns to the same instructions screen (its outstanding amount, its hold); no "open in wallet" button by default (Q46); the copy asks the user to compare the first and last six characters of a pasted address | instructions as soon as an invoice exists (revision 1: `paymentInstructions` checks only the invoice and the disclosures, `EntitlementEngine.kt:230-251`, so the UI could defeat F8 §19.11's delay, CR-3); a top-up shown outside the payment screen (no hold); a wallet button (hands the subaddress to whichever app claims `monero:` and nudges same-device payment, PV-15) | F8 §5.3, §19.11; E15 |
| D36 | **Onboarding and restore order.** J1: welcome → database key → **PIN → privacy mode** → invite → confirmation → activation → words → check → notifications → disclosures; restore: database key → PIN → mode → words → `Entitlement.restore` → notifications → next steps. No seed word is shown or typed without a configured lock; the trial and the first sessions run in the chosen mode. The DM ACTIVATE then runs inside the foreground session already running, the order F9 §22.36 item 9(g) left unmeasured; behaviour variant BV-2 measures it (Q54) | revision 1's order (the words before the PIN, CR-7, PV-5 (a); the mode after the trial, PV-5 (b)) | FR-1.4, FR-1.8, NFR-10; F9 §22.36 item 9(g) |

### 0.2 Guarantees claimed (each has a test in §12; none is a UI claim before the gate closes, CP-10)

| ID | Guarantee | Proof |
|---|---|---|
| P-U1 | **Secure windows.** Every window GHOST opens (activity, dialog, popup, menu, sheet, player) carries `FLAG_SECURE` from its first frame; no code path clears it; API 33+ activities also refuse recents screenshots. What this does and does not stop on each Android version is §2.3, never a stronger sentence | T10: G-U1, JVM window-flag tests, emulator `dumpsys window` on every window, capture and recents checks with positive controls, the black-box pass on the release APK, device checklist; PM-U1 … PM-U3 |
| P-U2 | **No text path out.** No message, post, caption, media or pseudonym can be selected, copied, shared, dragged or handed to a text-processing app; every clipboard write GHOST makes is marked sensitive and cleared 30 s after the copy while GHOST's process runs, at lock, and at GHOST's next focus if it is still GHOST's; the seed, passphrases, safety digits and the PIN are never written to the clipboard | T24: G-U2, G-U3, JVM toolbar, menu-item and clipboard spies on a virtual clock, the emulator's real-clock clear in the foreground and its freezer case; PM-U4 … PM-U8, PM-U22, PM-U34, PM-U38 |
| P-U3 | **Content hidden from non-tool accessibility services on API 34+**, visible to tools; a warning before a secret is typed where a service can see the key presses | T24: JVM semantics canary walk; emulator dumps through a non-tool and a tool client; the keypad-event check (V-U33); PM-U9 … PM-U11 |
| P-U4 | **Notifications carry nothing but a constant text** (and an optional count), locked or not | T11: G-U10, JVM notification shadow, emulator `dumpsys notification --noredact` canary scan; PM-U12, PM-U13 |
| P-U5 | **No UI-caused traffic outside §2.4's closed list**, and no foreground session before the user unlocks | T53: G-U5, the recording-gateway suite (zero traffic-causing calls outside intent handlers), twins NI-UI1 … NI-UI5 (the DM world in STANDARD now; channels and media with their facades; HIGH when the DM world has it), RT-UI1, the open-without-unlock test; PM-U16, PM-U17, PM-U27 … PM-U29 |
| P-U6 | **No sensitive UI state outside SQLCipher and RAM**: no saved-state bundle content, no preference or file written by the UI except the declared ones, and no link in the task the OS persists | T54: G-U6, G-U11's manifest rule, JVM bundle canary scans, emulator sandbox inventory and recent-tasks scan; PM-U14, PM-U15, PM-U33 |
| P-U7 | **Lock curtain.** While locked no content screen is composed; the lock decision precedes the first frame after a return; a new process starts locked; at every hide the screen models hold no content state and the content-lock duties have run | T55: JVM frame and hide tests, state-machine tests, emulator dumps; PM-U19, PM-U20, PM-U35 |
| P-U8 | **No unbacked claim.** No sentence that states an effect reaches a release unless it is a `CLAIM` whose evidence is in the green list; every `GOAL` is printed with its status; no forbidden phrase appears in either language | T56: G-U8; PM-U24, PM-U37 |
| CS-U1 | **Wipe completeness and resumability**: after a wipe, the inventory of §5.5 holds; a crash at any step finishes at the next start | T57: JVM crash enumeration of the wipe steps; emulator inventory; MC-U3, MC-U4 |
| CS-U2 | **Lock state machine**: every legal and illegal transition tested; a PIN failure is committed before its check; the back-off survives a kill, a reboot and a clock change | JVM; MC-U1, MC-U2, MC-U14, MC-U15 |
| CS-U3 | **Payment timing**: the UI never opens the disclosures or the instructions before `READY` or after the deadline, and an underpaid purchase uses the same screen and hold | JVM journey and recording-gateway tests; PM-U31, PM-U32 |
| CS-U4 | **Every engine outcome has copy and an action** in both languages, Keystore loss included | reflection test over every enum the gateways map; MC-U7, MC-U18 |
| CS-U5 | **Limits are enforced before a facade call** (NFR-14) | JVM; MC-U10 |
| CS-U6 | **No facade call on the main thread; no deadlock with the DM actor** | thread assertions in every adapter, StrictMode in debug; PM-U26 |
| CS-U7 | **Onboarding order**: no seed word is shown or typed without a configured lock; the privacy mode is set before the trial and the first session; the persisted mode and the payment hold are applied before the first session of every process | JVM onboarding model and process-start tests; MC-U6, MC-U9, MC-U11 … MC-U13 |

### 0.3 Deviations from approved documents (each recorded in an ADR of Appendix A)

| # | Document | Deviation | Why | ADR |
|---|---|---|---|---|
| X-U1 | F9 §2.5, §13.7 ("Lock and wipe call `ctxClose`") | **no lock in Phase 13 closes the DM context**; `ctxClose` runs at wipe; the strict lock that would close it is deferred (Q6) | without authentication-bound keys the context reopens from the Keystore at any process start, so closing it protects against nothing, while it stops RECV and notifications in the process the background job shares | ADR-55 |
| X-U2 | INV T24 ("`setPrimaryClip` în afara unui singur modul aprobat") | the approved unit is one file, `SensitiveClipboard.kt`, plus the root that installs it as Compose's `LocalClipboard` | a Gradle module per file is overhead; the gate checks the file | ADR-54 |
| X-U3 | ADR-27 point 5 ("ștearsă … doar dacă clipboard-ul mai conține datele puse de GHOST") | the ownership check runs only while GHOST has focus; without focus the clear is unconditional, and only within 5 minutes of its due time | Android 10+ lets only the focused app or the default IME read the clipboard (developer.android.com, Android 10 privacy changes); a late unconditional clear would erase another app's newer clip | ADR-54 (Q10) |
| X-U4 | ADR-08, ADR-27 point 6 (`IME_FLAG_NO_PERSONALIZED_LEARNING` "pe toate câmpurile") | the flag is on every system-IME field; the secrets have no system-IME field at all | the flag is a hint (`EditorInfo` javadoc); keypads remove the IME from the secret path | ADR-54 |
| X-U5 | ADR-06 ("+ un foreground service opțional «mod prompt»"), F7 §5.4, F11 Q30 | no foreground service in Phase 13 | needs its own ADR and battery measurement; changes the relay-visible cadence (L2.1 point 4) | ADR-53 (Q16, Q17) |
| X-U6 | plan row 13 ("4–6 s") | effort stated in agent-days (≈ 45–70 to "implemented and tested locally"), the gate dated by owner actions and by other phases' facades | §14.2; the Phase 10 (§19.11) and Phase 11 (§17.2, Q22) practice | Appendix B.1 (Q26) |
| X-U7 | plan Appendix B (`app/ # Compose UI, DI, navigare`) | Compose UI in `:ui`; DI and wiring in `:app` | D2 | ADR-53 |
| X-U8 | ADR-20 point 1 ("fără coroutines"), F9 §16.3 | coroutines allowed in `:ui` and `org.ghost.app.ui` only | Compose is coroutine-based; the engines keep the rule, now gated for all of them | ADR-53 |
| X-U9 | F9 §12.5 (cut-off, Invite v3), F9 Q8, F10 Q15 and Q35, F11 Q15, LIM rows "rotația cardului (Faza 13)", LIM:31 ("per deblocare") | not designed in Phase 13; each gets a successor (§1.4, §5.3) | protocol or engine changes, not UX (D1) | ADR-53 (Q6, Q19) |
| X-U10 | F11 Q15 ("in-app CameraX in Phase 13") | the camera is used only for QR scanning, through Camera2; no CameraX | no new native library; media capture stays out (D23) | ADR-57 |
| X-U11 | F10 §4.5 (channel copy that compares channels with DMs, `faza10-forum.md:365`) | the comparison clause waits for ADR-36's evidence; the channel limitation sentence ships beside a parallel DM limitation (DC-31), so neither implies that the other is protected | a sentence saying DMs are protected is a PQ claim before M-1 … M-7 and the external review (ADR-36 point 6) | ADR-56 |
| X-U12 | ADR-27 point 1 ("pe fiecare fereastră a aplicației") read with Phase 11's X-M11 | unchanged in substance; made exact: `SurfaceView` layers inside secure windows are also marked secure (`setSecure(true)`) | a video surface is its own layer (V-U2) | ADR-54 |
| X-U13 | INV T11 ("Notificările cu dispozitiv blocat …") | constant text **locked or not**, hidden on the lock screen by default, no badge | F9 Q19: Android's notification history keeps what was posted | ADR-54 |
| X-U14 | F7 §5.4, F8 §8.3 and `SyncWiring.kt:18-21` ("visibility starts and stops the foreground session and lets a pending onboarding trial retry") | the foreground session and the trial retry start at unlock (INTERACTIVE); hiding or locking stops them | an app or a page can open GHOST at a moment it picks (D33) | ADR-53 |
| X-U15 | F11 §6.5 and `faza11-media.md:686, 719, 738, 978` (the media duties "hang off `GhostApp.onLock`") | the media duties run through `GhostApp.onContentLock()` at every hide and every lock; `onLock` has no production caller in Phase 13 | X-U1 leaves `onLock` uncalled, and a view-once handle or a player must not wait in a hidden process (CR-4, PV-12) | ADR-55 |
| X-U16 | F9 §8.4 ("An in-person QR scan of a card sets `verified`", `faza9-dm.md:1243`) | the UI records `QR_IN_PERSON` only after the user says the code was on the person's own phone in front of them | the camera cannot tell that screen from a photo, a forward or another screen (D34) | ADR-57 |
| X-U17 | LIMITE L7-D17 ("notificare persistentă în Faza 13", `LIM:286`) | a persistent in-app banner with the bound, never a system notification | a second notification text would tell listener apps and the notification history that a contact's key changed (T11, D13) | ADR-54 (Q52) |

### 0.4 What this design deliberately does not do

- It changes no relay, issuer or mirror protocol and no observable field (`allowed-observables.json` unchanged, T1 untouched); it adds no JNI function and no Rust crate (the closed lists G-R6, G-M6 and G-D5 are unchanged); every engine change is a facade addition listed in §3.6. **It does change, in `:app`, when the foreground session starts** (at unlock, D33): a change of timing that relays see, which T53, the twins and Appendix B declare.
- It does not detect root, malware or "unsafe devices": any such check runs on the attacker's system (LIM L1); it says so instead.
- It does not protect what is on screen from a camera, a second device, a modified client or a rooted phone (ADR-27 residues), nor speech heard by bystanders when a screen reader reads aloud.
- It does not disguise the app (no fake icon or name) and does not hide that GHOST is installed.
- It builds no duress PIN (P2, plan §6.5), no strict lock (Q6, §5.3), no multi-device, no backup of contacts or tokens (E11, F9 §8.6), no bridge configuration (Phase 12, ADR-16), no in-app installer of other apps' payments (ADR-03).
- It makes no privacy, security or post-quantum claim in the UI: every sentence that states an effect is a blocked `CLAIM` in the register until its evidence is green (§8).

---

## 1. Scope, requirements, non-goals

### 1.1 The exit gate, read precisely (normative)

The gate has three items. **(a) "usability on the P0 journeys"** is defined by §12.5: a summative moderated round with at least 8 representative participants on the release-candidate build, in which every journey J1–J6 reaches the completion, critical-error and comprehension thresholds that the owner fixes (Q42; §12.5 proposes them), NFR-10 is timed, and the journey scripts are green (on the JVM over the real engines, §12.2; the emulator carries the platform suites, §12.3). **(b) "T10 green"** is the evidence matrix of §12.7 for T10: G-U1, the JVM window tests, the emulator matrix on API 29, 33, 35 and 36 (AOSP) plus 37 (`google_apis`) under the run rule of §14.3 item 3, the black-box pass on the release APK, and the signed device checklist. **(c) "T24 green"** is the same matrix for T24: G-U2 … G-U4, the JVM clipboard, toolbar, menu-item and semantics tests, the emulator accessibility dumps on API 35 (a tool and a non-tool client), the clipboard's freezer case, and the device checklist.

**What the gate proves:** that the shipped UI — the `gate` variant for the instrumented suites and the R8-shrunk release APK for the black-box checks (§12.1) — opens no unprotected window, offers no text exit for message content, writes the clipboard only sensitively and briefly, hides content from non-tool accessibility services where Android enforces it, starts no session before an unlock, and that representative users complete the P0 journeys and understand the disclosures the spec names. **What it does not prove:** anything about relays, cryptography or payments (other phases' gates), behaviour on device builds outside the tested matrix, protection against a compromised device (a non-goal, plan:377), the strict lock (deferred, Q6), or that a user who understood a warning will act on it. The new invariants T53–T57 are in the closing checklist (§14.3) although the plan's gate names only T10 and T24 (Q36).

### 1.2 Requirements (normative; each has a source and a test in §12)

| ID | Requirement | Prio | Source |
|---|---|---|---|
| R13-1 | Compose, Material You, light and dark themes, accessibility labels, scalable text; "automated accessibility and theme tests pass on supported devices" | P0 | FR-7.1 (spec p.10) |
| R13-2 | Every window `FLAG_SECURE`, no off switch; `setRecentsScreenshotEnabled(false)` on API 33+; screenshots and recordings black; nothing in recents; "mnemonic/seed does not appear in screenshots, recents or persistent clipboard" | P0 | ADR-27 point 1; FR-7.14 (plan:276); FR-7.8 (p.10); INV T10 (`INV:18`) |
| R13-3 | Messages and media: no selection, copy, share, "Trimite către", text-processing action or drag out; the composer stays normal | P0 | ADR-27 point 3; INV T24 (`INV:32`) |
| R13-4 | Messages, pseudonyms, safety numbers and seed words `accessibilityDataSensitive` on API 34+; below 34, a settings warning when a third-party accessibility service is on; screen readers keep working | P0 | ADR-27 point 4 and consequences |
| R13-5 | Clipboard only for user-requested non-message data; seed never; `EXTRA_IS_SENSITIVE`; cleared after 30 s or at lock | P0 | ADR-27 point 5; FR-7.8 |
| R13-6 | `IME_FLAG_NO_PERSONALIZED_LEARNING` on all fields; a one-time third-party-keyboard warning; no link previews | P0 | ADR-08; FR-7.12 (plan:274) |
| R13-7 | Notifications without content, locked or not; an option to hide the count | P0 | ADR-06; ADR-27 point 2; F9 Q19 (`faza9-dm.md:2769`) |
| R13-8 | Auto-lock (default 1 min in background) and an app PIN; "biometric/PIN policy MUST be configurable" (here: the PIN, an optional biometric and the timeout; LIM:31's per-unlock key binding is the deferred strict lock, Q6); duress wipe P2 | P0 (duress P2) | FR-7.13 (plan:275); FR-1.8 (p.8); LIM:31-32, LIM:40 |
| R13-9 | Onboarding only with a signed invite or an explicitly configured genesis policy; deep link and QR; damaged QR and unknown version fail safely; version and checksum shown | P0 (display P1) | FR-1.5, FR-1.6 (p.8); FR-7.7 (p.10, P1); ADR-05 |
| R13-10 | 24 words; "the UI MUST verify a randomized subset before completion"; restore within NFR-10 (< 3 min median, < 5 min p95; the study includes entry, validation and first unlock) | P0 | FR-1.4 (p.8); NFR-10 (p.12); R-01 (p.25) |
| R13-11 | High-privacy mode; receipts, delivery status and typing off in it | P0 | plan:263 (FR-4.2/4.3 delta); ADR-08; ADR-20 point 3 |
| R13-12 | Disclosures aligned with plan §4 and §7; "Marketing and in-app claims MUST match the guarantee matrix"; a signed claim checklist; UI and legal disclosures match the matrix | P0 | plan §4, §7; CP-10 (p.6); FR-8.7 (p.11); C-10 (p.28) |
| R13-13 | Payment rail metadata and trust assumptions disclosed before payment, including the KYC-exchange warning; UX/legal review | P0 | FR-6.9 (p.10; the plan calls it FR-6.8, plan:270); F8 §7.4; TM S13 |
| R13-14 | Offline and error states for every engine outcome, from enums only (no free text, identifier or time) | P0 | plan:317; ADR-19 |
| R13-15 | Warn when a contact's identity key changes; verify a safety code; key replacement creates a blocking or explicit confirmation state | P0 | FR-4.6 (p.9); TM S12 |
| R13-16 | Block and delete local and documented: "UI accurately states what can and cannot be deleted remotely" | P1 | FR-4.7 (p.9); F9 §12.4 |
| R13-17 | DM text, media, reactions, reply references and delivery status (here: the send outcome, F9 D10) | P0 | FR-4.3 (p.9) |
| R13-18 | Disappearing messages: off, 5 min, 1 h, 1 d, 7 d, 30 d; default 7 d; a timer change is a message both sides see; the recipient's countdown starts at first display | P0 | ADR-27 points 7–9; ADR-32; FR-4.4 |
| R13-19 | Channels: create, invite (in a password channel the app generates a 5-word passphrase, only committers invite, the link is shown once and the passphrase retyped at each issue), accept, posts and replies, members and roles, remove, leave, reveal after a warning, fingerprint comparison, resync and split states; filter, mute and hide local | P0 (FR-3.6 P1) | F10 §10.3, §19.28, §19.29; F10 Q14, Q35, Q42–Q50; FR-3.x (p.9) |
| R13-20 | The base identity is linked to a channel pseudonym only by an opt-in reveal per person, with a warning | P0 | ADR-04; FR-3.9 (plan:261) |
| R13-21 | Media: picker, progress, states, viewer, view-once (P1); no plaintext cache, no share | P0 / P1 | F11 §6.5, §11; FR-7.4 (p.10) |
| R13-22 | Update: version, offers, the age of the release information, platform install after the Play Protect and developer-verification disclosure, alarms; no check at start; no in-app "verify this app" | P0 | FR-7.5 (p.10); F14 §2.6, §7.3, §8.5, §9.5, F-D8 |
| R13-23 | Licences screen before the first distribution (with the MPL note); security contact; the ADR-38 residue sentence beside any allowed claim | P0 | ADR-37 point 3; FR-8.6 (p.11); ADR-38 point 11 |
| R13-24 | No Google Play services, Firebase, analytics or crash SDK; every UI dependency allowlisted; no font, CDN or network outside the relay client | P0 | ADR-06; FR-7.11 (plan:273); INV T7 |
| R13-25 | Crash reports local, encrypted, user-reviewed, scrubbed; sending manual via Tor | P0 (sending: §1.4) | FR-8.11 (plan:280) |
| R13-26 | No relay, issuer or mirror traffic caused by the UI beyond declared user actions | P0 | derived from T19, T23, T28, T31 (`INV:27,31,36,39`) |
| R13-27 | Limits enforced by the UI before a call | P0 | NFR-14 (p.12); F9 §12.6; F10 (100 members, 9 channels, 16 000 B posts); F11 §6.6 |
| R13-28 | Payment timing: the payment-screen hold; instructions only from `PAYMENT_READY` (≥ U[1 h, 6 h] after the invoice arrived) or an earlier showing; `PAYMENT_READY` never an immediate notification; "invoice now" and "check now" in STANDARD only | P0 | F8 §5.3, §19.11; LIM E3, E15 |
| R13-29 | Non-technical P0 copy: compromised phone; dedicated device or GrapheneOS; "rezistență, nu imunitate"; a regional Tor guide; channel rules at entry; remote-deletion limits | P0 | LIM:41, :33, :87, :159, :141; FR-4.7 |
| R13-30 | The copy obligations of Phases 9, 10, 11 and 14 (listed with their sources in §8.3) | P0 | F9, F10, F11, F14 |
| R13-31 | Doze, offline, retry and process-death behaviour of the UI | P0 | FR-7.3 acceptance (p.10) |
| R13-32 | Backup and device-transfer inspection finds no seed, DB key, protocol state or plaintext cache | P0 | FR-7.9 (p.10); INV T4 (`INV:12`) |
| R13-33 | Callers for what the engines wait on: the content-lock duties, wipe, key creation, notification port, `markDisplayed`, `setConversationOnScreen`, payment screen, privacy mode, expedite | P0 | `GhostApp.kt:161-188`; F9 §10.3; F11 §6.5; F8 §19.11 |
| R13-34 | Emulator and device evidence the earlier phases left here: T6 dynamic (with an update run, F14 §10.2), T20 device inventory, T4 inspection (device-to-device included, the path that matters at target 37), G-DM5 and the release smoke test on the graph that ships | P0 | `INV:14,28,12`; F7:1301; F14:933; `docs/reviews/2026-09-25-faza9-review.md:122` |
| R13-35 | No link payload, crash message or UI content in an OS record GHOST controls (the persisted task, logcat, DropBox); the OS records it cannot control are declared | P0 | T3, T54; LIM L1.1; PV-9, PV-11, PV-17 |

### 1.3 Debts other documents left to Phase 13, and their disposition

| Debt | Source | Disposition |
|---|---|---|
| Callers for `GhostApp.onLock`, `onUnlock`, `onWipe` | `GhostApp.kt:167-188`; F9 §22.17; LIM L7-D19 | **`onWipe` in scope** (§5.5). `onLock` and `onUnlock` (DM context close and reopen) keep no production caller: no Phase 13 lock closes the context (X-U1). The new `onContentLock()` carries the duties Phases 11 and 13 attach to a lock (X-U15) |
| A creator of the database key, then `onDatabaseKeyCreated` | `GhostApp.kt:161-165`; `DatabaseKeyProvider.kt:19` | **In scope** (§3.6, §6.2) |
| Callers for the DM facade, then G-DM5 and the release smoke test re-run on the graph that ships (R8 strips the facade today) | Phase 9 review A-4 (`docs/reviews/2026-09-25-faza9-review.md:55,122`) | **In scope** (S4, S10) |
| `setListener` (designed, never built) | F9 §13.2; `Messaging.kt:11-27` | **In scope** (§3.6) |
| `NotificationPort` implementation, its permission ADR, notification evidence | `MessagingPorts.kt:16-38`; F9 §21.10 point 9 | **In scope** (§4.6, ADR-57) |
| `markDisplayed` (recipient countdown) | F9 §10.3 | **In scope** (§3.5) |
| `setConversationOnScreen`, previews, the pause-download switch, the media lock duties | F11 §6.5, `faza11-media.md:548, 686, 719, 738, 978`, L9-M3 | **In scope** (§3.5, §6.6); the duties at every hide and lock (X-U15); the pause needs a Phase 11 method (F-U9) |
| `paymentScreenShown` / `Hidden`; copy for E11, E15, E21, E23, E25 | `Entitlement.kt:64-71`; F8 §19.11; LIM L6 | **In scope** (§6.3), with the `PAYMENT_READY` gate (D35) |
| `SCHEDULE_CONFLICT`, `ISSUER_MISMATCH`, `REFUSED_BY_RELAY` as security alarms | F8:432; `EntitlementStatus` | **In scope** (§6.1, §6.9) |
| Licences screen | ADR-37 point 3; STATUS licence row | **In scope** (§6.8) |
| Privacy-mode UI | `sync/api/Types.kt:103-104`; F7:1616 | **In scope** (§7.1), chosen before activation (D18) |
| Emulator CI "in Phase 13"; T6 dynamic; T20 inventory; T4 | F7:1301; `INV:14,28,12`; LIM:66 | **In scope** (S0a proves the runner, S10 runs the suites); runner KVM is an owner action (OA-1) |
| Device checklist steps 6–7 of Phase 9 (app lock, restore UI) | F9 §15.10; `faza9-dm.md:3677` | **In scope** (S4), with the cycle recorded: Phase 9's gate counts them while Phase 13 depends on Phase 9 (F-U12, Q51) |
| The order of ACTIVATE and the first session start at onboarding | F9 §22.36 item 9(g) (`faza9-dm.md:4522`) | **In scope**: fixed by D36, measured by BV-2 (Q54) |
| A persistent signal for an undecided key change | LIM L7-D17 (`LIM:286`) | **In scope** as a persistent in-app banner (X-U17, Q52) |
| Reactions UI; "send again" for INDETERMINATE; reconnect counts; "the contact's clock looks wrong" | F9 §7.1, :1079, §8.6, :1100 | **In scope** (§6.4) |
| Phase 14's update screens, the "Install unknown apps" prompt, the STALE, CONFLICT, ROOT_CONFLICT, UNSUPPORTED and SDK_UNSUPPORTED alarms, the age of the release information, the copy of F14 §2.6 and L10, the Play Protect and developer-verification disclosure | F14 §0.4, §2.6, §8.5, F-D8 (`faza14-distribution.md:1324`) | **In scope** (§6.7) |
| Prompt-mode foreground service; an upload service | F7 §5.4, ADR-20 consequences; F11 Q30 | **Deferred** (D26; Q16, Q17) |
| Card rotation (cut-off) with the P1 contact backup; the reduced reply card | F9 §12.5, Q27, Q70; LIM L7 rows | **Deferred** to a separate protocol design (Q19) |
| Invite v3 (a card inside the invite) | F9 Q32, X-13; ADR-05 note | **Deferred** (Q19) |
| Opt-in read receipts (`read_upto`) | F9 Q8 | **Not built** (Q18) |
| Flags, quarantine, strikes, exclusion lists, verified channels | F10 Q15, ADR-13 (P1) | **Deferred** to an engine design (Q19); ADR-27's abuse-report path through these flags is therefore absent and declared (Q19, §8.3 DC-27) |
| The deniable reveal | F10 Q35 ("designed with Phase 13's reveal UX") | **Deferred** to a protocol design; Phase 13 ships the warning (Q19) |
| In-app media capture | F11 Q15 | **Deferred**; the camera serves QR only (X-U10) |
| Crash-report transport | FR-8.11; ADR-06 | **Local part in scope**, transport deferred (Q20) |
| Keys bound to per-unlock authentication | LIM:31 | **Deferred** to the strict lock's own design (Q6, §5.3) |
| The alarm under Doze (A-2) | Phase 9 review A-2 | **Owner** (recorded, §17) |

### 1.4 Non-goals and deferrals (each with the constraint that decides it)

| Item | Status | Constraint |
|---|---|---|
| Strict lock (authentication-bound keys, process exit at lock) | its own design after Phase 13's gate (Q6); §5.3 lists what it must solve | it stops quiet runs (purchases, revocations, payouts), update runs and background DM and channel steps; the T2, T23, T27, T31 and T32 worlds have no strict profile (CR-1, PV-1) |
| Card rotation, contact backup, Invite v3, reduced reply card | separate protocol design before Phase 15 (Q19) | new registrations and card indices are relay-visible; they reopen T27, T31, T32 |
| ADR-13 governance (flags, quarantine, strikes) | engine design with the channel engine, then its UI (Q19) | Phase 10 reserved formats only (`faza10-forum.md:735`); P1 may be off in a labelled alpha (spec p.7) |
| Deniable reveal | protocol design (Q19) | changes `CH-REVEAL` and the first DM; the warning ships now |
| Read receipts, typing, delivery receipts | none | F9 D10, Q8; a reflex-free opt-in needs its own world |
| Prompt mode, upload FGS | a later ADR (Q16, Q17) | FGS type and cadence; battery unmeasured |
| Crash-report sending | designed with an operator endpoint (Q20) | no endpoint exists; a new onion service is Phase 14/15 work |
| Release notes in the update screen | not shown (F-U11) | Phase 14's `GHRM` release record carries a version code and name only (`faza14-distribution.md:397`) |
| Duress PIN | P2 | plan §6.5; LIM:40 |
| Bridges and pluggable transports UI | Phase 12 | ADR-16; `client-core/net` refuses obfs4, webtunnel, snowflake lines today (STATUS Phase 6 row) |
| History transfer in channels | not designed | F10 Q11 (approved "none") |
| App disguise, hidden icon | not designed | not in the plan; the APK name and package are visible anyway |
| Multi-device, device linking | P2 | plan §6.5 |
| Root or malware detection | never | LIM L1: the check runs on the attacker's system |

### 1.5 Contradictions between documents and how this design resolves them

1. **FR numbering.** The spec's table (p.8, read with `pdftotext -table`) numbers the randomized-subset rule FR-1.4, the invite payload FR-1.6, inviter eligibility FR-1.7 and the configurable biometric/PIN policy FR-1.8; the plan (plan:259-260) and LIMITE (LIM:31) cite them one lower, and the plan's FR-6.8 (KYC warning, plan:270) is the spec's FR-6.9. This design cites the spec's numbers and lists the errata (Appendix B.1, F-U1).
2. **What "lock" does.** F9 §2.5 and §13.7 say lock closes the DM context; with the default unbound keys (ADR-20 Q6, `AppDatabase.kt:16`) the context reopens at any process start, so a closed context in the live process only stops RECV and notifications. Resolution: X-U1 (no Phase 13 lock closes the context); the strict lock that would bind keys is deferred (item 10).
3. **T24's "single approved module"** vs a Compose app whose text fields write the clipboard through `LocalClipboard`: resolved by replacing `LocalClipboard` at every window root (X-U2).
4. **ADR-27 point 5's ownership check** needs a clipboard read Android allows only to the focused app, and a cached process is frozen: X-U3 and the persisted label (D11).
5. **ADR-08's IME flag "on all fields"** vs the flag being a hint: secrets move to keypads (X-U4).
6. **The channel PQ sentence** (F10 §4.5) states that DMs are protected, which ADR-36 point 6 forbids before the model and the review: X-U11.
7. **"Startup update checks"** (FR-7.5) vs Phase 14's update runs (F14 X-D1): Phase 13 follows Phase 14; nothing happens at start.
8. **Phase 9's facade** (`Messaging.kt`) lacks what its own design promised the UI (`setListener`, names; F9 §13.2): built here (§3.6).
9. **NFR-10's p95** needs about 20 restore trials; a moderated round of 8–10 cannot produce it: the gate reports the median and the p95 only with ≥ 20 trials, otherwise "unverified" by the spec's measurement rule (p.12) (Q23).
10. **LIM L1 asks for keys "cu autentificare biometrică/PIN per deblocare"** (LIM:31) while ADR-20 Q6 keeps the key unbound by default, and Phase 8 made quiet runs, which need the database in the background, the only route of automatic issuer calls (F8 D14): binding the keys is a cross-phase engine change, deferred to its own design (Q6, §5.3); LIM L1's row is amended to say so (Appendix B.1).
11. **"Foreground" meant "visible"** (F7 §5.4, F8 §8.3, `SyncWiring.kt:18-21`) while any app can make GHOST visible: the foreground starts at unlock (D33, X-U14).
12. **Phase 11 hangs its lock duties on `GhostApp.onLock`** (F11:978) while X-U1 leaves `onLock` uncalled: the duties move to `onContentLock`, run at every hide and lock (X-U15).
13. **Phase 9 records any card scan as in person** (F9 §8.4) while a camera cannot tell a person's phone from a photo of it: the user's answer decides (D34, X-U16).
14. **Phase 14 revision 1 offered a "verify this app" value; revision 2 removed it** (`faza14-distribution.md:266, 844`): Phase 13 follows revision 2 (D25).

---

## 2. Threat and privacy model of the UI layer

### 2.1 Assets that exist only because there is a UI

| Asset | Where it appears | Harm if it leaks |
|---|---|---|
| Decrypted messages, posts, captions, media pixels (AS-4) | screens, Compose state, JVM `String`s, GPU buffers | content disclosure |
| The 24 words (AS-1) | backup, verification, restore | identity takeover, every channel pseudonym |
| Safety numbers and their QR; channel fingerprints | verification screens | confirms who talks to whom (a fingerprint of two identities, F9 §8.4) |
| A channel's 5-word passphrase | create, invite, accept | admission oracle for leaked links (F10 §19.29.3) |
| Contact aliases the user types | lists, headers | social graph in plain words |
| Invite links and the own contact link (bearer) | share screens, the OS's task records if a link launched the app | an invite burned; "may message me" handed to a stranger (L7-D25) |
| Payment instructions (subaddress, amount, deadline) | payment screen | ties a person to an invoice (E7, E15) |
| The app PIN | lock screen | defeats the curtain |
| Entitlement and update states, notification activity | banners, notifications | activity timeline |
| The moments GHOST is opened, unlocked, notified or uses the camera | relay session starts, OS usage records | activity timeline (C16, C17) |
| UI settings (HIGH mode, lock timeout, notification options) | settings | tells an examiner what the user chose |

### 2.2 Leak channels, controls, residues (normative)

| # | Channel | Adversary (TM §3) | Control (section) | Residue (LIMITE L11) | Test |
|---|---|---|---|---|---|
| C1 | A person holding the unlocked phone | AD-8 without root | mandatory app lock, curtain before the first frame; a failure committed before each check; back-off on `elapsedRealtime` (§5.1, §5.2) | the PIN is a UI gate; with root it is brute-forceable on the device (L11-U8); a biometric unlock can be compelled (L11-U22) | T55 |
| C2 | Screenshots, screen recording, casting by apps or the OS | malware, MediaProjection clients | `FLAG_SECURE` on every window (§4.1) | a camera; a modified client; root (ADR-27); keyboards on API 29–30, and on later levels until V-U1 measures them (L11-U2) | T10 |
| C3 | Recents thumbnails and task snapshots on disk | AD-8 | `FLAG_SECURE` + `setRecentsScreenshotEnabled(false)` | a placeholder snapshot is still written (`isRealSnapshot=false`, src) | T10 |
| C4 | Accessibility services | malware with accessibility access; services that lie about being tools | decor-level and leaf sensitivity on API 34+; the services screen, the warning before secrets and the opt-in hiding below (§4.3) | everything, keypad presses included, on API 29–33; lying services on 34+; window events that show when GHOST is in front (assumed, V-U33); system tools (L11-U3, L11-U20) | T24 |
| C5 | Keyboards (third-party and preinstalled IMEs, cloud dictation, keyboard clipboard history) | IME vendor | IME flag; keypads for secrets; warning unless the keyboard is AOSP's (§4.5) | the composer's text and dictation reach the keyboard (L11-U5) | T24, EditorInfo test |
| C6 | Clipboard (other apps at paste time, keyboards, cross-device clipboard sync) | apps, IMEs | one sensitive helper, the 30-s clear while running, the persisted ownership label, no secrets (§4.4) | the 30-s window; keyboard histories; a clip that outlives a frozen or killed process until GHOST's next focus or Android 13+'s own clear; an unconditional clear can erase another app's newer clip (L11-U4, L11-U19) | T24 |
| C7 | Notifications (lock screen, listeners, wearables, history) | onlookers, listener apps | constant text, `VISIBILITY_SECRET`, no badge (§4.6) | the moment a notification appears equals a decryption moment (L11-U6); usage records keep it (C16) | T11 |
| C8 | Assistant, Content Capture, OEM screen AI | system and OEM | `FLAG_SECURE` (assist structure and Content Capture off for secure windows; on API 37 `setContentCaptureEnabled(false)` no longer works, developer.android.com behaviour changes 17) | OEM features not tested (L11-U1) | T10 device steps |
| C9 | Autofill services | password managers | autofill exclusion on the decor; secrets on keypads (§4.5) | manual autofill requests (src) | V-U6 |
| C10 | Shoulder surfing, cameras | bystanders | short timers, lock | always possible | — |
| C11 | Forensic examination of a seized phone | AD-8 with root, AD-12 | nothing outside SQLCipher and RAM (T54); no link in the OS's task records (D7); wipe (§5.5) | settings and the PIN-failure counter in SQLCipher; OS residues (L11-U10, L11-U11, L11-U17); Keystore deletion final only with rollback resistance (L11-U21) | T54, T57 |
| C12 | Relays and the network observing UI-caused traffic | AD-1, AD-2, AD-4 | the closed list of §2.4; sessions only after an unlock; bounded reads | app use: the foreground session starts at unlock (L11-U12) | T53 |
| C13 | The user's own mistakes | — | plain-language disclosures, usability study (§8, §12.5) | understanding is not action | §12.5 |
| C14 | Hostile `ghost://` intents from other apps; link hijacking by apps claiming the scheme; links kept by the OS | malicious apps; AD-8 | strict parse, confirmation screen after unlock, `persistNever`, the clean relaunch, QR in person recommended (§3.4) | a link opened elsewhere can be read or replaced (L11-U13); the task record in memory until the relaunch (V-U31) | G-U11, JVM, V-U31 |
| C15 | Tapjacking and overlays | overlay apps | Android 12+ blocks touches from untrusted overlays above 0.8 opacity (developer.android.com, behaviour changes 12); `filterTouchesWhenObscured` on confirm screens (§4.1) | partial overlays below API 31 | V-U1 |
| C16 | OS records of use: usage events (activity resumed, paused and stopped; notification interruptions with an obfuscated channel id), the camera permission history, DropBox crash entries, tombstones | apps with usage or notification access; AD-8 with ADB or root | nothing GHOST can turn off; no exception message reaches the platform handler (§10); notifications optional | when GHOST was opened, notified and used the camera (L11-U17, L11-U23) | device checklist (§12.6 step 10) |
| C17 | An app or a web page that opens GHOST at a moment it picks | malicious apps, web pages, colluding relays | sessions only at unlock (D33); an open that carries a link waits U[0, 2 min] more | when the user unlocks, the session start follows the open by seconds to minutes (L11-U18) | T53 open-without-unlock test |

### 2.3 What each protection does on Android 10 … 17 (API 29 … 37)

Legend: **doc** = verified at developer.android.com, source.android.com or the Microsoft Learn mirror of the AOSP javadoc (2026-10-03); **src** = read in AOSP or AndroidX sources by the research and not re-read here, unless Appendix C.2 says so; **S0** = to be measured (V-U checks, Appendix C.4).

| Protection | 29 | 30 | 31–32 | 33 | 34 | 35 | 36 | 37 | Never covers |
|---|---|---|---|---|---|---|---|---|---|
| `FLAG_SECURE`: screenshots and recordings by apps, ADB, MediaProjection; insecure displays | yes | yes | yes | yes | yes | yes (ADB `screencap` draws secure layers black, src) | yes | yes | camera, modified client, root (`LSPosed` modules), userdebug builds with `DISABLE_SECURE_WINDOWS` (src) |
| `FLAG_SECURE`: recents thumbnail replaced by the theme placeholder | yes (src) | yes | yes | yes | yes | yes | yes | yes | the placeholder file itself |
| `FLAG_SECURE`: IME window protected when its target is secure | **no** (src) | **no** | yes (src) | yes | yes | yes | yes | yes | **unverified**: public reports disagree; V-U1 captures the keyboard on every level and L11-U2 stays conditional until it does |
| `FLAG_SECURE`: Assist structure, Content Capture off | yes (src) | yes | yes | yes | yes | yes | yes | yes, and the only opt-out (doc) | app overrides of `onProvideAssistData` (banned) |
| `FLAG_SECURE` against accessibility screenshots by system tool services | — | — | — | — | — | — | from 16 QPR2 tools may capture secure layers (src, S0 V-U20) | same | — |
| `setRecentsScreenshotEnabled(false)` | — | — | — | yes (doc: "only affects … Overview"; the system may still screenshot elsewhere) | yes | yes | yes | yes | screenshots in other contexts (doc) |
| `accessibilityDataSensitive` / `isSensitiveData` | ignored | ignored | ignored (tool flag readable from 31, doc) | ignored | **enforced** for non-tool services (doc API 34) | enforced | enforced | enforced; with Advanced Protection, non-tool services are blocked outright (secondary sources) | services that declare `isAccessibilityTool` falsely (self-declared; checked only by Play's policy and by Play Protect where it runs, so on a device without Google Play services nothing checks it); tools; speech; the window events a non-tool service may still receive (assumed, V-U33) |
| Key presses on in-app keypads, as accessibility events | every enabled service | every enabled service | every enabled service | every enabled service | non-tool services blocked by the decor flag | same | same | same | a service that lies about being a tool |
| `EXTRA_IS_SENSITIVE` on a clip | ignored | ignored | ignored | preview hidden (doc) | yes | yes | yes | yes | "does not change clipboard behavior" (src); keyboard histories |
| Clipboard read restricted to the focused app or default IME | yes (doc) | yes | yes; a toast when an app reads another app's clip (doc) | yes | yes | yes | yes | yes | the focused app, the IME |
| System clears the clipboard about 1 h after a copy | no | no | no | yes (doc "secure clipboard handling"; DeviceConfig-controlled, src) | yes | yes | yes | yes | — |
| Cached-app freezer: a cached process's threads stop, timers included | no | supported from Android 11, device-dependent (doc; S0 V-U28) | same | same | **frozen 10 s after it is cached** (doc); on by default on Pixel and some other devices (secondary) | same | same | same | a manifest broadcast, a job or the user's return unfreezes it (doc) |
| `IME_FLAG_NO_PERSONALIZED_LEARNING` | hint | hint | hint | hint | hint | hint | hint | hint | an IME that ignores it (`EditorInfo` javadoc) |
| `VISIBILITY_SECRET` notification on a secure lock screen | yes | yes | yes | yes | yes | yes; content hidden during screen sharing (doc behaviour changes 15) | yes | yes | notification listeners; wearables; history |
| Untrusted overlay touches blocked | no | no | yes above 0.8 opacity (doc) | yes | yes | yes | yes | yes | — |
| Compose's text menu offers `PROCESS_TEXT` actions (app-side, Compose Foundation 1.9+, `ProcessTextKey`) | GHOST filters them on every level (D9; S0 V-U26 measures what appears) | | | | | | | | — |
| A deleted Keystore key cannot be restored (rollback resistance) | device-dependent: "an attacker who has previously managed to retrieve the key material could potentially restore it" without it (doc, KeyMint implementer reference); read from key attestation (S0 V-U29) | | | | | | | | file deletion is not erasure |

The UI copy never says more than this table. The "Securitate" screen states the protections that apply on the user's own API level, from this table (§6.8).

### 2.4 UI-caused traffic: the closed list (normative; T53)

Everything not in this table causes **no** relay, issuer or mirror traffic and no change of a read schedule, session start or session end. Rendering, scrolling, opening a conversation, the lock screen, `markDisplayed`, `setConversationOnScreen`, previews, verification, safety numbers, blocking, accepting or rejecting a request, adding a contact, copying, notifications and every status read are local.

| User action | Facade call | What becomes visible, and to whom | Declared in |
|---|---|---|---|
| Unlocking the app while it is visible (an open that carried a link adds U[0, 2 min], ended early by the user's first action of this table) | `SyncController.onAppForeground()` → foreground session; a pending trial retries (`Entitlement` foreground hook) | relays see the foreground cadence (app use); a pending trial makes one issuer call (L3) | D33; LIM L2.1 point 4; L11-U12, L11-U18 |
| Hiding the app, or locking it while visible | `onAppBackground()` | the foreground session ends | `SyncRuntime.kt:100-102` |
| Send, post, react, set a timer, retry, send again, reset a session, reconnect, revoke (P1) | `Messaging.*`, `Channels.*` enqueue | stores at the next pair events (HIGH: delayed U[0, 10 min]) | T19; F9 §11.1 |
| Expedite after a send (STANDARD only) | `SyncController.requestExpedite()` | the work lane wakes for due stores; no read event | `SyncController.kt:10`; F7:1400 |
| Create a channel, invite, accept, remove, leave, set policy, reveal, resync | `Channels.*` | commits, Welcome, join requests at pair events | F10 §7.7 |
| Send media, retry media | `sendMedia`, `retryMedia` | the upload burst | F11 §12.1 |
| Pause or resume media download | Phase 11's pause method (F-U9) | `M_0` listing stops or resumes (relay-visible) | F11:548, L9-M3 |
| Activate an invite | `Entitlement.activate` → `RedeemInvite` in the foreground | one issuer call (L3) | F8 §8.3; E3 |
| Invoice now, check now (STANDARD only) | `requestInvoiceNow`, `checkNow` | one issuer call each (L3) | F8 §11.2; E3 |
| Buy, claim a payout, create or revoke an invite, auto-renew with credits | `startPurchase`, `claimPayout`, `createInvite`, `revokeInvite`, `setAutoRenewWithCredits` | issuer calls in later quiet runs only | F8 §12.2, §19.11, §19.14 |
| Show the payment instructions | `paymentInstructions`, `paymentScreenShown` / `Hidden` | relay sessions close and stay held U[20, 60] min | F8 §19.11; E15 |
| Change the privacy mode | `setPrivacyMode` | read pages per event, send delays, slot days | ADR-20 point 3 |
| Check for an update, download it | `Updates.requestCheck`, `requestDownload` | mirror fetches on the `Update` scope, possibly while a foreground relay session runs: an operator of a relay and a mirror can line them up (L10-D20) | F14 §7.3, Q47 |
| Install an update | `Updates.install` → `PackageInstaller` | **not GHOST traffic:** on GMS devices Play Protect may send app details or the APK to Google, and the developer verifier may look the install up at Google (L10-D9, L10-D24) | F14 §8.5; DC-28 |

### 2.5 The property the gate proves

For a device running the closing commit's builds on a tested API level — the `gate` variant for the instrumented suites and the R8-shrunk release APK for the black-box checks (§12.1, §12.3) — (i) every window GHOST opens is secure from its first frame and none is made insecure (T10); (ii) no UI path writes message, post, media or secret text to the clipboard, another app, a text-processing action, a drag, or a non-tool accessibility service on API 34+, and every clipboard write GHOST makes is sensitive and cleared within 30 s while GHOST runs and at its next focus otherwise (T24); (iii) notifications carry a constant text (T11); (iv) only §2.4's actions cause traffic, and no session starts before an unlock (T53); (v) the UI keeps no sensitive state outside SQLCipher and RAM, and no link in the OS's task records (T54); (vi) locked means nothing composed, and hidden means no content state held (T55); (vii) no unbacked claim ships (T56); (viii) a wipe leaves §5.5's inventory (T57); and (ix) representative users complete the P0 journeys and understand the named disclosures (§12.5). It says nothing about a compromised device, about OEM builds outside the matrix, about OS records GHOST cannot control (C16), or about what a user does after understanding a warning.

---

## 3. Architecture (normative; ADR-53)

### 3.1 Module layout

| Module / package | Contents | May depend on |
|---|---|---|
| `:ui` `org.ghost.ui.shell` | `GhostRoot` (the window root: theme, IME interceptor, clipboard override, curtain), `Route`, `BackStack`, the route host, banners, the two-pane layout | Compose (BOM 2026.09.00), `activity-compose` 1.13.0 (`BackHandler`, `PredictiveBackHandler`), `lifecycle-runtime-compose` 2.11.0, `androidx.window` 1.5.0 (size classes), `core-ktx` |
| `:ui` `org.ghost.ui.protect` | `SecureActivity`, `SecureDialog` helpers, `SensitiveText` (value class), `SensitiveTextView` (the one unwrap site), `GhostTextField` (with the text-menu filter), `ImeIncognito`, `SensitiveClipboard`, `PinPad`, `WordKeyboard` | the above |
| `:ui` `org.ghost.ui.design` | colour, type and shape tokens, components (buttons, banners, list items, state panels, `HoldToConfirm` with its accessible alternative) | `material3` 1.4.0 |
| `:ui` `org.ghost.ui.qr` | `QrImage` (zxing encoder drawn on a `Canvas`), `QrScanner` (Camera2 preview on a `TextureView`, zxing decoder on `ghost-qr`) | `com.google.zxing:core` 3.5.4; platform `android.hardware.camera2` |
| `:ui` `org.ghost.ui.platform` | `SystemIntents.kt` only: the photo or document picker launcher (§6.6) and the "Install unknown apps" settings intent (§6.7) — the one file of `:ui` that may name `android.net.Uri` and build an `Intent` | the above |
| `:ui` `org.ghost.ui.gateway` | the gateway interfaces, UI models and UI enums (§3.2); nothing else | `kotlinx-coroutines` (already shipped, 1.9.0) |
| `:ui` `org.ghost.ui.feature.*` | `onboarding`, `restore`, `lock`, `access`, `dm`, `channels`, `media`, `settings`, `security`, `update`, `about` | the packages above only |
| `:app` `org.ghost.app` | `GhostApp`, `MainActivity` (extends `SecureActivity`), `SyncWiring`, `MessagingWiring`, `AppDatabase` (existing roles; `GhostApp`'s lifecycle wiring changes, X-U14) | every module |
| `:app` `org.ghost.app.ui` | gateway adapters, the `ghost-ui-io` executor, `ChangeHub`, `AppPresence`, `LockController`, `ContentLock`, `LinkIntake`, `WipeController`, `GhostNotifier`, `SettingsStore`, `CrashCapture`, `KeystorePin` | `:ui` and the engines |
| `:app` `src/release`, `src/debug`, `src/gate` `org.ghost.app.ui.GatewayFactory` | a **build-type twin** (the `DmBranch` pattern, `GhostApp.kt:90-94`): the release and debug halves build the real adapters and nothing else; the gate half can serve a fixture to the emulator's platform suites (§12.3). G-DM5 already accepts a name a release source set declares too, and refuses what only the gate half names | as `org.ghost.app.ui` |
| `:app-uitest` (new, `com.android.test`, never shipped) | the emulator platform suites against `:app`'s `gate` variant, with `AndroidJUnitRunner`, Compose test rules and ATF; Phase 9's own suites keep `AppDeviceRunner` (`app/build.gradle.kts:23`) in `:app`'s androidTest | `:app` (`targetProjectPath`), test dependencies only (§13.3) |

**Rules (gated).** `:ui` declares no `project(…)` dependency and names no `org.ghost.*` package outside `org.ghost.ui` (G-U5); it names no network, storage or file API (G-U5 reuses the lists of `kotlin-clearnet.sh` and G-DM1 and adds SQLite, `File` writes and `openFileOutput`), except `android.net.Uri` and `Intent` construction in `SystemIntents.kt`. `:app` reaches a traffic-causing facade method (the list of G-U5, §13.1) only from the adapter files allowlisted for it (G-DM2's pattern), and `:ui` calls a gateway method marked `@UserAction` only from a screen model's intent handler (`on…` functions of `*Model.kt`). No new JNI function and no Rust code: Phase 13 is Kotlin only, and the closed native lists (G-R6 for `DmNative`, G-M6 for `MlsNative`, G-D5 for `UpdateNative`) are unchanged; the Kotlin analogue of a closed surface is the gateway list of §3.2, which G-U5 checks against the adapters. `ui-tooling` (previews) is declared only as `:app`'s `debugImplementation`, never in `:ui`: the `gate` build type resolves library modules to their debug variants (`matchingFallbacks`, `app/build.gradle.kts:51-56`), so a `debugImplementation` in `:ui` would put previews into the gate APK that the gate devices install.

### 3.2 Data flow, threads, unavailability

```
Composable ── intent ──▶ ScreenModel (main thread; StateFlow<UiState>)
                           │ suspend gateway call
                           ▼
            gateway interface (:ui)  ◀── implemented by ──  adapter (:app, org.ghost.app.ui)
                                                              │ blocking facade call on ghost-ui-io (2 threads)
                                                              ▼
                     Messaging · Channels · media · Entitlement · SyncController · Updates · IdentityBackup
ChangeHub ◀── content-free hints (MessagingListener, ChannelListener) ; status polls every 2 s while INTERACTIVE
```

- **Gateways** (closed list, each method mapped to exactly one facade method or a local composition): `IdentityGateway` (create the database key, inspect and activate an invite, activation state, restore, mnemonic indices for display, backup challenge, **the BIP-39 word list** read from `:identity`'s `Bip39Wordlist` so the UI holds no copy of its own, and **new passphrase indices** drawn with `SecureRandom` in the adapter), `LockGateway`, `AccessGateway` (entitlement), `DmGateway`, `ChannelGateway`, `MediaGateway`, `UpdateGateway` (**null in a build without `:update`**, Phase 14's store flavor, `faza14-distribution.md` §8.2 (c)), `StatusGateway` (sync, entitlement and Keystore status), `SettingsGateway`, `WipeGateway`. UI models are `data class`es of UI enums, local ids and `SensitiveText`; no engine type crosses into `:ui`.
- **Threads.** Every adapter call runs on `ghost-ui-io` (a fixed pool of 2, wrapped as a coroutine dispatcher) and asserts its thread name (CS-U6); debug builds add StrictMode `penaltyDeath` for disk and network on the main thread (in `src/debug`, never shipped). The DM actor serializes its own calls in the order posted (`DmActor.kt:199-216`): a long actor pass delays a UI read, and a due time-triggered turn waits behind at most the two UI calls the pool can have in flight. RT-UI1 measures that wait on the production actor thread (§12.2) and the gate holds it to the bound V-U17 fixes.
- **Unavailability.** A facade that is `null` (`GhostApp.messaging` before the first database open, `GhostApp.kt:77`) or that throws `IllegalStateException` (a stopped actor, `DmActor.kt:194`) maps to `Unavailable(STARTING)` and is retried at the next hint; `CRYPTO_UNAVAILABLE`, `NATIVE_MISSING` and `KEYSTORE_LOST` map to the states of §6.9. Adapters never cache a facade instance, because the stack is replaced when the database reopens (`MessagingWiring.kt:229-264`).
- **Hints.** `ChangeHub` is a `MutableSharedFlow<ChangeKind>` with `extraBufferCapacity = 64` and `DROP_OLDEST`, fed by `tryEmit` from the engine's thread (the listener must never block the actor, F9 §13.7); a lost hint is harmless because models re-query. Screen models conflate hints and re-query at most every 250 ms, with at most one read in flight each.
- **Polling.** `SyncController.status()` (it opens a read transaction), `Entitlement.status()` and `Updates.status` are polled every 2 s while the app is INTERACTIVE, never otherwise. The UI's total read rate is bounded (at most about ten facade reads per second in the worst screen, never more than two in flight).

### 3.3 State holders, the unlocked session, hide and lock

- **`UnlockedSession`** is created by `LockController` at unlock (and during onboarding before a lock exists) and closed at lock: its coroutine scope is cancelled, every screen model and its `UiState` dropped, and the content composition replaced by the lock screen.
- **At every hide** (`MainActivity.onStop` that is not a configuration change), whether or not the timeout will lock at the return, `ContentLock` runs: every screen model drops its `UiState` (lists, decrypted texts, previews) and re-queries when the app is shown again; the composition shows a neutral panel until then; `GhostApp.onContentLock()` closes every open media handle (a view-once handle closes as viewed, F11's `VIEW-ONCE-CLOSE`), releases players, clears the preview cache and sets the on-screen signal to `null`; the payment screen is hidden (`paymentScreenHidden`). The DM context, the database and sync are untouched (X-U1).
- **At lock**, in addition: the routes that must not reappear after an unlock are popped — `ViewOnce`, `MediaViewer`, `PaymentInstructions`, `Backup` (the words), `Reveal` and the wipe confirmation — so the user lands on their parent screen; the clipboard is cleared if it still holds GHOST's clip (checked with focus, §4.4). The rest of the back stack (routes hold only local ids) survives a lock in memory.
- **Drafts** (the composer's text per conversation) are kept in memory across hides and locks and lost at process death; they are never persisted (F9 §7.3 crash table: "the draft lived in memory"; Q34).
- **No saved state.** `SecureActivity.onCreate` passes `null` to `super.onCreate`, and `onSaveInstanceState` clears the bundle after `super` (T54; V-U16 checks AndroidX tolerates both). `rememberSaveable`, `SavedStateHandle`, `rememberTextFieldState` (it is saveable) and `@Parcelize` UI models are banned in `:ui` and `org.ghost.app.ui` (G-U6). Text fields use `remember { TextFieldState() }`.
- **`SensitiveText`** is a value class over `String` with `toString() = "SensitiveText(redacted)"`; its unwrap is called only in `SensitiveTextView.kt` (G-U3), which renders it with `isSensitiveData = true`. A reflection test fails if any UI model has a `String` property outside a reviewed allowlist (route and enum names).
- **The mnemonic** is an `IntArray` of 24 word indices, rendered from the word list the identity gateway returns, zeroed when its screen leaves; no `String` is built from the root (F-U4 removes the `String` of bits the current encoder builds, `Bip39.kt:29-36`). A JVM test checks that the gateway's list hashes to `:identity`'s list, and a round trip (indices → displayed words → `Entitlement.restore` → the same root) runs in the journey suite.

### 3.4 Navigation and links

- **Back stack:** a `SnapshotStateList<Route>` in the session; `Route` is a sealed interface of plain objects and data classes (onboarding steps, `Restore`, `Home(tab)`, `Conversation(id)`, `ContactAdd`, `MyCard`, `Requests`, `SafetyNumber(id)`, `KeyChange(id)`, `ContactInfo(id)`, `ChannelList`, `Channel(id)`, `ChannelCreate`, `ChannelInvite(id)`, `ChannelAccept(link)`, `Members(id)`, `Reveal(id, member)`, `Access`, `Purchase(id)`, `PaymentInstructions(id)`, `Invites`, `Payout`, `Settings(section)`, `WhoSeesWhat`, `Accessibility`, `Backup`, `Wipe`, `Update`, `About`, `Licences`, `Crash`, `MediaViewer(id)`, `ViewOnce(id)`). Transitions by `AnimatedContent`; back by `PredictiveBackHandler` on the top route; nothing is written to a bundle.
- **Two panes** from a window width of 600 dp (`androidx.window` size class): conversation and channel lists beside their detail. Android 17 removes the opt-out from orientation and resizability rules on large screens for apps targeting API 37 (developer.android.com, behaviour changes 17), so every screen is resizable and rotatable (V-U24).
- **Links (normative).**
  1. The launcher activity has `VIEW` filters for `ghost` with the hosts `invite`, `contact` and `channel` only (no `http` or `https`, no `autoVerify`), and the manifest attributes `android:launchMode="singleTask"` and `android:persistableMode="persistNever"` (G-U11). With the default `persistRootOnly` "the root activity's launching intent is used" across restarts (developer.android.com, `<activity>`), and AOSP writes that intent's data to `/data/system_ce/<user>/recent_tasks/<id>_task.xml` (`Task.saveToXml` → `Intent.saveToXml`; `ActivityRecord.isPersistable`; `TaskPersister`), outside SQLCipher and outside T57's wipe.
  2. `LinkIntake` reads the link once, in `onCreate` or `onNewIntent`, bounded to 1 024 characters, into a `PendingLink` held by the `Application` object in memory; then the activity removes it from its intent (`setIntent(Intent())`) and, when the link was the task's launching intent, relaunches itself with an explicit intent and `FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TASK`, so the task's base intent carries no link and a recreation after process death does not process it again (V-U31 checks `dumpsys activity recents` and the task file; the in-memory record until the relaunch is declared, L11-U13).
  3. Link data on an intent marked `FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY` is ignored.
  4. A pending link is acted on only after unlock, through a confirmation screen that shows its kind, version and check sum (§4.7). Another app may fire any `ghost://` intent at GHOST and may claim the scheme itself (L11-U13); QR in person stays the recommended path (ADR-05). An open that carried a link delays the first foreground session after the unlock by U[0, 2 min] (D33).

### 3.5 Lifecycle: presence, sessions, lock timing, "displayed", "on screen", payment

- **`AppPresence`** = HIDDEN, VISIBLE (a GHOST window is shown, possibly the lock screen; `ProcessLifecycleOwner` ON_START) or INTERACTIVE (VISIBLE, `MainActivity` resumed, and unlocked — onboarding before a lock exists counts as unlocked).
- **Sessions follow INTERACTIVE (D33, X-U14).** `GhostApp`'s process observer keeps only the local step at ON_START (the DM stack is built if a database is open, `MessagingWiring.onVisible`, `GhostApp.kt:140`); `SyncController.onAppForeground()` and the entitlement engine's foreground hook (the pending trial's retry, `EntitlementEngine.kt:142-145`) run when presence becomes INTERACTIVE, after a further U[0, 2 min] drawn from `SecureRandom` when the open carried a link (the wait ends at once if the user takes an action of §2.4 first: a user issuer call such as the activation needs the foreground, `SyncRuntime.kt:781`, and the moment is then the user's); `onAppBackground()` and the entitlement engine's hidden hook (which keeps an open payment screen's moment, F8 §19.11) run at ON_STOP and at a lock while visible. While the app shows only its lock screen, no foreground session exists, and a periodic job that fires then runs as Phase 7 decides (`SyncRuntime.kt:95-99`).
- **Lock timing:** `MainActivity.onStop` (not a configuration change) records `hiddenAt = SystemClock.elapsedRealtime()` in memory and runs the hide duties of §3.3; `onStart` locks when `elapsedRealtime − hiddenAt ≥ timeout` (0, 60, 300 or 1 800 s; default 60 s, LIM:32) before the next frame, because a Compose state change made in `onStart` is applied before the frame that follows. A timeout of 0 locks at `onStop`. A new process starts locked when a lock is configured. Round trips to the photo picker, the camera permission dialog or system settings count like any other hide (no grace, Q29).
- **"Displayed"** (`markDisplayed`, the recipient's countdown, F9 §10.3): an incoming message counts as displayed when its item is at least half visible for 500 ms in a conversation screen while INTERACTIVE; calls are batched every 500 ms. A notification, a list summary or a TalkBack read of a list never counts.
- **"On screen"** (`setConversationOnScreen`, F11 §6.5): the contact of the top route while INTERACTIVE; `null` at lock, at hide and on leaving the route.
- **Payment screen:** `PaymentInstructions(id)` is reachable only for a purchase whose `PurchaseView.state` is `READY` or `UNDERPAID` (§3.6, D35). `paymentScreenShown(id)` at every resume of that route while INTERACTIVE, `paymentScreenHidden(id)` at pause, at hide and when the route leaves (F8 §19.11; `Entitlement.kt:64-71`). No other screen calls `paymentInstructions`, whose read marks the purchase shown (`EntitlementEngine.kt:230-251`) and so ends `cancel` and `PAYMENT_READY`; G-U5 confines the call to the payment adapter.
- **Privacy mode and payment hold at process start:** the mode is read from `ui_settings` on the sync runtime thread when the runtime opens the database, before any job or foreground session, posted in `SyncWiring.onProcessStart` beside the payment hold's restore (`SyncWiring.kt:34-39`), so a job process obeys HIGH too and the first session of a new process is both in the persisted mode and held when a hold is due (MC-U9, MC-U11).

### 3.6 Facade additions (normative; each re-runs its phase's gates)

| Module | Addition | Why | Gates and tests re-run |
|---|---|---|---|
| `:messaging` | `setListener(MessagingListener?)` with `fun interface MessagingListener { fun onChanged(kinds: Set<ChangeKind>) }`, `ChangeKind ∈ {CONTACTS, MESSAGES, REQUESTS, TRUST, OUTCOMES, STATUS}`, emitted after commits on the actor thread | live screens; designed in F9 §13.2, never built (`Messaging.kt:20-22`) | G-DM1 … G-DM7, `NotificationPortContractTest` pattern for the listener (enums only), the privacy worlds at PR scale |
| `:messaging` | `addContact(card, source, name: String?)`, `rename(contact, name: String?)`, `ContactView.name` | aliases; `dm_contact.name_env` exists (`Schema.kt:936`); F9 §13.2's signature | same |
| `:messaging` | `conversationSummaries(): List<ConversationSummary>` (contact id, live unread count, newest live message minute; **no text**) | lists and badges; pure queries over stored content, no new column (T33) | `DmSchemaIntrospectionTest`, `DmExpiredRowLint` (the expiry filter applies) |
| `:messaging` | `conversationTimer(contact): Timer?`; `MessageView.timer`, `MessageView.expireAtMinute`, `MessageView.myReaction`, `MessageView.peerReaction` | L7-D28's own-timer display; countdowns; reactions (FR-4.3) | same |
| `:entitlement` | `inspectInvite(text): InvitePreview` (version, expiry day, refusal reason; local, no state) | a confirmation before `activate` commits a trial | `TrialStepsTest`, T16 vectors |
| `:entitlement` | `openPurchases(): List<PurchaseView>` (id, pay-with, `state`; no amount, address or time) with `state ∈ {PREPARED, INVOICE_PENDING, READY, UNDERPAID, CONFIRMING, FINALIZED, EXPIRED_UNPAID, EXPIRED_SEEN, LOST, CANCELLED}`: `READY` is exactly the `paymentReady` predicate (`EntitlementEngine.kt:200-206`) or "shown before and the deadline not passed"; an invoiced purchase inside its U[1 h, 6 h] delay is `INVOICE_PENDING`, never `READY`; `UNDERPAID` is a shown purchase with an outstanding amount before its deadline. And `invites(): List<InviteView>` (index, expiry day, state) | resume a purchase after process death without breaking F8 §19.11's delay (CR-3); list and revoke invites | the entitlement harness, `EntitlementSchemaConstraintsTest`, a predicate test against `paymentReady` |
| `:entitlement` | `activateGenesis(acknowledged: Boolean): ActivationResult`, refusing unless the build's genesis policy is on | FR-1.5's genesis path has no facade (`IdentityManager.kt:19`) | E6 stays declared; Q21 |
| `:identity` | `RootEntropy.toMnemonicIndices(): IntArray`, `IdentityManager.verifyBackupIndices(…)`, `IdentityManager.backupChallenge(count, carried)` (the positions missed so far kept in the next challenge, the rest drawn as today, `IdentityManager.kt:80`), a read-only view of `Bip39Wordlist`, and the encoder and decoder rewritten over zeroed bit arrays (F-U4) | no `String` of the root in the heap; one word list for every screen (CR-15) | the Trezor vectors, `KeyDerivationTest`, the word-list hash test |
| `:app` | `GhostApp.createDatabaseKey()` (`DatabaseKeyProvider.getOrCreate()`, zero the returned array, then `onDatabaseKeyCreated()`); `restorePrivacyModeFrom(…)` beside `restorePaymentHoldFrom`; `GhostApp.onContentLock()`; the lifecycle wiring of §3.5 (X-U14); `AppDatabase.open` records any other `GeneralSecurityException` at open as `KEYSTORE_LOST` and returns null (today only `UserNotAuthenticatedException` is caught, `AppDatabase.kt:43-48`, §5.4); `GhostApp.onWipe()` extended by the stops of the Phase 10, 11 and 14 stacks | the missing creator (`GhostApp.kt:161`); D18; X-U15; D33; CS-U4; D16 | `MessagingWiringTest`, `SyncWiringTest`, the `:app` JVM tests |
| `:sync` | `AndroidSyncController.restorePrivacyModeFrom(read: () -> PrivacyMode?)`, run on the runtime thread before any session, like `restorePaymentHoldFrom` | D18 | `:sync` suite, T19 tests |
| Phase 10 (coordination, F-U8, F-U10) | `ChannelView.unread`, per-post timer and expiry, a content-free `ChannelListener` (F10 §10.3 lists it), and `inspectInvite(link): ChannelInvitePreview?` (local parse only: password required, expiry day, already a member; no state, no `CH-ACCEPT`) | the same needs as DMs; `acceptInvite(link, null)` on an open link runs `CH-ACCEPT` at once, so "preview first" needs its own call (FE-6) | Phase 10's gates |
| Phase 11 (coordination, F-U9) | `setDownloadsPaused(paused: Boolean)` and `downloadsPaused()`, persisted in Phase 11's own schema so a job process obeys it, with a twin in Phase 11's world (pause on vs off: only the declared `M_0` listing differs); its lock duties callable from `onContentLock` (X-U15) | F11 describes the switch only in prose (`faza11-media.md:548`) and has no method or state for it | Phase 11's gates |
| Phase 14 | none beyond F14 §9.5; a flavor without `:update` gives the UI no update gateway | — | — |

---

## 4. Protection components (normative; ADR-54)

### 4.1 Secure windows

```kotlin
abstract class SecureActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(LayoutParams.FLAG_SECURE, LayoutParams.FLAG_SECURE)         // before any content
        if (SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        super.onCreate(null)                                                          // never restore UI state
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        if (SDK_INT >= 34) window.decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        // task description: the constant label "GHOST"; nothing else about the content
    }
    override fun onSaveInstanceState(outState: Bundle) { super.onSaveInstanceState(outState); outState.clear() }
}
```

- `MainActivity` is the only activity and extends `SecureActivity` (G-U1 checks every `Activity` subclass of the production source sets, and the merged release manifest's exact activity set).
- **Dialogs, sheets, menus, popups:** only Compose `Dialog`, `Popup`, M3 `ModalBottomSheet` and `DropdownMenu`, all of which take `SecureFlagPolicy.Inherit` by default and copy `FLAG_SECURE` from the host window at creation (AndroidX `AndroidDialog.android.kt`, `AndroidPopup.android.kt`, `ModalBottomSheet.android.kt`, read by the research, src); `SecureFlagPolicy.SecureOff` is banned. Each dialog's content marks its own decor view sensitive (API 34+) through `SecureDialog`, which reads `LocalView.current.rootView`.
- **Banned window sources** (G-U1): `android.widget.Toast`, `PopupWindow`, `ListPopupWindow`, `android.app.Dialog`, `AlertDialog`, `DialogFragment`, `Presentation`, `WindowManager.addView`, `Spinner`, `AutoCompleteTextView`, `PopupMenu`, Media3 `PlayerView`, `WebView`. Feedback uses the in-window M3 `Snackbar`.
- **Surfaces:** video and the QR camera preview render on a `TextureView`, which draws inside the secure window; a `SurfaceView` (a separate layer) is used nowhere, and if a later need arises it must call `setSecure(true)` (X-U12; V-U2 measures both).
- **No overrides** of `onProvideAssistData`, `onProvideAssistContent` or `onProvideReferrer` (they still run for secure windows, research src); no `setShowWhenLocked`, `setTurnScreenOn` or picture-in-picture.
- **Overlays:** `filterTouchesWhenObscured` is set on the root view while one of these screens is on top: PIN entry and change, the 24 words, payment instructions, key-change acceptance, reveal confirmation, wipe confirmation (app-wide it would freeze the UI under screen dimmers).

### 4.2 Text

- No `SelectionContainer`, `textIsSelectable` or selectable `Text` anywhere (G-U2). Message, post, caption and alias text is rendered only by `SensitiveTextView` (`BasicText`, no selection, `isSensitiveData`).
- A long press on a message opens GHOST's own menu (reply, react, details, retry or "send again" where the state allows); no copy, share or forward entry exists. The same actions exist as accessibility `customActions` (§4.3).
- URLs, numbers and addresses in messages are plain text: no `Linkify`, `LinkAnnotation`, `LocalUriHandler`, `autoLink` or preview (G-U2; ADR-08). A user who needs a URL retypes it (L11-U15). Help, licence and contact texts are plain text too: GHOST opens no browser, mail client or other app with a URI (G-U2).
- No drag source (`dragAndDropSource`, `View.startDragAndDrop`) and no share (`ACTION_SEND`, `ACTION_SEND_MULTIPLE`, `ShareCompat`, `createChooser`) anywhere (G-U2; Phase 11's proposed G-M1 bans them as well, `faza11-media.md:1197`).
- **The composer** is a normal field (ADR-27 point 3): the user may paste into it; its copy and cut go through `SensitiveClipboard` because `GhostRoot` provides `LocalClipboard` (and the deprecated `LocalClipboardManager`) backed by it (X-U2; V-U5 confirms that Compose 1.12.1's text fields use the provided clipboard).
- **The text menu of every editable field** (`GhostTextField`, the only place a text field is built, G-U4) is filtered with `Modifier.filterTextContextMenuComponents` to cut, copy, paste and select-all: Compose Foundation added `ProcessTextKey` for menu items of activities that handle `ACTION_PROCESS_TEXT` (Translate and any installed app), which would receive the selected text (CR-14). V-U26 lists what each API level shows with and without the filter, a stub app that registers `ACTION_PROCESS_TEXT` being the control; a JVM menu-item test and PM-U34 keep it.

### 4.3 Accessibility sensitivity

- **Window level:** decor `ACCESSIBILITY_DATA_SENSITIVE_YES` on API 34+ for the activity and for every dialog and popup window (`SecureDialog`). Non-tool services then see no GHOST node at all; tools (TalkBack, Switch Access, Voice Access) see everything (`View.setAccessibilityDataSensitive`, API 34, "only allow interactions from AccessibilityServices with the isAccessibilityTool property set to true", developer.android.com via Microsoft Learn). What a non-tool service still learns from system window events (that GHOST is in front) is measured by V-U33 and declared (L11-U20).
- **Leaf level:** `isSensitiveData = true` (Compose UI ≥ 1.9; "hiding this node and its generated AccessibilityEvents from other Accessibility Services that are not declared as accessibility tools", AndroidX `SemanticsProperties.kt`) on every message, post, caption, alias, pseudonym, safety digit, fingerprint, word, passphrase, PIN dot row, keypad key, payment field and the composer. The leaf marking is what the JVM tests can see (the platform enforces only on 34+).
- **Announcements:** a new message is announced politely as "Mesaj nou" (a constant), never its text; no `liveRegion` on content (PM-U11).
- **Actions:** every long-press menu also exists as `customActions`; every icon has a content description; headings are marked; traversal order is set where the visual order differs; `HoldToConfirm` has an accessible alternative (§9.2).
- **Below API 34**, and on any level where an enabled service is not a declared tool: the screen "Cine poate citi ecranul" (§6.8) lists the enabled services (label, package, system or installed, declared tool from API 31) and offers **"Ascunde conținutul de toate serviciile de accesibilitate"**, which replaces content semantics with constant descriptions (`hideFromAccessibility` on content leaves) and, on the keypads, removes the key labels from accessibility and shuffles the digit layout. It is off by default and its copy says that a screen reader will then not read messages or keys (Q8).
- **Before a secret is typed** (the PIN, the 24 words at restore or in the backup check, a channel passphrase), if a service that would receive the key presses is enabled — any non-system service on API 29–30 (no tool flag exists there), any non-tool service on API 31–33 — a warning names it: "Serviciul «X» poate vedea ce apeși aici. Oprește-l înainte sau folosește «Ascunde conținutul…»." On API 34+ the decor flag already withholds the events from non-tool services (PV-13; V-U33).

### 4.4 Clipboard (`SensitiveClipboard.kt`, the only writer)

| Item | Rule |
|---|---|
| What may be copied | an invite link, the own contact link, a channel invite link, a payment subaddress, a payment amount; nothing else (a `CopyKind` enum) |
| Never | message, post or caption text, aliases, pseudonyms, the 24 words, a passphrase, safety digits, the PIN |
| Each write | `ClipData.newPlainText(label, text)` with `label` = 16 hexadecimal characters of 8 random bytes (the ownership token) and `extras` = `{"android.content.extra.IS_SENSITIVE": true}` (the string key also works below API 33, developer.android.com, copy and paste); the 8 bytes are written to `ui_settings.clip_label` in the same step (no time, no content) |
| Clear while running | 30 s after the copy (`elapsedRealtime`), at lock and at wipe: with focus, `getPrimaryClipDescription()` (no paste toast, developer.android.com behaviour changes 12) and clear only if the label is ours; without focus, `clearPrimaryClip()` unconditionally (X-U3, Q10). A timer that fires more than 5 minutes after its due time — the process was frozen (Android 14+ freezes a cached process 10 s after it is cached, all threads suspended, source.android.com cached-apps freezer) — does not clear unconditionally |
| Clear later | at every process start and every focus gain, with focus: if the clip's label equals `ui_settings.clip_label`, clear it; `clip_label` is reset whenever GHOST clears its clip or sees another clip |
| What remains | a clip that outlived a frozen or killed process until GHOST's next focus, or Android 13+'s own clear (about 1 h), or, on API 29–32, until replaced (L11-U4, L11-U19); V-U28 measures the frozen case |
| Paste | only into the composer, the contact-link and invite fields and a payout address field; never into the PIN, word or passphrase keypads |

### 4.5 Keyboards and autofill

- **`ImeIncognito`:** `GhostRoot` wraps every window's content in `InterceptPlatformTextInput` (public in `PlatformTextInputModifierNode.kt`, AndroidX), whose interceptor wraps the `PlatformTextInputMethodRequest` and ORs `EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING` into `imeOptions` in `createInputConnection`. Composition locals reach dialog content, so one interceptor per window covers it (V-U4 confirms on AOSP's keyboard and Gboard). Compose's own `KeyboardOptions` has no field for the flag (`EditorInfo.android.kt` sets only action, ASCII, no-enter and no-fullscreen flags).
- **Keypads:** `PinPad` (10 digits, delete, confirm; no IME, no paste, no autofill; digits held in a `CharArray` zeroed after the check) and `WordKeyboard` (26 letters, delete, and suggestion chips from the BIP-39 list from the second letter; a word is completed as soon as the typed prefix matches one word only, which four letters always do in the BIP-39 English list, and a three-letter word that begins longer ones, such as "act", is picked from its chip; the chosen word is the list's constant; used for restore, backup verification and the channel passphrase). Both are ordinary Compose buttons, readable by TalkBack and usable by Switch Access. V-U30 times a `WordKeyboard` prototype with at least 5 people in S0a against NFR-10's budget (Q15).
- **Keyboard warning:** at the end of onboarding and in Settings, if the default input method (`Settings.Secure.DEFAULT_INPUT_METHOD`) is not AOSP's `com.android.inputmethod.latin` (V-U14), a one-time warning names it and says what it can see: "Tastatura «X» vede tot ce scrii în câmpul de mesaj. Unele tastaturi trimit textul sau vocea (dictarea) unui serviciu online." Preinstalled keyboards are not exempt (Gboard and Samsung Keyboard have cloud and dictation features, CR-17).
- **Autofill:** excluded on every decor view (§4.1); secrets never use a system field, so no autofill or credential manager can save them.

### 4.6 Notifications (`GhostNotifier`, the `NotificationPort` implementation)

| Element | Value |
|---|---|
| Channel | one, `ghost_messages_v1`, importance DEFAULT, `setShowBadge(false)`, lock-screen visibility SECRET (set before creation; V-U15 measures the effect per API level) |
| Title, text | `R.string.notif_title` ("GHOST") and `R.string.notif_new` ("Ai mesaje noi"); with the count option, the plural `R.plurals.notif_new_count`; nothing else, ever (G-U10 accepts only resource ids from an allowlist) |
| Visibility | `VISIBILITY_SECRET` by default; with "show on lock screen" on, `VISIBILITY_PRIVATE` with a public version of the same constant text |
| Not used | `MessagingStyle`, `BigTextStyle`, `InboxStyle`, `BigPictureStyle`, `RemoteInput`, actions, `setNumber`, `Person`, large icons, shortcuts, bubbles, conversation categories |
| Other | `setLocalOnly(true)` (a hint not to bridge to wearables), `setOnlyAlertOnce(true)`, `setAutoCancel(true)`; the tap opens `MainActivity` through an immutable `PendingIntent` without extras |
| When | `onUnreadChanged(count)` (F9's port, `MessagingPorts.kt:35-38`) posts or cancels from a single-thread executor, never on the actor thread; nothing is posted while INTERACTIVE, and unlock cancels; channel content uses the same constant notification (coordination item with Phase 10) |
| Never notified | `PAYMENT_READY` (F8 §19.11), `ENTITLEMENT_NEEDED`, update offers, alarms, **a pending key change** (a persistent in-app banner with its bound, X-U17): in-app only |
| Permission | `POST_NOTIFICATIONS` (API 33+, in T15) requested at the end of onboarding after a screen showing exactly what the notification will say; refusal is respected and shown in Settings |
| In HIGH mode | on, as in STANDARD, unless behaviour variant BV-1 (§12.2) moves S-DM1 or S-DM2 beyond their allowance; then off by default in HIGH (Q49) |

### 4.7 QR codes and the camera

- **Encoding:** zxing `QRCodeWriter` (byte mode, margin 4) drawn module by module on a Compose `Canvas` (no `Bitmap`); error correction L for invite links (876 characters → version 21, F8:1769), M for channel links (552 characters → version 18, F10 §19.29.3), L for the 131-byte contact card and the 65-byte safety-number form (F9 §12.1, §8.4). While a code is shown the window's brightness is raised (`screenBrightness = 1f`, own window only).
- **Scanning:** in-app, on the `QrScanner` screen only, with `CAMERA` (in T15) requested at first use; Camera2 preview on a `TextureView` inside the secure window; YUV frames from an `ImageReader` decoded on `ghost-qr` by zxing `QRCodeReader` (`TRY_HARDER`); frames are never stored; the camera closes at leave, hide and lock. Each screen states which payload it expects (an invite, a card or link, a channel link, a safety-number code) and refuses others.
- **A scanned contact card** is followed by one question, "Unde ai văzut acest cod?": «Pe telefonul persoanei, în fața mea» records `QR_IN_PERSON`; «Într-o poză, un mesaj, un apel video sau pe alt ecran» and «Nu știu» (preselected) record `LINK` and lead to the safety-number prompt (D34, X-U16). The answer is the user's; the copy of "Cardul meu" says that a photographed or forwarded code counts as a link (DC-33). A scanned safety-number code needs no question: it is compared, not trusted (F9 §8.4).
- **FR-7.7 display:** every link confirmation shows the kind, the format version and an 8-hex-digit **check sum** `SHA-256(link)[0..4]`, labelled "sumă de control": it detects a damaged or mistyped link, **not a substituted one** (a forger can match 32 bits with about 2³² work, CR-8); a damaged code or an unknown version fails with a typed message and nothing is stored. Substitution is answered by the safety number for cards, the post-join fingerprint for channels (§6.5) and the issuer's signature for invites.
- **Fallbacks:** paste into the link field; a device without a camera (`android.hardware.camera` declared not required) uses paste only.

---

## 5. Lock, wipe, backup, restore (normative; ADR-55)

### 5.1 The app lock (one strength in Phase 13)

| Item | Rule |
|---|---|
| Unlock with | the app PIN (6–16 digits on `PinPad`), or a biometric (`BIOMETRIC_STRONG`, the platform `BiometricPrompt`) as a convenience the user turns on; the lock step and Securitate say that a biometric can be compelled where a PIN cannot (DC-29) |
| At every hide | the hide duties of §3.3: screen models drop their state, media handles close (view-once as viewed), players are released, previews and the on-screen signal are cleared, the payment screen is hidden |
| At lock | the curtain before the first frame; the unlocked session closed; the one-shot routes popped (§3.3); the clipboard cleared if it is still GHOST's; the foreground session ended (D33) |
| What keeps running | the DM context, the database and sync: background receipt, sweeps, owner steps and notifications continue (the job process and the UI process share the DM layer; X-U1) |
| Keys at rest | Keystore-wrapped, usable without the user (ADR-20 Q6, `AppDatabase.kt:16`) |
| Protects against | someone holding the unlocked phone (C1) |
| Does not protect against | root, or anyone who can use the app's Keystore keys on the device; memory of the live process (the DM context's keys, L7-D19 as amended in Appendix B.1; the drafts, Q34) |

**State machine** (`LockController`, every legal and illegal transition a JVM test, CS-U2): `UNCONFIGURED` (onboarding before a PIN) → `UNLOCKED` (PIN set, §6.2 step 3); `UNLOCKED` → `LOCKED` (timeout at `onStart`, timeout 0 at `onStop`, "Blochează acum", process start with a lock configured); `LOCKED` → `CHECKING` (a PIN or a biometric submitted; for a PIN the failure is committed first, §5.2) → `UNLOCKED` (match; the counter reset) or `LOCKED`, and from the fifth consecutive failure `BACKOFF` until `elapsedRealtime` passes the wait of §5.2. The session (§3.3) exists exactly in `UNLOCKED` and `UNCONFIGURED`.

### 5.2 The PIN verifier and its back-off (byte level)

```
K_pin    = Keystore HMAC-SHA256 key, alias "ghost.v1.pin-mac", non-exportable, StrongBox when present,
           no user-authentication requirement, created at the first PIN set
salt     = 16 bytes from SecureRandom, new at every set or change
input    = "ghost/v1/app-pin" ‖ 0x00 ‖ salt ‖ ASCII digits of the PIN
tag      = HMAC-SHA256(K_pin, input)                                  (32 bytes)
stored   = ui_lock(salt, tag, failures)                               (§10; no time column, T33)
submit   = (1) commit failures := failures + 1                         (before the check: a kill now keeps it)
           (2) ok := MessageDigest.isEqual(HMAC-SHA256(K_pin, input'), tag); the digit array zeroed after the call
           (3) ok → commit failures := 0; UNLOCKED                     (a biometric success also resets it)
wait(f)  = 0 for f < 5;  min(30 s · 2^(f − 5), 3 600 s) for f ≥ 5
backoff  = armed at each failure on SystemClock.elapsedRealtime, and in full at every process start with f ≥ 5:
           a kill or a reboot restarts the wait, a change of the system clock changes nothing
```

Without the device's Keystore a copied database gives no PIN (each guess needs `K_pin`); with root on the device, guesses run at Keystore speed (V-U10 measures it; a 6-digit PIN is then a matter of minutes to hours) — declared (L11-U8), consistent with L1's non-goal. No automatic wipe after failures (duress is P2); the failure counter is a forensic artefact, reset at a successful unlock (L11-U8). Revision 1 stored a wall-clock `retry_minute`, which moving the system clock forward skipped, and did not order the check against the counter's write, so a force-stop right after a wrong guess could drop it and give an unlimited oracle (CR-6, PV-19); MC-U14 and MC-U15 keep both closed.

### 5.3 The strict lock: deferred, and what its design must solve (normative for that design)

Revision 1 offered an opt-in "strict mode" (database, identity, DM content and state keys bound to device authentication; process exit at lock). The reviews showed it cannot ship as a UI option (CR-1, PV-1, PV-2, PV-3, CR-5, CR-11, FE-5), so Phase 13 does not build it (Q6). A later design must solve, before it is offered:

1. **Background protocol work.** With an authentication-bound database key, `AppDatabase.open(BACKGROUND)` is refused even while the database is already open (`AppDatabase.kt:41-42`: the purpose check precedes the cached handle), and `SyncRuntime.runJob` opens the database for BACKGROUND before it starts a quiet run (`SyncRuntime.kt:476-482`). So no quiet run ever happens, and every automatic issuer call lives in quiet runs (F8 D14, §12.2): `BlindSign` (a paid purchase would never deliver tokens; `checkNow` never signs, `Entitlement.kt:29-30`), the default `RequestInvoice`, invite revocation ("never a foreground call", F8 §19.14), payout claims, `RefreshCredit` and auto-renewal; nor would Phase 14's update runs. DM weekly renewals at their PRF time (F9 §4.8), establishment steps and Phase 10's committer passes would run only at unlock times; registrations would lapse after about two weeks unopened (F9 SCN-E); 5-minute and 1-hour messages, whose relay TTL is one hour, would be lost unless the app were unlocked within it; a committer would stall its channel (members raise `partition_suspected` after 9 days, `faza10-forum.md:673`); relays would see a client with no background cadence at all, and the issuer only user-timed calls co-timed with foreground sessions. None of the worlds that prove T2, T23, T27, T31 or T32 has run such a client.
2. **Two candidate shapes**, each to be analysed with a strict client profile in the T2 and DM privacy worlds before any default: (a) **content-bound** — the database key stays unbound, so Phase 7 and 8's cadence stays as proven, while the identity, the DM content and state keys and Phase 10's `mls_state_key` are bound; the DM and channel time-triggered steps still move to unlock times, and the entitlement engine's drop opening and invite keys, which unwrap the root (`IdentityAdapters.kt:26-50`), must wait for an unlock; (b) **fully bound**, with purchases, claims, revocations and refreshes refused up front while it is on, and every cost above declared.
3. **Envelopes and aliases.** `DatabaseKeyProvider.exists()` and `getOrCreate()` know one envelope name (`DatabaseKeyProvider.kt:17-24, 30`), `SyncWiring` returns early without it (`SyncWiring.kt:36`), and revision 1's wipe resumption ("no database-key envelope but a database") would have wiped a strict device at its next start (CR-5). A second envelope set must be visible to all three; the fixed aliases (`KeystoreKeyWrappers.kt:161, 182`, `IdentityManager.kt:103`) must be parameterised, and every wrapped key inventoried (`dm_self`'s two keys, `Schema.kt:898-905`; Phase 10's `mls_state_key`, `faza10-forum.md:1021`; later ones).
4. **Re-wrapping is not re-keying.** Wrapping the same database and DM keys under new aliases leaves them recoverable to an examiner who copied the old envelope and can restore a deleted keyblob (no rollback resistance, KeyMint implementer reference); the switch must re-key the database (`sqlcipher_export` into a new file under a fresh key) and rotate the DM keys, or declare the residue.
5. **The authentication window.** A key usable for N seconds after authentication is unlocked by any authentication of the user to the device, the phone's own lock-screen unlock included (KeyGenParameterSpec: "The user authorizes key use by authenticating to the device using a secure lock-screen credential … or biometric authentication"); per-use keys with a `CryptoObject` (API 30+) are the alternative.
6. **Cold start.** Every process-start read (the payment hold, `GhostApp.kt:136`; the privacy mode; the DM open pass) fails before authentication (`AppDatabase.kt:43-48` returns null) and is never re-run: they must run at the first authenticated open, before the first session, behind a latch in `SyncRuntime` (CR-3 (c), PV-2).
7. **Lock while hidden.** The strict lock must end the process at hide, or by an alarm at hide + timeout, not at the next `onStart` (CR-10 (b), PV-3).
8. **Invalidation.** Removing the screen lock invalidates the keys irreversibly ("The key is irreversibly invalidated if the secure lock screen is disabled or forcibly reset", KeyGenParameterSpec); a state, copy and journey are needed (§5.4 is the pattern).
9. **Visibility.** Strict envelope names and aliases tell an examiner the mode without opening the database (PV-21 (a)).
10. `setUnlockedDeviceRequired` is not a substitute: symmetric operations were unrestricted up to API 30 and the javadoc lists bugs on Android 12–14 fixed only in 15 (Microsoft Learn mirror, 2026-10-03).

### 5.4 Keystore loss

A Keystore key that wraps the database key or the identity can become unusable (`KeyPermanentlyInvalidatedException`, `UnrecoverableKeyException`, an `InvalidKeyException` after a Keystore reset or an OEM fault). Today `AppDatabase.open` catches only `UserNotAuthenticatedException` (`AppDatabase.kt:43-48`), so such an exception would end the sync runtime's thread. Phase 13 records any other `GeneralSecurityException` at open as `KEYSTORE_LOST` (the open returns null and nothing is written) and shows a full screen: "Cheile acestui telefon nu mai deschid datele GHOST. Încearcă din nou; dacă nu merge, datele nu se mai pot citi: șterge-le și restaurează identitatea din cele 24 de cuvinte." Actions: "Încearcă din nou" (a new open), then "Șterge și restaurează" (§5.5, then §5.7). The state is in the catalogue (§6.9, CS-U4) and MC-U18 keeps it.

### 5.5 Local wipe (crypto-shred first)

| Step | Action |
|---|---|
| W1 | the user reads what a wipe does and does not do (contacts' copies, relay copies until TTL, tokens and credits lost, identity recoverable only with the 24 words; deleted files and keys are as final as the phone's storage and Keystore allow), re-enters the PIN and confirms with `HoldToConfirm` (3 s) or its accessible alternative (§9.2) |
| W2 | on the `ghost-wipe` thread: `GhostApp.onWipe()` — the DM stack (and Phase 10's channel stack on the same actor) stops after the pass in flight and the alarm is cancelled; Phase 11's media stack and its sandbox stop; Phase 14's updater stops and abandons an open installer session; the sync controller cancels the periodic job and drops the stores (`GhostApp.kt:185-188` covers DM and sync today; the others join as their stacks land); never on the main thread |
| W3 | delete the database-key and identity envelopes (`DatabaseKeyProvider.destroy()`, `IdentityManager.wipe()`): from here no envelope file names the keys, though a deleted file's blocks may survive on flash until reused |
| W4 | delete every GHOST Keystore alias (`ghost.v1.secret-wrap`, `ghost.v1.dm-content-key`, `ghost.v1.dm-state-key`, Phase 10's MLS state-key alias, `ghost.v1.pin-mac`, the crash-report key): **this is the crypto-shred** — an envelope that survives on flash cannot be unwrapped without its key, provided the Keystore deletes with rollback resistance; without it, "an attacker who has previously managed to retrieve the key material could potentially restore it to the device" (KeyMint implementer reference). V-U29 reads the property from key attestation on the test phones; the copy states only what the phone gives (L11-U21) |
| W5 | delete files: `databases/ghost.db` with `-wal`, `-shm` and `-journal` (the file is in `databases/`, not `no_backup/`, F9 §22.32 point 5); all of `noBackupFilesDir` (the `secrets/` envelopes, Arti state `tor/`, Phase 11's `m/`, Phase 14's `update/`, `crash/`); the contents of `filesDir` and `cacheDir` |
| W6 | cancel every notification; clear the clipboard unconditionally |
| W7 | `finishAndRemoveTask()`, process exit; the next launch is a fresh onboarding |

**Resumption (CS-U1):** in `GhostApp.onCreate`, before any wiring, if the database-key envelope `db-key.v1` is missing but `ghost.db`, its WAL or any GHOST file beyond a fresh install's baseline (V-U18) exists, W4–W6 run silently first. A crash before W3 leaves an intact app; any crash after W3 is completed at the next start. The condition names the one envelope set Phase 13 has; a design that adds another (the strict lock's) must extend it (§5.3 item 3). **What remains** (T57, L11-U11, L11-U21): an empty app sandbox apart from the system's `code_cache`, the notification channel record, the OS's job and alarm histories (`dumpsys` "removal history", LIM:68), notification history if the user enabled it, usage records (C16), relay copies until their TTL, the flash blocks of deleted files and, without rollback resistance, a restorable keyblob.

### 5.6 Seed backup

- **When:** after `activationState() == ACTIVE` (a failed trial wipes the identity, F8 §8.3 step 4), never before, and always with a lock already configured (D36). The 24 words are numbered in two columns, large type, `isSensitiveData`, under `FLAG_SECURE`, rendered from `toMnemonicIndices()` and the gateway's word list; no copy, no export, no QR, no file.
- **Verification (FR-1.4):** four positions from `IdentityManager.backupChallenge(4, carried)` (§3.6; today's `backupChallenge(4)` is `IdentityManager.kt:80`), entered on `WordKeyboard`. **A wrong answer shows the 24 words again, then a new challenge that contains every position answered wrongly so far**, completed to four with random positions; there is no skip; onboarding stays incomplete (`ui_settings.backup_verified = 0`) and the main screens stay closed until it passes. Then a full check of all 24 words is offered ("Verifică toate cele 24 — recomandat, cam 2 minute"): a random subset lets one miscopied word through with probability 20/24 ≈ 0.83 and two with 0.69 (CR-7), which only the full check removes; Q47 asks whether it should be mandatory.
- **Later:** Settings > "Cuvintele de recuperare" shows them again only after the **typed** app PIN (never a biometric, which can be compelled) and, where the phone has a secure lock screen, the device credential (`BiometricPrompt` with `DEVICE_CREDENTIAL` alone, API 30+; on API 29 the platform's credential confirmation, V-U9); a phone without a secure lock screen needs the PIN only, and the screen says so. The check can be run again from there.
- **Copy** (§8.3): write on paper, keep offline, never photograph, never type them into another app or site; GHOST asks for them only at restore and in this check.

### 5.7 Restore

1. Welcome → "Restaurez din 24 de cuvinte" → **"Ce se întoarce și ce nu"** before any typing: back come the identity, the contact card and the safety numbers (ADR-33′); not back come contacts, conversations, sessions, access tokens and unused credits (E11), credits sent to invites above index 7 (only drops 0–7 are listened to for 5 weeks, LIM E11), channel memberships (each needs a new invite, and in a password channel the password, F10 Q48 (a)), media.
2. The database key is created (`createDatabaseKey`), then **the PIN** (typed twice, optional biometric) **and the privacy mode** are set (D36): no word is typed on a phone without a lock, and the first sessions run in the chosen mode.
3. The 24 words are typed on `WordKeyboard` (each slot accepts only list words), with the accessibility warning of §4.3 if needed → `Entitlement.restore(words)` (local, `Entitlement.kt:51`): `RESTORED`, `REFUSED_MNEMONIC` ("un cuvânt sau ordinea nu se potrivesc"), `ALREADY_ACTIVE`, `UNAVAILABLE`.
4. The notification step as in onboarding (§6.2 step 10).
5. **"Pașii următori"**: buy access (no token survived; until a pack's tokens are usable, hours to days, nothing can be sent), add contacts again by scanning their cards, then "Reconectează" (staggered over 48 h, F9 §8.6; progress shows counts only), ask channel owners for new invites.
6. **NFR-10 clock:** from the first key on the restore path's PIN screen to the home screen — the lock set, the mode chosen, the words entered and validated (spec p.12 counts entry, validation and the first local unlock; this clock includes the lock's setup as well, so it measures more than the spec asks).

---

## 6. Journeys and screens (normative)

### 6.1 Information architecture

- **Three destinations:** **Conversații** (DM list, requests, new contact), **Canale** (channel list, create, join), **Setări** (sections: Acces; Confidențialitate; Securitate; Despre; Ajutor; Șterge datele). Two panes from 600 dp.
- **Status chip** in the top bar: hidden when the transport is `READY`, otherwise the connection state (§6.9).
- **Banners**, one at a time by priority: (1) security alarms (`SCHEDULE_CONFLICT`, `ISSUER_MISMATCH`, `REFUSED_BY_RELAY`, update `CONFLICT`, update `ROOT_CONFLICT`); (2) a pending key change of any contact, persistent until decided, with its bound (X-U17); (3) access and version (`ENTITLEMENT_NEEDED`, `PAYMENT_READY`, `PAYMENT_EXPIRED`, `PAYMENT_LOST`, `UPDATE_REQUIRED`, update `UNSUPPORTED`, `SDK_UNSUPPORTED`); (4) connectivity (`UNAVAILABLE` after 30 s, `NO_REPLICAS`); (5) information (an update is available; `STALE` after 7 days; `NO_MANIFEST`; `NO_CHANNEL`). `NATIVE_MISSING` and `KEYSTORE_LOST` are full screens.
- **Every list and detail screen has the same seven states:** empty, loading, ready, offline (transport not `READY`: content stays readable, sends queue), degraded (fewer than two operators, or a relay flag), locked (curtain), unavailable (`CRYPTO_UNAVAILABLE`, facade not yet open); "wiped" is not a state of a screen but a fresh onboarding.

### 6.2 J1: invite → identity (onboarding)

| # | Screen | Gateway calls (engine) | Traffic | States and copy |
|---|---|---|---|---|
| 1 | **Bun venit** | none | none | the build stage label ("Previzualizare pentru dezvoltatori", later "Alfa privată"; spec §3.1) and three limits: a compromised phone defeats GHOST (LIM:41); your provider sees that you use Tor (LIM L4); "rezistență, nu imunitate" (LIM:87). Choices: "Am o invitație", "Restaurez din cuvinte" (§5.7); "Bootstrap (genesis)" only where the build's genesis policy is on (Q21) |
| 2 | Pregătire | `createDatabaseKey()` → `onDatabaseKeyCreated()`; wait for the database to open (migrations) | none yet; from here the foreground session runs while onboarding is in front (D33; it has nothing of the identity's to read until step 7) and the periodic job is scheduled (ADR-20 point 1) | loading; a Keystore or storage failure shows a typed error and a retry (§5.4); nothing else is created before the key envelope exists |
| 3 | Blocarea aplicației | `LockGateway.setPin` (typed twice), optional biometric | none | why it exists and what it does not do (L11-U8); "amprenta sau fața pot fi folosite împotriva voinței tale; PIN-ul nu" (DC-29); from here a process death reopens at the lock screen, so nothing later in onboarding is ever shown unlocked |
| 4 | Mod de confidențialitate | `SettingsGateway.setPrivacyMode` → `setPrivacyMode` (persisted, §3.5) | changes pacing (§2.4) | STANDARD preselected; HIGH's consequences in plain words (§7.1); "Alegerea contează de acum: accesul de probă primit la pasul următor urmează modul ales" (D18) |
| 5 | Invitația | scan (`QrScanner`), paste, or a pending `ghost://invite/` link | none | link via another app: "Linkul a trecut prin acea aplicație; ea îl poate vedea sau înlocui. Preferă codul QR, în persoană" (ADR-05, plan:191; DC-11) |
| 6 | Confirmă invitația | `inspectInvite(text)` (local) | none | kind, version, expiry day, check sum (§4.7, DC-33); "se poate folosi o singură dată"; each `REFUSED_*` with its copy (§6.9) |
| 7 | Activare | `activate(text)` → `PENDING`; `RedeemInvite` as a user issuer call; `activationState()` polled | one issuer call over Tor (L3, E3) | "Conectare prin Tor, poate dura până la 3 minute" (bootstrap bound 180 s, RPC 60 s, ADR-19); transient failure: retried at each unlock (at most 40, LIM E3) and by a button (each try is an L3 sample, said in the button's help); `FAILED`: "Invitația a fost refuzată: folosită deja sau revocată. Identitatea creată a fost ștearsă." (F8 §8.3 step 4). The DM ACTIVATE that the identity's creation triggers runs inside the foreground session already running (BV-2 measures this order, Q54) |
| 8 | Cuvintele tale | `toMnemonicIndices()`, the gateway's word list | none | §5.6 |
| 9 | Verificare | `backupChallenge(4, carried)`, `verifyBackupIndices`; the offered full check | none | §5.6; no skip |
| 10 | Notificări | `POST_NOTIFICATIONS` request (API 33+) | none | a picture of the exact notification; "fără expeditor, fără text" (a `CLAIM`, shown once T11 is green, §8.5); refusal is fine |
| 11 | Înainte să începi | `SettingsGateway.ackDisclosures(version)` | none | three cards (§8.3 DC-1 … DC-3); the keyboard warning if needed (§4.5); the accessibility warning if needed (§4.3); then home |

### 6.3 J2: payment (access)

| # | Screen | Gateway calls | Traffic | States and copy |
|---|---|---|---|---|
| 1 | **Acces** (Setări) | `status()` every 2 s while INTERACTIVE; `openPurchases()`; `invites()` | none | "Acces până la sfârșitul săptămânii …" (from `coverageEndWeek`), fresh credits, invites left; each purchase by its `PurchaseView.state`; flags as banners (§6.9) |
| 2 | Cumpără | `startPurchase(XMR \| CREDITS)` | none now; `RequestInvoice` in a later quiet run (no earlier than U[0, 24 h] after the purchase when `ENTITLEMENT_NEEDED` was set, F8 §19.13) | `null` → "Programul de prețuri al aplicației se termină curând: actualizează" (`UPDATE_REQUIRED`) or "Creditele nu ajung"; else "Factura vine automat; o vei vedea peste câteva ore"; STANDARD only: **"Cere factura acum"** (`requestInvoiceNow`) with "Un apel imediat către serviciul de plată e un semnal de timp. Factura apare tot după 1–6 ore." (E3, F8 §5.3) |
| 3 | Factura e gata | `PurchaseView.state == READY` (the `PAYMENT_READY` predicate, at least U[1 h, 6 h] after the invoice arrived; never a notification) | none | only from `READY` (or an earlier showing, `UNDERPAID`) do steps 4–5 open; an `INVOICE_PENDING` purchase reads "Factura se pregătește" (D35, CS-U3) |
| 4 | Înainte de plată | `requiredDisclosures(id)`; `acknowledge(id, all five)` | none | the five disclosures, each a short paragraph with its own tick (§8.3 DC-6 … DC-10); the button stays disabled until all five |
| 5 | **Instrucțiuni de plată** | `paymentInstructions(id)` (only here, only for `READY` or `UNDERPAID`); `paymentScreenShown(id)` at every resume, `paymentScreenHidden(id)` at pause and hide | relay sessions close now and stay held U[20, 60] min after the screen hides (F8 §19.11) | the exact amount, or the outstanding amount after an underpayment (XMR), the subaddress (grouped, `isSensitiveData`), the deadline (receipt + 24 h, local time), the QR of the `monero:` URI built locally; **"Copiază adresa"** and **"Copiază suma"** (sensitive clips); no "open in wallet" button (Q46); "Plătește de pe alt dispozitiv sau mai târziu, fără GHOST deschis" (E15); "După ce lipești adresa în portofel, verifică primele și ultimele 6 caractere: o tastatură sau o aplicație de clipboard o poate înlocui" (DC-32); "Sincronizarea e oprită cât e deschis acest ecran și 20–60 de minute după" (DC-23) |
| 6 | După plată | `openPurchases()`, `status()`; STANDARD only: **"Verifică acum"** (`checkNow`, never signs) | `checkNow`: one issuer call | `CONFIRMING`: "Plata se confirmă în cel mult 72 de ore; accesul devine folosibil de la o oră de activare, la câteva ore după" (F8 §19.11, E1); `UNDERPAID`: "Lipsește o parte din plată" → step 5, which shows the outstanding amount and keeps the hold (D35); `EXPIRED_SEEN` / `EXPIRED_UNPAID`: whether the payment was seen, and "o plată întârziată nu se poate potrivi; fără rambursare" (E25); `LOST`: what happened and that nothing can be recovered (E8) |
| 7 | Anulare | `cancel(id)` | none | offered only while no instructions were ever shown (`Entitlement.kt:32-36`) |
| 8 | Credite și plată referral | `claimPayout(address)`; `setAutoRenewWithCredits` | the claim, and auto-renewal, in later quiet runs | "o subadresă nouă din portofelul tău, niciodată a unui exchange"; "o revendicare refuzată pierde creditele" (E21); E23 |
| 9 | Invitații | `createInvite(expiryDay)`, `invites()`, `revokeInvite(index)` | redemption in a later quiet run | the link shown once as QR and text, copyable (sensitive clip), with ADR-05's warning and the check sum's meaning (DC-11, DC-33); revoke explains it burns the token |

### 6.4 J3: direct messages

| Screen | Gateway calls | Traffic | States and copy |
|---|---|---|---|
| **Conversații** | `contacts()`, `conversationSummaries()`; hints | none | alias (`SensitiveText`), trust badge, unread count, newest minute; **no message preview** (Q14); "Cereri (n)" entry; empty state explains cards and QR |
| Contact nou | scan (`QrScanner`), then "Unde ai văzut acest cod?" (§4.7): «Pe telefonul persoanei, în fața mea» → source `QR_IN_PERSON` (starts verified); «Într-o poză, un mesaj, un apel video sau pe alt ecran» or «Nu știu» (preselected) → source `LINK` (unverified); or paste a `ghost://contact/` link → `LINK`; then `addContact(card, source, name)` | none (R-E1: adding is local) | `LINK`: "Aplicația sau imaginea prin care a venit codul îl poate vedea sau înlocui; verifică numărul de siguranță" (DC-11); each `AddContactResult` (§6.9) |
| Cardul meu | `myCard()` | none | QR in person first; "Un cod fotografiat sau trimis mai departe contează ca link" (DC-33); "Copiază linkul" (sensitive clip) with: "cine are cardul tău îți poate scrie, pentru totdeauna" (L7-D25) |
| **Conversație** | `conversation(id, 50, before)`, `markDisplayed` (§3.5), `setConversationOnScreen` | none | bubbles: text, minute timestamp ("ora la minut e vizibilă corespondentului", ADR-08), state for outgoing (§6.9), the message's own timer when it differs from the conversation's (L7-D28), quote, reactions; a banner while `CHANGED` |
| Compunere | `send(id, text, quote)`; then `requestExpedite()` in STANDARD | stores at pair events | byte counter near 61 440 B; the first send to a `LINK` or request contact shows once: "Primul mesaj îi dă cardul tău complet" (L7-D25); `KEY_CHANGED` opens the key-change screen |
| Mesaj — acțiuni | `retry(id)` (FAILED, before the deadline); "Trimite din nou ca mesaj nou" for INDETERMINATE (F9:1079); `react(id, target, g)` | stores | "Trimis" means stored on relays, not read (F9 D10); no copy, share or forward |
| Timer | `conversationTimer(id)`, `setTimer(id, t)` | one TIMER_SET store | values off, 5 min, 1 h, 1 d, 7 d (default), 30 d; §7.2 copy |
| **Schimbare de cheie** | `pendingSafetyNumber`, `verifyKeyChange(id, scanned)`, `acknowledgeKeyChange(id)` | none | "Mesajele tale nu pleacă și ale lui sunt ținute până decizi (cel mult 30 de zile)"; paths: scan in person; compare the 60 digits in person, or read them aloud only on a channel that may know the two of you talk (a safety number confirms who talks to whom, §2.1; CR-22); or accept without checking (a separate, explicit confirmation stating that nothing was verified); the home banner stays until a decision and names the bound: undecided past it, held messages are lost (L7-D17, X-U17) |
| **Număr de siguranță** | `safetyNumber(id)`, `markVerified(id, scanned)`, `markVerifiedManually(id)` | none | 60 digits in 12 groups of 5 and the QR; "Ai comparat? Asta confirmă că vorbești cu aceeași persoană care ți-a dat cardul, nu cine este" |
| Cereri | `acceptRequest`, `rejectRequest`, `blockRequest` | none | up to 64, expire after 7 days; the requester is not told anything (F9 §12.3); media in a request never opens (F11 D28) |
| Contact | `rename`, `block`, `unblock`, `deleteContact`, `resetSession` | `resetSession`: one store later | block: "nu îl oprește să depună în inboxul tău, nu îi spune nimic și nu șterge copiile de pe telefonul lui" (F9 §12.4, FR-4.7); unblock requires the card again |
| Reconectare (after restore) | `reconnect(ids)` | controls over 48 h | counts only |
| Revocare (P1) | `issueRevocation(reason)`, `notifyContactsOfRevocation(cert)` | controls over 24 h | "Identitatea ta devine inutilizabilă pentru toți contactele; ține aplicația deschisă și conectată 24 de ore" |

### 6.5 J4: channels (on Phase 10's `Channels`, `faza10-forum.md:975-1000`)

| Screen | Calls | Traffic | States and copy |
|---|---|---|---|
| **Canale** | `channels()`, hints | none | name, role, member count, unread (coordination item), flags (`resync_needed`, `reinvite_needed`, split, partition, stale) |
| Creează | `create(name, timer, sizeClass)`; optional password (§6.5.1) | commits at passes | timer default 7 d; size 32 or 100 members; at most 9 channels per device (F10 Q4); "≥ 2 finanțatori recomandați" (F10 R-5) |
| Canal | `posts`, `post(text, replyTo)`, `react`, `markDisplayed`, `hide(post)`, `mute` | stores | posts flat with reply chips; a thread view filters by root (F10 D1: threads are a rendering); 16 000 B per post; the limitation sentence (§8.4) |
| Invită | `createInvite(id, expiryDays ≤ 7, password?)` | stores at passes | in a password channel only committers may invite (F10 Q46 (b)); the sponsor **retypes the passphrase** on `WordKeyboard` at each issue (Q50 (a)); the link appears **once** (QR and copyable text); in a password channel it is not kept on the phone (`invite_env` NULL, F10 §19.29.3), while an open channel's link is kept for the sponsor's list until it expires (`ch_invite_own`, `faza10-forum.md:912`, PV-21 (c)); a later void (a committer change or a password change) is told to the sponsor: "Spune-i celui invitat să nu folosească linkul vechi" (F10 §19.29.2 (3)) |
| Intră | `inspectInvite(link)` (Phase 10 coordination, F-U10), then `acceptInvite(link, password?)` | none for the preview; a join request at passes | a preview before anything is written (until F-U10 lands: the kind, the check sum and an explicit confirmation before `acceptInvite`); `PASSWORD_REQUIRED` → `WordKeyboard`, then a progress indicator while Argon2id runs (seconds on a low-end phone, F10 Q44); `WRONG_PASSWORD`; then "Așteaptă aprobarea unui moderator; poate dura ore" (`PENDING`); "Apari sub același pseudonim ca în orice canal anterior cu acest identificator" (F10:599); channel rules (LIM:141) |
| După intrare | `fingerprint(id)`: the epoch number and the 8-byte code (`faza10-forum.md:993`) | none | "Compară codul și numărul epocii cu cel care te-a invitat, pe alt canal. Dacă numerele epocii diferă, comparați mai târziu. Doar la aceeași epocă, coduri diferite înseamnă probabil o copie falsă a canalului: părăsește-o și cere o invitație nouă." (F10 Q49 (a); CR-9: two honest members at different epochs see different codes) |
| Membri | `members(id)`, `remove`, `setPolicy` | commits | pseudonym fingerprints, roles, sponsor; owner actions (moderators, funders, transfer of rank 0, timer, name, who may invite — members or committers only, forced to committers in a password channel (F10 Q46 (b)) — password set, change or removal); after a removal: "Cel scos știe parola; schimb-o?" (F10:1965) |
| Părăsește | `leave(id)` | commit | a committer must resign or transfer first (F10 §6.6); the only committer with members names a successor (F10:691) |
| **Dezvăluie identitatea** | a same-epoch fingerprint comparison inside the flow (§6.5 "După intrare"; nothing stored), then `reveal(id, member)` | a post | the flow starts with the comparison: a captured member's reveal goes to the forger's puppet (`faza10-forum.md:2001` (b)), so "Ați comparat codul la aceeași epocă și se potrivește?" must be answered yes (Q53). Before the button: "Persoana aleasă va putea dovedi oricui (unui operator, unei instanțe, altor membri) că pseudonimul tău din acest canal ești tu, și primește cardul tău de mesaje directe, pentru totdeauna. Ceilalți membri văd că ai făcut o dezvăluire, nu către cine." (F10 Q14, Q35, L8-C8; L7-D25); confirm with `HoldToConfirm` or its accessible alternative |
| Resincronizare | `resync(id)` | a rejoin request | offered on `resync_needed` only, as a user action |

**6.5.1 The channel password (F10 §19.28, §19.29.3; Q42–Q50 approved).** At create or at "set password" the app draws 5 words uniformly from the 2 048-word BIP-39 English list (indices from `SecureRandom` in the identity adapter, words from the same list the seed uses, §3.2), ≈ 55 bits (Q44 (a)); the owner cannot choose a weaker one. Canonical form: the five lowercase words joined by one U+0020, NFKD, UTF-8 — the bytes Phase 10's facade receives (`CharArray` zeroed after the call, `faza10-forum.md:965`). The words are shown once with "Scrie-o pe hârtie și comunic-o membrilor în persoană; nu o copia"; there is no copy. Changing it voids old invites and moves the channel to a new address (+3 tokens, Q45 (a)). Restoring a device needs it (Q48 (a)). Because the same word list serves the seed, the passphrase screens use a distinct frame and title, and the app never asks for seed words after onboarding except in the backup check behind re-authentication (§5.6).

### 6.6 J5: media (on Phase 11's facade, `faza11-media.md:516-531`)

| Screen | Calls | Traffic | States and copy |
|---|---|---|---|
| Atașează | the platform photo picker (`MediaStore.ACTION_PICK_IMAGES`, through `SystemIntents.kt`) where the platform provides it; elsewhere `ACTION_OPEN_DOCUMENT` directly, never the `ACTION_SYSTEM_FALLBACK_PICK_IMAGES` route that Google Play services implements on GMS devices (V-U34, FX-1); `sendMedia(id, source, caption, viewOnce)` | the upload burst | caption ≤ 1 024 B; `TOO_LARGE`, `TOO_LARGE_FOR_TIMER` (video ≤ 160 s, ≤ 85 s in 5-min and 1-h conversations), `UNSUPPORTED_SOURCE`, `UNDECODABLE`; "Fotografia e re-codată înainte de trimitere; originalul rămâne în galeria ta" (FEATURE); "metadatele (locație, model) sunt eliminate" is a `CLAIM` (F11 §8, L9-M9) shown only once its evidence is green (§8.5) |
| Progres | `mediaState(id)` | — | fragments held of F; `failed` → `retryMedia` (≤ 3, before the deadline); "Trimiterea continuă în fundal și poate dura ore" (no upload service, D26) |
| Primire | `mediaState`, `mediaPreview` (only while on screen) | automatic download on `M`'s schedule (F11 D10) | awaiting, fetching (progress), complete, verified, `corrupt`, `incomplete` ("poate fi incomplet"), `undecodable`, `NOT_KEPT` (from a request: never opens); opening an item never triggers a fetch (PM-U28) |
| Vizualizare | `openMedia(id)` → `MediaHandle` closed on leave and at hide | none | full screen, secure, Compose player (`media3-ui-compose`, `TextureView`); no save, share or copy |
| Vezi o dată (P1) | `openViewOnce(id)` | none | before opening: "Se poate vedea o singură dată pe acest telefon. Dacă ieși din aplicație, se închide. Oricine poate fotografia ecranul cu alt telefon." (F11 §11.2; LIMIT); "Captura de ecran e blocată" is a `CLAIM` (T10), shown once T10 is green |
| Pauză descărcări | Phase 11's pause method (F-U9) | `M_0` listing stops or resumes | "Releele văd că ai oprit descărcările" (L9-M3) |

### 6.7 J6: update (on Phase 14's `Updates`, F14 §9.5, revision 2, proposed)

| Screen | Calls | Traffic | States and copy |
|---|---|---|---|
| **Versiune și actualizări** | `Updates.status`, `Updates.manifestIssuedDay` | none | the installed version; `UpToDate`, `Available(name, code)`, `Downloading(received, total)`, `Ready(name, code)`, `Installing`, `Installed(code)`, `Stale(day)`, `Unsupported(floor)`, `SdkUnsupported`, `NoManifest`, `Conflict`, `RootConflict`, `NoChannel`, `Failed(code)`; "Informațiile despre versiuni au N zile" (from `manifestIssuedDay`, public data, no device time stored) |
| Verifică acum | `requestCheck()` | mirror fetches on the `Update` scope (F14 §7.3) | foreground only; "Verificarea poate avea loc în timp ce aplicația vorbește cu releele; cine operează și un releu și o oglindă le poate pune cap la cap" (L10-D20; Q47 of F14) |
| Descarcă | `requestDownload()` | APK ranges | progress; resumable |
| Instalează | first DC-28 (Play Protect and Android developer verification, F14 §8.5), then `canRequestPackageInstalls()`; if false, `Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES` for GHOST (`SystemIntents.kt`); then `install()` → `PackageInstaller` session, the system's confirmation | **not GHOST traffic**: on GMS devices Play Protect may send app details or the APK to Google, and the developer verifier may look the install up (L10-D9, L10-D24) | "Android îți va cere să confirmi; GHOST nu instalează nimic fără tine" (F14 Q16) |
| Alarme | — | — | `Conflict` and `RootConflict` (red, persistent): "Am primit două versiuni diferite ale aceluiași manifest de actualizare: posibilă încercare de atac. Nu instala GHOST din alte surse; raportează."; `Stale` after 7 days: "Informațiile despre versiuni sunt vechi; aplicația merge mai departe"; `Unsupported`: "Această versiune nu mai e acceptată; actualizează"; `SdkUnsupported`: "Versiunile noi nu mai merg pe această versiune de Android"; `NoManifest`; `NoChannel` (no mirror answered in 12 consecutive update runs, F14 §7.5) |
| A build without the updater | no `UpdateGateway` (Phase 14's store flavor, F14 §8.2 (c)) | none | the version only, and "Actualizările vin din magazin și nu trec prin verificarea GHOST" (F14 §2.6's second residue sentence) |

There is **no in-app "verify this app"** (Phase 14 revision 2 removed `signerCertificateSha256()`: "a malicious APK would report whatever it liked", `faza14-distribution.md:844`; "The app shows no 'verify this app' value of its own", :266). The "Despre" screen says, as plain text, that an installation can be checked on a computer with the public verifier `ghost-verify` (F14 §5.4). Only after Phase 14's gate closes may the copy of F14 §2.6 appear, beside both of its residue sentences; before that, the screens state only versions and states (§8).

### 6.8 Settings, security, about

- **Confidențialitate:** privacy mode (§7.1); notifications (on/off, count, lock-screen display); media download pause (§6.6).
- **Securitate:** app lock (change PIN, biometric, timeout 0/1/5/30 min); **"Cine poate citi ecranul"** (enabled accessibility services, §4.3, and the protections that apply on this Android version, from §2.3); the keyboard (§4.5); "Cuvintele de recuperare" (§5.6); "Diagnostic" (counts only: `MessagingStatus`, sync flags, never ids or times).
- **Despre:** version; **"Cine vede ce"** (§8.2); "Limite" (plan §7, LIM summaries, and ADR-27's missing abuse-report path, DC-27); **Licențe** (renders `assets/THIRD_PARTY_NOTICES.txt` with the MPL-2.0 source offer, ADR-37 points 2–3); the security contact as plain text (FR-8.6; the owner provides it, OA-6); the `ghost-verify` sentence (§6.7); the ADR-38 residue sentence ("Nu puteți verifica singuri codul sursă; vă bazați pe auditorii numiți și pe jurnalul public") once any claim is allowed.
- **Ajutor:** "Tor și țara ta" (LIM:159; text under legal review, OA-5; no location lookup); "Înainte să schimbi telefonul" (what a restore loses, §5.7); "Raportează o problemă" (local crash reports: review, delete; sending waits for Q20). Every address in these texts is plain text, never a tappable link (§4.2).
- **Șterge datele** (§5.5).

### 6.9 States catalogue (normative; every constant has Romanian and English copy and an action, CS-U4)

| Engine value | UI state and action |
|---|---|
| `TransportStatus.STARTING` | chip "Se conectează prin Tor"; after 30 s "poate dura până la 3 minute" (no percentage exists, `TransportPort.kt:7`) |
| `UNAVAILABLE` | banner after 30 s: "Nu ne putem conecta prin Tor. Verifică rețeaua și ora telefonului; în unele rețele Tor e blocat." → "Tor și țara ta" (the cause is not distinguishable, so both hints) |
| `BRIDGE_CONFIG`, `TRANSPORT_FAILED` | "Configurația de conectare nu e validă" / "Conexiunea a eșuat; reîncercăm automat" |
| `NATIVE_MISSING` | a full screen: "Instalarea e incompletă. Reinstalează GHOST din sursa oficială." No retry loop |
| `KEYSTORE_LOST` (§5.4) | a full screen: "Cheile acestui telefon nu mai deschid datele GHOST…" → "Încearcă din nou", then "Șterge și restaurează" |
| `OFF` | nothing (hidden, or before the key) |
| `StatusFlag.RELAY_SUSPECT`, `RELAY_REJECTS` | Diagnostic and a Securitate notice: "Un releu s-a comportat anormal; mesajele folosesc celelalte" |
| `BUG`, `UNKNOWN_CATEGORY` | Diagnostic: "Eroare internă" → "Raportează o problemă" |
| `CONSUMER_POISONED`, `EXPIRED_UNCONSUMED` | Diagnostic counts: "date primite care nu au putut fi procesate" |
| `CAPABILITY_NEEDED` | none directly; `ENTITLEMENT_NEEDED` is the user-facing one |
| `ENTITLEMENT_NEEDED` | banner "Mesajele noi așteaptă acces" → Cumpără |
| `UPDATE_REQUIRED` | banner "Pentru a cumpăra acces, actualizează aplicația" → Versiune |
| `SCHEDULE_CONFLICT` | red alarm: "Aplicația a primit chei sau prețuri care contrazic unele acceptate. Nu cumpăra nimic acum; actualizează doar din sursa oficială." |
| `ISSUER_MISMATCH` | red alarm: "Serviciul de plată a răspuns ceva ce un serviciu cinstit nu răspunde. Nu plăti acum." |
| `REFUSED_BY_RELAY` | alarm: "Un releu a refuzat un token valid; accesul poate fi afectat" |
| `PAYMENT_READY`, `PAYMENT_EXPIRED`, `PAYMENT_LOST` | §6.3 steps 3 and 6 |
| `PurchaseView.state` (`PREPARED`, `INVOICE_PENDING`, `READY`, `UNDERPAID`, `CONFIRMING`, `FINALIZED`, `EXPIRED_UNPAID`, `EXPIRED_SEEN`, `LOST`, `CANCELLED`) | §6.3; only `READY` and `UNDERPAID` open the payment screen |
| `CLOCK_UNTRUSTED` | reserved, never set (`EntitlementStatus.kt`); copy exists for completeness |
| `ActivationResult.REFUSED_MALFORMED`, `_VERSION`, `_SIGNATURE`, `_TOKEN`, `_EXPIRED`, `_REPLAYED`, `UNAVAILABLE`, `ALREADY_ACTIVE` | "Nu e o invitație GHOST" / "Versiune necunoscută: actualizează" / "Invitația a fost modificată" / "Invitație invalidă" / "Invitația a expirat" / "Invitația a fost deja folosită" / "Aplicația încă pornește" / "Există deja o identitate pe acest telefon" |
| `SendResult.KEY_CHANGED`, `BLOCKED`, `REVOKED`, `REQUEST_NOT_ACCEPTED`, `TOO_LARGE`, `NO_REPLICAS`, `STORAGE_FULL`, `CRYPTO_UNAVAILABLE`, `UNKNOWN`, `DEADLINE_PASSED` | key-change screen / "Contact blocat" / "Contactul și-a revocat identitatea" / "Acceptă cererea întâi" / (prevented by the counter) / "Nu sunt destui operatori de relee disponibili acum" / "Spațiu insuficient pe telefon" / "Mesajele nu sunt disponibile acum" / "Mesajul nu mai există" / "Prea târziu pentru reîncercare: trimite din nou ca mesaj nou" |
| `MessageState.QUEUED`, `SENT`, `DEGRADED`, `FAILED`, `INDETERMINATE` | "în așteptare" / "trimis la relee" / "trimis parțial (un singur operator)" / "netrimis" + Reîncearcă / "incert: poate a ajuns" + "Trimite din nou ca mesaj nou" |
| `Establishment.CARD_ONLY`, `FETCHING`, `UNREACHABLE` | "Primul mesaj pleacă după ce găsim contactul" / same / "Nu găsim contactul; cardul poate fi vechi. Cere-i cardul din nou." (F9 Q42: three tries) |
| `TrustState.UNVERIFIED`, `VERIFIED`, `CHANGED`, `BLOCKED`, `REVOKED`, `REQUEST` | badges "neverificat", "verificat", red "cheie schimbată", "blocat", "revocat", "cerere" |
| `AddContactResult.*`, `VerifyResult.*`, `RestoreResult.*` | one sentence each (`MISMATCH`: "Codurile NU se potrivesc. Nu confirma."; `CARD_CHANGED`: "Acest contact are deja alt card; schimbarea cardului nu e încă posibilă") |
| Phase 10 results, Phase 11 states, Phase 14 `UpdateStatus` | mapped the same way when their facades land (the reflection test enumerates them) |

### 6.10 Limits the UI enforces before a call (NFR-14; CS-U5)

Contacts 1 000 (F9 §12.6); message body 61 440 B and a reaction grapheme 32 B (`Messaging.kt:120-125`); alias 64 characters (`name_env` admits 256 B of plaintext, `Schema.kt:936`); caption 1 024 B (F11 §6.6); post 16 000 B, 9 channels per device, 32 or 100 members by size class, invite expiry ≤ 7 days (F10); PIN 6–16 digits. A limit reached shows its number; nothing is truncated silently.

---

## 7. Modes, timers and media honesty (normative)

### 7.1 High-privacy mode

| | STANDARD (default) | HIGH |
|---|---|---|
| When it is chosen | onboarding step 4, before the invite is activated (D18), or later in Settings | same |
| Sends | leave when due (≤ 32 per pass); the UI expedites after a user send | each operation delayed once by U[0, 10 min]; stores only at the pair's events (≤ 8 per event) (ADR-20 point 3) |
| Reads | ≤ 4 pages per event | exactly 1 page per event (ADR-20 point 4) |
| New access tokens | usable from the activation slot; a trial at once (F8 §12.3) | plus Geometric(1/2) extra days (LIM E1); a trial by the pack rule, its extra days capped at the trial's last week (`Slots.kt:30-35`) |
| "Cere factura acum", "Verifică acum" | shown | hidden (`Entitlement.kt:26-30`) |
| Receipts, typing, delivery reports | none exist (F9 D10) | none |
| Volume | follows activity in both modes (no cover traffic; LIM L2.1 point 3) | same |

Copy (Romanian, DC-22): "În modul de confidențialitate ridicată, trimiterile pleacă cu o întârziere aleatoare de până la 10 minute, aplicația citește mai puțin la fiecare verificare, iar un acces nou devine folosibil cu câteva zile mai târziu. Volumul traficului rămâne vizibil: GHOST nu trimite trafic de acoperire." A change after activation applies to later token batches; the trial keeps the slot it was given. The per-namespace send-delay override is not exposed (DM and channel namespaces cannot turn it off, F9:1758). The mode persists in `ui_settings.privacy_mode` and reaches every process before its first session (§3.5, MC-U9, MC-U11).

### 7.2 Disappearing messages: what the UI says, and only that (ADR-27 points 7–11, ADR-32, F9 §10)

- The conversation's timer is a chip in the header (default 7 days); a change is a message both sides see ("Ai setat ca mesajele să dispară după 1 zi").
- A message whose own timer differs from the conversation's shows it (L7-D28).
- The countdown starts for the sender at sending and for the recipient at first display (§3.5's definition); a read message shows a coarse "dispare în ~3 h".
- Unread messages disappear at the latest when their relay copy expires; short timers lose messages for a recipient who stays offline (ADR-27 consequences, F9 R-15).
- DC-15, verbatim intent, split by kind (§8.5): **LIMIT** "Mesajul se șterge de pe acest telefon când expiră. O captură făcută cu alt dispozitiv sau o copie păstrată de o aplicație modificată rămân."; **CLAIM** (evidence T25; shown only once it is green) "Pe telefonul celuilalt, aplicația oficială îl șterge la fel."; **GOAL** until then, through `GoalText`: "Obiectiv de design: mesajul dispare și de pe telefonul celuilalt, dacă folosește aplicația oficială — neverificat încă."; **CLAIM** (relays' TTL behaviour, Phase 9's gate) "Releele cinstite șterg copia criptată când îi expiră termenul."
- "Un timer diferit de 7 zile face conversația mai ușor de recunoscut de relee" (L7-D4; F9 Q39).

### 7.3 Media: ephemeral and view-once (F11 §11)

The copy of §6.6 and nothing stronger: view-once means at most one display **on this device**, and the item closes when the app is hidden (§3.3); screenshots are blocked (a `CLAIM` on T10, shown once T10 is green); a camera, a second device, a modified client or a rooted phone are not; relay copies live until their TTL; the sender's original stays where it was picked from; decrypted pixels may linger in memory GHOST does not own (L9-M7).

### 7.4 Receipts and typing

None are built (F9 D10; Q18). "Trimis" always means "stored on relays", never "delivered" or "read"; DC-16 says the minute of each message is visible to the correspondent (ADR-08).

---

## 8. Disclosures and the claims register (normative; ADR-56)

### 8.1 Three layers

1. **Onboarding** (step 11 of J1, short and mandatory): DC-1 … DC-3; DC-29 at the lock step.
2. **Just in time**, at the action that carries the risk: payment (DC-6 … DC-10, DC-23, DC-32), sharing a link or a card (DC-11, DC-33), the first send to a link contact (DC-12), block (DC-13), key change (DC-14), timers (DC-15), reveal (DC-17), view-once (DC-18), notifications (DC-19), installing an update (DC-28).
3. **Reference:** "Cine vede ce" (plan §4 as a table), "Limite" (plan §7 and LIM summaries, DC-27, DC-30, DC-31), "Cine poate citi ecranul" (§2.3 for the user's own API level).

### 8.2 "Cine vede ce"

One row per actor of plan §4 (relay, entitlement issuer, network or ISP, channel members, DM correspondent, the operator, the Monero network, an attacker with the unlocked phone) plus "cine are cardul tău" (L7), "moderatorii unui canal" (F10), **"operatorii oglinzilor de actualizare"** (F14 §2.4: update runs, user checks, the downloaded release), **"Google, pe telefoanele cu servicii Google"** (Play Protect and the developer verifier at an install or update, L10-D9, L10-D24) and **"aplicațiile cu acces la utilizare sau la notificări"** (C16). Three columns: **Vede** (always shown; a `LIMIT`, written as "vede cel puțin", never "doar"), **Nu ar trebui să vadă** (a `GOAL`, always printed with its status, today "obiectiv de design — neverificat încă"), **Dovada** (the evidence IDs and their status from the register). When an evidence ID enters the green list, the row's status changes; the sentence becomes a `CLAIM` only through the register (§8.5).

### 8.3 Mandatory disclosures (each registered; a `LIMIT` unless §8.5 makes part of it a `CLAIM`)

| ID | Disclosure | Source | Where |
|---|---|---|---|
| DC-1 | A compromised phone defeats GHOST; what reduces the damage | LIM:41 | J1 step 11; Securitate |
| DC-2 | A dedicated device (for example GrapheneOS) for high-risk profiles, and why | LIM:33 | J1 step 11 |
| DC-3 | Your provider sees that you use Tor; "rezistență, nu imunitate"; the regional guide | LIM:87, :159; plan §7 | J1 step 11; Ajutor |
| DC-4 | The 24 words: the only way back; never typed elsewhere; what a restore loses | FR-1.4; E11; F9 §8.6 | §5.6, §5.7 |
| DC-5 | What a wipe does and does not do, including that deleted files and keys are as final as the phone's storage and Keystore allow | FR-4.7 by analogy; CR-11 | §5.5 |
| DC-6 | Paying from an exchange with KYC links you to an invoice; the Monero network sees the broadcast moment and the wallet's fingerprint; prefer your own wallet over Tor, at a random moment | FR-6.9; TM S13; E7 | J2 step 4 |
| DC-7 … DC-10 | No refund; the exact amount (a shortfall can be topped up in the window); no lock time; 24 h to pay, up to 72 h to confirm, pay from another device or later | `Disclosure.kt`; F8 §7.4; E15, E25 | J2 step 4 |
| DC-11 | A link sent through another app is seen, and can be replaced, by that app; a code photographed or forwarded is a link too; a link tapped in another app opens GHOST at that app's moment, so pasting it into GHOST is better; prefer QR in person | ADR-05; plan:191; F9 §12.1; CR-2, CR-20, PV-6 | every link screen |
| DC-12 | Your card means "may message me", for good; the first message gives the full card | L7-D25 | my card; first send |
| DC-13 | Block does not stop deposits, does not tell the contact, does not delete their copies | F9 §12.4; FR-4.7 | contact screen |
| DC-14 | What a key change and a safety number mean; compare in person, or read aloud only on a channel that may know the two of you talk; held messages and their bound | FR-4.6; TM S12; L7-D17; CR-22 | key change, safety number |
| DC-15 | Timers, split by kind (§7.2) | ADR-27; L7-D4, L7-D28; T25 | timer sheet |
| DC-16 | The minute of each message is visible to the other side | ADR-08 | conversation info |
| DC-17 | Channel pseudonyms; the reveal's transferable proof and the DM card it hands over for good; the same pseudonym on a re-invite; classical cryptography in channels; the fingerprint check with its epoch; every member, and every removed member, knows the password; funders are recognisable to relays | ADR-04; F10 Q14, Q35, Q49, Q7; F10:365, :599, :993; §19.28.2; L7-D25 | channel screens |
| DC-18 | Media re-encoding and what survives; view-once limits, and that it closes when you leave the app; the pause is visible | F11 §8.5, §11.2; L9-M3 | media screens |
| DC-19 | What a notification shows; that listener apps, watches and the OS's usage records see when it appears | §4.6; L11-U6, L11-U17 | J1 step 10 |
| DC-20 | Which accessibility services can read the screen and the key presses on this Android version; the tool flag is the service's own declaration, which nothing checks on a phone without Google Play services | §2.3; CR-19, PV-13 | Securitate; before secrets |
| DC-21 | A keyboard other than AOSP's sees what you type in the composer, and some send text or voice (dictation) to an online service | ADR-08; CR-17 | keyboard warning |
| DC-22 | HIGH mode's effects; no cover traffic | ADR-20; LIM L2.1 | §7.1 |
| DC-23 | Sync stops while the payment screen is open and 20–60 min after | F8 §19.11 | J2 step 5 |
| DC-24 | Updates: no claim before Phase 14's gate; after it, F14 §2.6's sentence beside both residue sentences ("Nu puteți verifica singuri codul sursă…" and "Prima instalare și actualizările din magazine nu trec prin această verificare; folosiți verificatorul public"); no verification inside the app | F14 §2.6 | §6.7 |
| DC-25 | "Nu puteți verifica singuri codul sursă; vă bazați pe auditorii numiți și pe jurnalul public" beside any allowed claim | ADR-38 point 11 | with every `CLAIM` |
| DC-26 | *(withdrawn in revision 2: it disclosed the strict mode's costs; the strict lock is deferred, Q6)* | — | — |
| DC-27 | The build stage ("previzualizare", "alfa privată", …), that no privacy property is verified yet, and what this stage lacks: reports of abuse through ADR-13's flags do not exist yet, while screenshots are blocked | spec §3.1; STATUS; ADR-27 consequences; FE-15 | Bun venit; Despre; Limite |
| DC-28 | On phones with Google Play services, Play Protect may send app details or the APK to Google at an install or update, and Android's developer verification may look the install up at Google; de-Googled systems and the Play Protect setting are the user's options | F14 §8.5, F-D8; L10-D9, L10-D24 | before "Instalează"; Cine vede ce |
| DC-29 | A fingerprint or face unlock can be forced on you; a PIN in your head cannot | PV-21 (b) | J1 step 3; Securitate |
| DC-30 | The phone's system keeps its own records of when GHOST was opened, notified or used the camera; apps with usage access and anyone who examines the phone can read them | LIM L1.1 (extended); C16; PV-11 | Limite; J1 step 10 |
| DC-31 | Direct messages: the ratchet and authentication are classical, and network metadata is not protected against a future quantum computer (`LIMIT`); the relay-stored envelopes' X-Wing layer is a design goal not yet verified (`GOAL`, via `GoalText`) | ADR-36 points 4, 6; X-U11; CR-13 | Cine vede ce; Limite; conversation info |
| DC-32 | After pasting the payment address into a wallet, compare its first and last six characters: a keyboard or a clipboard tool can replace it | F8 §5.3; CR-3 (d) | J2 step 5 |
| DC-33 | A check sum shows that a link or code is undamaged, not who sent it; a photographed or forwarded code counts as a link | §4.7; CR-8, CR-2 | link screens; Cardul meu; Contact nou |

### 8.4 Forbidden wording and the PQ rule

- **Never** (either language, any screen, store text or document): "100%" next to private, anonymous or safe; "complet anonim", "total privat", "nimeni nu poate", "imposibil de urmărit / citit / spart", "anonimat garantat", "untraceable", "unbreakable", "military-grade"; "open source", "sursă deschisă", "verificabil de oricine", "auditat" without a named report (ADR-38 point 11); "quantum-proof", "rezistent cuantic", "criptare end-to-end post-cuantică", "ratchet PQ", "protocolul Signal", "verificat formal" (ADR-36 point 6); for updates "sigur", "imposibil de falsificat", "martori independenți", "reproductibil" without a named attestation, and any statement that Google does not learn of installs or updates (F14 §2.6).
- **Post-quantum:** no post-quantum **claim** — nothing that says GHOST resists a quantum computer — until ADR-36's model (M-1 … M-7) has run and the external review is published; then only ADR-36's sentence, for DMs. Limitations ship now, in parallel for both, so neither implies that the other is protected: channels (DC-17, X-U11): "Mesajele din canale folosesc criptografie clasică; nu sunt protejate împotriva unui viitor calculator cuantic."; direct messages (DC-31): "În mesajele directe, ratchet-ul și autentificarea sunt clasice, iar metadatele de rețea nu sunt protejate împotriva unui viitor calculator cuantic." The DM envelopes' X-Wing layer appears only as a `GOAL` with its status, never as a claim.
- **End-to-end encryption** and every "X cannot see Y" sentence are `CLAIM`s, blocked until their evidence is green (Phase 9 and 10 gates, the Phase 15 audit); today the UI does not say them.
- A negated phrase ("GHOST nu este 100% privat") is allowed only through the reviewed allowlist of G-U8.

### 8.5 The register (format) and its gate (G-U8)

`ghost/android/ui/claims/claims.tsv`, one row per sentence, columns: `id` (the string resource id), `kind` (`LIMIT`, `FEATURE`, `GOAL`, `CLAIM`), `evidence` (comma-separated evidence IDs, or `-`), `residue` (the id of the sentence that must accompany it, or `-`), `source` (document and line), and for `CLAIM` rows the Romanian and English text. G-U8 fails when any of these rules is broken:

1. **Effect sentences are `CLAIM`s.** A string whose Romanian or English text matches the reviewed trigger list `claims-triggers.tsv` — phrases that state what an adversary, another device, a relay, the network or the platform can, cannot or will do ("nu poate", "nu vede", "dispare … de pe telefonul", "sunt eliminate", "e blocată", "trece prin Tor", "fără expeditor", "criptat", "cannot", "is removed", "is blocked", "goes through Tor", "disappears from", …) — must be a `CLAIM` row with evidence, whatever its author called it; a match that is not a claim needs a reviewed line in `claims-allow.tsv` (id and reason). Revision 1 let such sentences ship as `FEATURE`s (CR-12): DC-15's "dispare … de pe telefonul celuilalt" (T25), "metadatele … sunt eliminate" (F11's T5 change), "Captura de ecran e blocată" (T10), "Verificarea trece prin Tor" (T6, T51), "fără expeditor, fără text" (T11).
2. **Coverage.** Every string resource of the onboarding disclosures and of the `security`, `access`, `media`, `channels` and DM trust and safety-number screens has a row of some kind, so a security sentence cannot stay unregistered (G-U8 enumerates those resource files by package).
3. **Release.** A `limit_`, `goal_` or `claim_` resource has a row of that kind and both languages; a `CLAIM` whose evidence is not entirely green appears in no `res/values*/strings.xml` of a release source set; a `goal_` string is rendered only through `GoalText` (which prints the status).
4. **The green list** `ghost/test-harness/privacy/claims-evidence.txt` (empty today) has one line per evidence ID: `<id> <ci-run-id> <commit> <report-check> <sha256 of the archived report>`; G-U8 checks that the archived report under `docs/evidence/` has that hash and that the commit is the release commit (PV-16).
5. **Unique evidence IDs.** Every evidence ID in the register and the green list names exactly one thing across INVARIANTS and the designs' identifier conventions (`evidence-ids.txt`, generated from them); revision 1's twins `NI-U1 … NI-U3` collided with Phase 14's `NI-U1 … NI-U5` and are renamed `NI-UI1 …` (PV-16, FE-11).
6. **Forbidden phrases** (§8.4) match nowhere outside `claims-allow.tsv`.

Before a distributed release the register carries the signed claim checklist of FR-8.7 (a release check, §14.3).

### 8.6 Copy rules

Romanian first, informal "tu" (LIM:41's voice); sentences of at most about 20 words; a term explained at first use (releu, Tor, card, număr de siguranță); "ș" and "ț" with comma below (U+0219, U+021B); numbers with units; local dates and times; no claim adjectives ("sigur", "anonim") about GHOST; addresses, the security contact and the verifier's location are plain text, never tappable; a native editor reviews every string, and counsel reviews the payment, privacy and Tor-guide texts (OA-5).

---

## 9. Design system, accessibility, localisation (normative)

### 9.1 Theme and components

- **Material 3** from the pinned BOM (`material3` 1.4.0, verified for BOM 2026.09.00 at developer.android.com's mapping); **dynamic colour** on API 31+ (Material You, FR-7.1), on by default with a switch; a fixed palette below 31; **semantic colours fixed** in both modes and contrast-checked: danger, warning, verified, neutral (a key change is always the same red).
- **Typography:** the M3 type scale over the system font; `sp` everywhere; no bundled font, no downloadable font (`ui-text-google-fonts` asks a Google Play services provider and is denied by G-U7).
- **Icons:** a small set of Material Symbols vector drawables committed to `res` (Apache-2.0; a notice line); no icon artifact.
- **Images:** no image-loading library and no network image; contacts show a monogram of the alias; previews come only from Phase 11's RAM cache (`mediaPreview`).
- **Components** (`org.ghost.ui.design`, `.protect`, `.qr`): `GhostRoot`, `SecureDialog`, `SensitiveTextView`, `GhostTextField`, `PinPad`, `WordKeyboard`, `QrImage`, `QrScanner`, `StatePanel` (the seven states of §6.1), `Banner`, `StatusChip`, `MessageBubble`, `TrustBadge`, `TimerChip`, `CheckCode`, `GoalText`, `HoldToConfirm`, `StepProgress`.

### 9.2 Accessibility requirements (FR-7.1; WCAG 2.2 level AA as the yardstick)

Touch targets ≥ 48 dp (developer.android.com accessibility guidance; WCAG 2.5.8 asks 24 × 24 CSS px); contrast ≥ 4.5:1 for text and ≥ 3:1 for large text and controls (WCAG 1.4.3, 1.4.11), checked on the token pairs arithmetically in a unit test; text up to 200 % (Android 14 scales non-linearly to 200 %; WCAG 1.4.4) with no clipped or overlapping content; a content description for every icon; headings marked; traversal order set where needed; nothing conveyed by colour alone; no time limit except the lock and payment deadlines, both stated; animations off when the system's animator scale is 0; layouts mirror under a right-to-left pseudo-locale (no RTL language ships). TalkBack, Switch Access and Voice Access are walked through on a device for every P0 journey (§12.6).

- **`HoldToConfirm`** (wipe, reveal) has an accessible alternative: a custom accessibility action and a visible "Altă metodă de confirmare" button lead to a second, explicit confirmation dialog; a hold is never the only way (FE-12).
- **Declared deviation from WCAG 3.3.8** (Accessible Authentication, Minimum, AA): the app PIN is a memorised secret typed on a keypad that accepts no paste and no password manager, by design (a secret must not pass through the clipboard or autofill); the alternative 3.3.8 allows is the optional biometric unlock, so the deviation remains for users who cannot or will not use one. Typing the 24 words at restore is a transcription task with no alternative that keeps the words off the clipboard. Both are declared in "Limite" and in ADR-54 (FE-12).

### 9.3 Accessibility versus leakage (the trade-off, Q8)

A screen reader must read the text to the user, so any protection that hides text from every service also excludes blind users. The only mechanism that separates "assists a user" from "reads the screen" is the self-declared `isAccessibilityTool` flag, enforced by the platform from API 34 and backed only by store policy (Play rejects false declarations and Play Protect blocks them where it runs, developer.android.com blog 2025-12-11; on a device without Google Play services — GrapheneOS among them, which DC-2 recommends — a sideloaded service can lie and nothing checks it) and, on Android 17 with Advanced Protection, by blocking non-tool services (secondary sources, Appendix D).

| Option | What it does | Cost |
|---|---|---|
| A (default) | decor and leaf sensitivity: non-tool services see nothing on API 34+; tools see everything | none for users; nothing below API 34; a lying service still reads |
| B | hide content from all services, always | blind users cannot use GHOST; contrary to ADR-27 |
| C (default, opt-in) | A, plus the "Cine poate citi ecranul" screen, the warning before secrets (§4.3), and an opt-in that hides content and keypad labels from all services, offered when a non-tool or unknown service is enabled | a user who turns it on loses screen-reader reading of content and keys |
| D | announce new content aloud (live regions) | bystanders hear messages; rejected; only "Mesaj nou" is announced |

Disclosed limits (DC-20): nothing is enforced on API 29–33, key presses included; services that lie about being tools, unchecked where Play Protect does not run; system window events that may still tell a non-tool service when GHOST is in front (assumed, V-U33); system tools (from Android 16 QPR2, per AOSP sources read by the research, able to capture secure windows; V-U20); a screen reader's own cloud features (TalkBack 16.0 can send a screenshot of the screen to Gemini for description at the user's request, support.google.com, 2026-10-03); speech heard by others.

### 9.4 Localisation (Q9)

`values-ro` is written and reviewed first; `values` (English) is the fallback for every other locale; a gate (G-U12) requires every string in both with the same placeholders, and Romanian plurals with `one`, `few` and `other`. Per-app language from API 33 through `LocaleManager` (Android 13, developer.android.com app-languages) with `generateLocaleConfig` (AGP 8.1+); on API 29–32 the app follows the system language (AppCompat's back-port needs `AppCompatActivity`, a dependency rejected in D22). BIP-39 words stay English (the standard; no Romanian list exists). The UI locale never leaves the device (ADR-08: no locale in protocol messages).

### 9.5 Layout

Edge-to-edge with explicit insets (enforced for apps targeting API 35+), IME insets, two panes from 600 dp, no orientation or aspect lock (Android 17, API 37), foldables treated as resizable windows (V-U24).

---

## 10. Storage: migration UX (normative; one transaction, append-only, fail-closed)

`UX` is the next free schema version at merge (Phase 14's X-D12 rule: 10 if Phases 10, 11 and 14 land first with 6, 7, 8 and 9). The F9 §13.6 rules apply: explicit columns, `typeof` CHECKs, REPLACE guards, no time column of activity (T33).

```sql
CREATE TABLE ux_migration_guard (row_count INTEGER NOT NULL CHECK (row_count = 0));
INSERT INTO ux_migration_guard(row_count) SELECT count(*) FROM sqlite_master WHERE name GLOB 'ui_*';
DROP TABLE ux_migration_guard;

CREATE TABLE ui_settings (
  id               INTEGER PRIMARY KEY CHECK (id = 1),
  privacy_mode     INTEGER NOT NULL CHECK (privacy_mode IN (0, 1)),              -- 0 STANDARD, 1 HIGH
  lock_timeout_s   INTEGER NOT NULL CHECK (lock_timeout_s IN (0, 60, 300, 1800)),
  biometric        INTEGER NOT NULL CHECK (biometric IN (0, 1)),
  notif_mode       INTEGER NOT NULL CHECK (notif_mode IN (0, 1, 2)),             -- off, constant, constant with count
  notif_lockscreen INTEGER NOT NULL CHECK (notif_lockscreen IN (0, 1)),          -- 0 hidden (VISIBILITY_SECRET)
  theme            INTEGER NOT NULL CHECK (theme IN (0, 1, 2)),                  -- system, light, dark
  dynamic_color    INTEGER NOT NULL CHECK (dynamic_color IN (0, 1)),
  a11y_hide        INTEGER NOT NULL CHECK (a11y_hide IN (0, 1)),
  onboarding_step  INTEGER NOT NULL CHECK (onboarding_step BETWEEN 0 AND 11),    -- §6.2's order (D36)
  backup_verified  INTEGER NOT NULL CHECK (backup_verified IN (0, 1)),
  ime_warned       INTEGER NOT NULL CHECK (ime_warned IN (0, 1)),
  disclosures_v    INTEGER NOT NULL CHECK (typeof(disclosures_v) = 'integer' AND disclosures_v >= 0),
  clip_label       BLOB CHECK (clip_label IS NULL OR length(clip_label) = 8)     -- §4.4: the ownership token, no time
);
INSERT INTO ui_settings (id, privacy_mode, lock_timeout_s, biometric, notif_mode, notif_lockscreen, theme,
                         dynamic_color, a11y_hide, onboarding_step, backup_verified, ime_warned, disclosures_v, clip_label)
  VALUES (1, 0, 60, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, NULL);

CREATE TABLE ui_lock (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  salt         BLOB NOT NULL CHECK (length(salt) = 16),
  tag          BLOB NOT NULL CHECK (length(tag) = 32),
  failures     INTEGER NOT NULL CHECK (typeof(failures) = 'integer' AND failures BETWEEN 0 AND 1000000)
);                                                                               -- no retry time (§5.2, T33)

CREATE TABLE ui_crash (
  crash_id   BLOB    PRIMARY KEY NOT NULL CHECK (length(crash_id) = 16),
  day        INTEGER NOT NULL CHECK (typeof(day) = 'integer' AND day >= 0),           -- a day index, nothing finer
  version    INTEGER NOT NULL CHECK (typeof(version) = 'integer' AND version > 0),     -- the versionCode
  report_env BLOB    NOT NULL CHECK (length(report_env) BETWEEN 29 AND 8220)            -- content-key envelope, ≤ 8 KiB of report
) WITHOUT ROWID;
-- Triggers: no DELETE on ui_settings; at most one ui_lock row; at most 8 ui_crash rows (the importer deletes the oldest first);
-- the REPLACE guards of F9 §13.6.
```

**The crash report** (FR-8.11's local half): the uncaught-exception handler writes, synchronously and at most 8 KiB, the exception chain as class names and frames (`class.method:line`) with no message, thread name, path or argument, into `noBackupFilesDir/crash/pending.bin` as `0x01 ‖ nonce(12) ‖ AES-256-GCM(K_crash, report, AAD = "ghost/v1/crash")`, `K_crash` a non-exportable Keystore key; it sets the file's modification time to 0 (`File.setLastModified(0)`), so the file carries no crash time, and **ends the process itself** (`Process.killProcess`) without chaining to the platform's default handler, whose "FATAL EXCEPTION" log line and DropBox `data_app_crash` entry would carry the exception's message (PV-17). The next start imports the report into `ui_crash` under the content key and deletes the file. It is the UI's only file outside SQLCipher (declared in T54 and L11-U14); the T3 canary test puts a canary in an exception message and scans logcat and `dumpsys dropbox --print` for it. A native crash in the main process still leaves a tombstone the OS writes (L11-U23). Sending waits for Q20.

Nothing else of the UI is persisted: drafts, back stacks, scroll positions and screen states live in memory (T54).

---

## 11. Invariants (new T53–T57; changes to T3, T4, T6, T10, T11, T20, T24, T25, T33)

### 11.1 New invariants (Romanian rows for INVARIANTS.md in Appendix B.2)

| ID | Invariant | Verification | Executable from |
|---|---|---|---|
| T53 | **UI-caused traffic.** Only §2.4's closed list of user actions causes relay, issuer or mirror traffic, and no foreground session starts before an unlock; no other UI event or state (opening a screen, the lock screen, scrolling, display, notifications, status reads) changes a read schedule, a session's start or end, or what is sent, except the bounded delay UI reads add to a due time-triggered turn (RT-UI1) | G-U5; the recording-gateway suite (every intent of every screen model against recording facades: the traffic-causing calls equal §2.4's row for that intent, and **zero** such calls on model creation, route entry, hints, polls and lifecycle events); the open-without-unlock test (an open, with or without a link, causes no `onAppForeground` and no trial retry until an unlock, and a link open adds its delay); twins NI-UI1 (the Phase 9 privacy world with a UI driver reading every facade method at the bounded maximum rate vs none: identical relay views, registrations in the same minute), NI-UI2 (a conversation opened and displayed vs not), NI-UI3 (payment instructions read vs not, on a world that models the payment hold, apart from the declared hold), NI-UI4 and NI-UI5 (Phase 10's and Phase 11's worlds with a UI driver vs none, built in S5 and S6); RT-UI1 (§12.2) | Phase 13 (JVM) |
| T54 | **UI persistence.** The UI keeps nothing sensitive outside SQLCipher and RAM: the saved-state bundle is empty; no preference, DataStore or file except the declared transient crash file (encrypted, no time); no sensitive value in a `toString`; no link in the task the OS persists | G-U6; G-U11's manifest rule (`persistNever`, `singleTask`); JVM bundle canary scan per screen; the `toString` reflection test; emulator sandbox inventory with canaries (Phase 11's scan extended) and the recent-tasks scan after a link launch (V-U31) | Phase 13 (JVM, emulator) |
| T55 | **Lock and hide.** While locked no content screen is composed; the lock decision precedes the first frame after a return; a new process starts locked when a lock is configured; at every hide the screen models hold no content state and the content-lock duties have run | JVM state-machine, frame and hide tests on a virtual clock; emulator (`uiautomator dump` shows only the lock screen; after a hide no media handle is open and no content node exists) | Phase 13 |
| T56 | **Claims.** No sentence that states an effect reaches a release unless it is a `CLAIM` whose evidence is in the green list; every `GOAL` is printed with its status; every string of the sensitive screens is registered; every evidence ID is unique and every green-list line names its run, commit and report hash; no forbidden phrase in either language | G-U8 with fixtures; a JVM test that parses every resource and the register | Phase 13 |
| T57 | **Wipe.** After a wipe: no key envelope, no GHOST Keystore alias, no database or WAL, no file under `no_backup`, `files` or `cache`, no scheduled job or alarm, no notification; an interrupted wipe completes at the next start | JVM crash enumeration over W2–W7 (every step and file operation); emulator `run-as` inventory and `dumpsys jobscheduler`, `alarm`, `notification`; device | Phase 13 |

### 11.2 Changes to existing invariants

| ID | Change |
|---|---|
| T10 | Made exact: every window the package opens (activity, Compose dialog, popup, menu, sheet, player) is secure from its first frame; G-U1's bans; API 33+ recents opt-out; on the emulator `dumpsys window` shows `SECURE` on every window of every scripted screen, ADB capture is refused or black **as V-U1 measures per API level** (revision 1 wrote the outcomes before the measurement, FE-16), and the recents snapshot is a placeholder (not "absent": it is written with `isRealSnapshot=false`, research src), each with a non-secure control; the keyboard is captured explicitly on every level (V-U1); the black-box pass repeats the window and capture checks on the R8-shrunk release APK; Phase 11's media-window rule (X-M11) is folded in |
| T11 | "Locked or not" (F9 Q19); one constant text and an optional count; hidden on the lock screen by default; no badge; no notification for a key change (X-U17); `dumpsys notification --noredact` canary scan and the notification-history step on a device |
| T24 | The approved unit is `SensitiveClipboard.kt` plus the root that provides it as Compose's clipboard (X-U2); the clear is checked-if-ours with focus and unconditional without, within 30 s while the process runs and at the next focus otherwise (X-U3, D11); no `PROCESS_TEXT` item in any text menu (D9); window-level and leaf-level sensitivity; the secrets have no system-IME field (X-U4); emulator dumps through a non-tool client (zero canaries) and a tool client (canaries present) on API 34+; the freezer case (V-U28) |
| T3 | The canaries add aliases, message and post text, passphrase and seed words, the PIN, payment addresses and **link payloads**; the scan adds logcat during every emulator suite, `dumpsys dropbox --print`, crash reports and bundles; a canary placed in an exception message must appear nowhere (§10) |
| T4 | Executed on the emulator in S10 on both paths: the cloud path with the local transport (`allowBackup="false"` is honoured there, AOSP `BackupEligibilityRules`), and the **device-to-device** path (LocalTransport with `is_device_transfer=true`), where `allowBackup` is ignored for apps targeting 31 or later (`IGNORE_ALLOW_BACKUP_IN_D2D`), so only the `<device-transfer>` excludes protect GHOST at target 37; each with a relaxed-rules control APK whose canary file must appear; API 29–30 separately (V-U25) |
| T6 | The dynamic half runs in S10 with packets attributed to GHOST's UID (V-U27: the emulator's root shell with an `iptables` owner match or per-UID accounting), a control app that resolves a name and must be seen, a twin capture (journey vs idle), Tor unreachable, every journey script exercised and an update run (F14:933): zero non-Tor packets and zero DNS queries from GHOST's UID; traffic of the platform or of apps GHOST hands work to (the photo picker, the installer, Play Protect) is outside T6 and declared (§2.4) |
| T20 | The device inventory runs on the emulator in S10 after a session and after a wipe, against V-U18's fresh-install baseline; the UI's declared file (the crash file) is listed |
| T25 | The UI's "displayed" definition (§3.5) starts the recipient's countdown; unchanged otherwise |
| T33 | "Notificări cu text constant" becomes "notificări cu text constant, opțional cu numărul de mesaje necitite" (Q7); `ui_lock` and `ui_settings` hold no time (§10) |

---

## 12. Testing and the exit-gate argument

### 12.1 Tiers

| Tier | Runs | Build | Proves | Cannot prove |
|---|---|---|---|---|
| JVM | every push, in the `android` job (Robolectric 4.17, SDK 35 by default, SDK 29, 33 and 34 for version-gated cases; JDK 17) | the debug variant of `:ui` and `:app` | window flags at creation, toolbars and text menus, semantics, clipboard on a virtual clock, bundles, lock and hide frames, state machines, recording gateways, **the journeys J1–J6 over the real engines**, twins, RT-UI1, behaviour variants, crash enumerations, the state catalogue, semantic snapshots | what the platform does with a flag (capture, enforcement, recents), real keyboards, real Keystore |
| Emulator | by rotation and on dispatch (`ui-emulator.yml`, §13.2), AOSP x86_64 images API 29, 33, 35, 36 and `google_apis` 37.0 (no AOSP 37 image exists, `sys-img2-3.xml`, 2026-10-03) | the `gate` variant, whose gateways serve fixtures, instrumented by `:app-uitest`; **plus a black-box pass on the R8-shrunk release APK** (`-Pghost.smoke.release=true`), driven from the host by `adb` (`input`, `uiautomator dump`, `dumpsys`, `screencap`) | §12.3: platform behaviour of every protection, ATF checks, T4, T6, T20, T54's task scan, T57, and the release APK's windows, lock and wipe | OEM builds, hardware Keystore, real Tor latency, humans |
| Devices | two phones at the phase's close (OA-2), signed checklist (§12.6) | the release candidate | hardware keys, rollback resistance (V-U29), OEM screen features, real keyboards, TalkBack walkthroughs, real QR scanning | — |
| People | two moderated rounds (§12.5) | the release candidate | completion, critical errors, comprehension, NFR-10 | long-term behaviour |

**The journey harness** (JVM, D27, Q45) wires `:app`'s real composition — the wiring classes of `GhostApp`, the real `MessagingRuntime`, entitlement engine and `SyncRuntime` — over SQLite JDBC and the host DM library (`ghost-dm-host`, as `MessagingWiringRuntimeTest` already does), with the Phase 7 model relay and the Phase 8 model issuer shared into `:app`'s test source set the way `storage/src/testShared` already is (`app/build.gradle.kts:102`). Compose screens are driven by Robolectric's Compose rule. Tor is not exercised (that is the `live-tor` job's). No seam is added to release code: the emulator's fixture gateways live in the `gate` half of a build-type twin (§3.1), the pattern G-DM5 already accepts.

Robolectric's `android-all-instrumented` jars are resolved through Gradle and pinned in `verification-metadata.xml` and run offline (`robolectric.offline`, `robolectric.dependency.dir`; robolectric.org configuring page), never downloaded at test time; SDK 36 and 37 under Robolectric need JDK 21 (Robolectric 4.16 notes), which CI does not use (ADR-34), so API 36 and 37 are covered on the emulator only.

### 12.2 JVM suites (in `:ui` and `:app` test sources)

- **Protection suite:** window flags of the activity and of every dialog, popup, menu and sheet at creation (PM-U1 … PM-U3); a spy `TextToolbar` that must see no `showMenu` on a long press over content (PM-U4); the text-menu items of every `GhostTextField` (cut, copy, paste, select-all only; PM-U34); a semantics walk that finds no `CopyText`, `CutText` or `SetSelection` action and finds `isSensitiveData` on every node that carries a canary (PM-U5, PM-U8, PM-U9, PM-U22, PM-U25); a clipboard spy on a virtual clock (sensitive extra on every write, clear at 30 s and at lock, the persisted label cleared at the next focus after a simulated process restart, no unconditional clear more than 5 min late, no write for secrets; PM-U6, PM-U7, PM-U38); `EditorInfo` captured from every editor, flag set (PM-U23); the keyboard warning for every default IME other than AOSP's (PM-U39); the saved bundle of every screen scanned for canaries after `onSaveInstanceState` (PM-U14, PM-U15); notifications through the notification-manager shadow (PM-U12, PM-U13); lock frames on the virtual `mainClock` (PM-U19, PM-U20); the hide test: after `onStop` no screen model holds content state, no media handle is open and the on-screen signal is `null` (PM-U35); live regions carry constants only (PM-U11).
- **Recording gateways (T53):** every intent of every screen model runs against recording facades; the set of traffic-causing calls per intent must equal §2.4, and **no** traffic-causing call may happen on model creation, route entry, a hint, a poll or a lifecycle event (PM-U16, PM-U17, PM-U27, PM-U28); the payment screens open only for `READY` or `UNDERPAID`, and an underpaid purchase goes through `PaymentInstructions` with its hold (PM-U31, PM-U32, CS-U3); a display-semantics test checks what counts as "displayed" (§3.5; PM-U18).
- **Open-without-unlock test (T53):** an open by the launcher, by a `ghost://` link or by an explicit intent from a test app causes no `onAppForeground` and no trial retry while the lock screen shows; the unlock starts them, a link open after a delay in [0, 2 min] or at the user's first action of §2.4, whichever comes first (PM-U29).
- **Provenance test:** a scanned card records `QR_IN_PERSON` only with the "in front of me" answer; the default and the other answers record `LINK` (PM-U30).
- **Journeys** (the harness of §12.1): J1–J6 and restore end to end, with the onboarding-order and process-start tests (no word before a lock, the mode before the trial, the persisted mode and the hold before the first session; MC-U6, MC-U9, MC-U11 … MC-U13), the restore round trip (indices → displayed words → `Entitlement.restore` → the same root), the payment timing (CS-U3), the PIN submit at every kill point (MC-U14), the back-off across a clock change and a restart (MC-U15), the backup check's carried positions (MC-U16) and the re-display's authentication (MC-U17).
- **Twins** (T53): **NI-UI1** and **NI-UI2** on the Phase 9 privacy world (`dmworld`, production triggers, F9 §22.36) at PR scale, with the UI driver as an extra participant, in STANDARD only (the world has no HIGH mode, F9 §22.36 item 9(f)); they show that UI reads and display change no relay view, not timing (the world runs in virtual time, with the facade unattached to the actor, item 2). **NI-UI3** on a world that models the payment hold: Phase 8's T2 world (which models payments from the payment screen, S3d, mutant M19), with the UI's read modelled as `paymentInstructions` plus `paymentScreenShown`; if that world cannot take a UI driver, a JVM twin over the entitlement harness with the production `SyncRuntime` hold (decided in S3). **NI-UI4** and **NI-UI5** on Phase 10's and Phase 11's worlds when their facades land (S5, S6); until then P-U5's twin evidence says "DM, STANDARD".
- **RT-UI1 (real clock):** the production `ghost-dm` actor thread over the host DM library, a time-triggered turn due every 200 ms, and a UI driver that keeps both `ghost-ui-io` threads busy with the worst screen's reads; it measures the extra delay of the due turns' starts (p50, p99, maximum) against a run without the driver, and fails above the bound that V-U17's measurement on the low-end phone fixes in S0a. What a relay can see of that delay is at most one maintenance pass (60 s in the foreground) for the stores of a turn that falls within the bound before a pass (D19).
- **Behaviour variants** at PR scale on the Phase 9 privacy world, each re-running S-DM1, S-DM2, JD7, JD8 and the NI-DM twins against the pinned baselines (the +0.02 rule of F9 §22.36 item 6): **BV-1**, notification-coupled use — a share of foreground periods starts LogNormal(median ≈ 3 min) after a background delivery that raised the unread count (PV-8); **BV-2**, ACTIVATE inside a foreground period already running, with no session start in the same second (the order D36 fixes, F9 §22.36 item 9(g)'s first one); **BV-3**, restore, the session running before the restore and the DM ACTIVATE resuming at its first pass, `NO_RELAYS` until the schedule facts arrive. If BV-1 fails, Q49 turns notifications off by default in HIGH; if BV-2 or BV-3 fails, Q54's option (b) applies.
- **Semantic snapshots:** for each screen × {ro, en} × font scale {1.0, 2.0}, the unmerged semantics tree serialised (role, resource text, flags, actions, size class; sensitive text replaced by a token) and compared with committed goldens; text diffs are reviewed like code. No theme axis: the semantics tree carries no colour (FE-17).
- **Pixel goldens** (informative, Linux CI only, fonts differ by OS): Robolectric native graphics `captureToImage` for about 30 key screens in light and dark, compared with a small tolerance by a comparator in test code (no new dependency).
- **Accessibility arithmetic:** every clickable node ≥ 48 dp; every token pair meets its contrast ratio; no visual text overflow at font scale 2.0; `HoldToConfirm` reachable through its alternative.
- **Crash enumerations:** the wipe (W2–W7) over an in-memory file system and a software Keystore port (CS-U1; MC-U3, MC-U4).
- **Catalogue and limits:** reflection over every mapped enum, `KEYSTORE_LOST` included (CS-U4, MC-U7, MC-U18); every limit refused before a call (CS-U5, MC-U10); adapters on `ghost-ui-io` only (CS-U6, PM-U26).

### 12.3 Emulator suites (`ui-emulator.yml`, judged by `ui-emulator-check.sh`: exact test counts, zero skipped, every report line present; not run is red)

| Suite | Build | Method |
|---|---|---|
| T10 | gate; release (black box) | for each scripted screen (and its dialogs, sheets, menus): `dumpsys window windows` → every window of the package has `fl=… SECURE`; `screencap` refused or black inside the app's bounds, whichever V-U1 records for the level (a JDK program checks uniformity); the keyboard captured with an editor focused; the recents snapshot (`adb root`, `/data/system_ce/0/snapshots`) not real or uniform; each check repeated on a control activity without the flag in the test APK, which must capture (V-U1) |
| T24 | gate | accessibility dumps through a non-tool `UiAutomation` (API 34+; or, if V-U3 finds that unusable, a test-only service declaring `isAccessibilityTool=false`): zero canary nodes; through the default (tool) client: canaries present; keypad presses seen by a non-tool test service on API 29–33 and not on 34+ (V-U33); the clipboard on the real clock in the foreground: cleared within 30–35 s; **the freezer case**: GHOST hidden and demoted to the cached state with the freezer on (V-U28 fixes the commands): the clip outlives the 30 s, then is cleared at GHOST's next focus; the text menu with a stub app that handles `ACTION_PROCESS_TEXT` installed: no such item (V-U26); IME flags read from `dumpsys input_method` |
| T11 | gate | the gate variant's `GhostNotifier` driven through the `NotificationPort` by a gate instrumentation command, with canary text in the fixture's rows (the DM receipt path itself is the JVM journeys') → `dumpsys notification --noredact` scanned for every canary; visibility and badge fields |
| T54 | gate; release (black box) | sandbox inventory with canaries; a cold launch from a `ghost://` link with a canary payload, then `adb root`: `/data/system_ce/0/recent_tasks/*` and `dumpsys activity recents` hold no canary (control: a test APK without `persistNever` and the relaunch shows it, V-U31) |
| T55, T57 | gate; release (black box) | background past the timeout (0 and 60 s), return, dump; hide with a view-once item open: no handle after `onStop`; wipe then `run-as` inventory and `dumpsys jobscheduler`, `alarm`, `notification` |
| ATF | gate | `enableAccessibilityChecks()` (Compose ≥ 1.8, `ui-test-junit4-accessibility`) over every screen on API 35: zero errors |
| Process death | gate | `am kill` at every step of the J1 and J2 screens (fixture state), then relaunch: locked when a lock exists, resumed from engine state alone (the onboarding step in `ui_settings`, `openPurchases`, the activation state), drafts lost as declared; the journeys' own process-death cases are the JVM harness's |
| Smoke | gate | J1's first screens and the home screen render on every level (the journeys themselves run on the JVM, D27) |
| Earlier phases' debts | release | G-DM5 and the release smoke test on the R8 graph that now has callers (Phase 9 review A-4); T4 on both paths (V-U25); T6 dynamic, attributed to GHOST's UID (V-U27); T20 inventory against V-U18's baseline |

### 12.4 Mutants (each registered only with its killer; each detected against a same-scale control; implemented only in test sources or as `pq-mutants.sh`-style source patches)

| ID | Mutant | Killed by |
|---|---|---|
| PM-U1 | `FLAG_SECURE` removed from `SecureActivity` | G-U1; JVM flags; emulator `dumpsys` |
| PM-U2 | a sheet with `SecureFlagPolicy.SecureOff` | G-U1; JVM sheet window; emulator |
| PM-U3 | a `Toast` for "copiat" | G-U1; emulator window list |
| PM-U4 | `SelectionContainer` around a message | G-U2; toolbar spy |
| PM-U5 | a "copy text" item in the message menu | G-U2; clipboard spy; semantics walk |
| PM-U6 | `SensitiveClipboard` without the sensitive extra | G-U2 (constant presence); clipboard spy |
| PM-U7 | the clear moved to 300 s | virtual-clock test; emulator real clock |
| PM-U8 | a copy action on the 24 words | G-U2 path rule; semantics walk |
| PM-U9 | `isSensitiveData` missing on safety digits | semantics canary walk; non-tool dump |
| PM-U10 | decor-level sensitivity missing on dialogs | non-tool dump (API 34+) |
| PM-U11 | a live region announcing message text | live-region test |
| PM-U12 | the contact alias in the notification | G-U10; notification shadow; `dumpsys` canary |
| PM-U13 | `VISIBILITY_PUBLIC` | G-U10; shadow |
| PM-U14 | the composer draft in `rememberSaveable` | G-U6; bundle canary |
| PM-U15 | `SecureActivity` stops clearing the bundle | bundle canary |
| PM-U16 | `requestExpedite()` on opening a conversation | G-U5; recording gateways; NI-UI2 |
| PM-U17 | a status screen reads `paymentInstructions` | G-U5; recording gateways (the shown flag); NI-UI3 |
| PM-U18 | `markDisplayed` for every fetched message | display-semantics test; the T25 countdown case |
| PM-U19 | content composed for one frame at `onStart` | frame test |
| PM-U20 | a new process starts unlocked | process-restart test; emulator |
| PM-U21 | *(withdrawn in revision 2: "the strict lock does not exit"; the strict lock is deferred)* | — |
| PM-U22 | `Linkify` on message URLs | G-U2; semantics walk (no link actions) |
| PM-U23 | the IME interceptor removed | `EditorInfo` test; G-U4 |
| PM-U24 | a blocked `CLAIM` string shipped | G-U8 |
| PM-U25 | message previews in the conversation list | semantics canary walk |
| PM-U26 | a facade call on the main thread | adapter thread assertion |
| PM-U27 | a failed message retried automatically when its conversation opens | recording gateways (zero calls outside intents); G-U5 |
| PM-U28 | opening an undownloaded media item calls a fetch | recording gateways |
| PM-U29 | the foreground session started at VISIBLE (under the lock screen) | open-without-unlock test; emulator |
| PM-U30 | the scanner records every card as `QR_IN_PERSON` | provenance test |
| PM-U31 | `PurchaseView.state` taken from the stored `invoiced` state (instructions before `PAYMENT_READY`) | predicate test against `paymentReady`; J2 journey; recording gateways |
| PM-U32 | the underpaid top-up shown outside `PaymentInstructions` (no hold) | recording gateways; J2 journey |
| PM-U33 | the link left as the task's base intent (no `persistNever`, no relaunch) | G-U11; emulator recent-tasks scan |
| PM-U34 | `GhostTextField` without the text-menu filter | menu-item test; G-U4 |
| PM-U35 | the hide duties skipped (a view-once reader open after `onStop`) | hide test; emulator |
| PM-U36 | the crash handler chains to the platform's default handler | logcat and DropBox canary test (T3) |
| PM-U37 | an effect sentence registered as `FEATURE` without evidence | G-U8 trigger rule |
| PM-U38 | the clip's label not persisted (a clip outlives a restart unchecked) | clipboard restart test; emulator freezer case |
| PM-U39 | the keyboard warning only for non-system keyboards (Gboard silent) | keyboard-warning test |
| MC-U1 | PIN failures not persisted | state-machine restart test |
| MC-U2 | no back-off | state-machine test |
| MC-U3 | files deleted before the key envelope | wipe crash enumeration |
| MC-U4 | leftovers not finished at start | wipe resumption test; emulator |
| MC-U5 | *(withdrawn in revision 2: the strict rewrap; the strict lock is deferred)* | — |
| MC-U6 | onboarding completes without a verified backup | onboarding model test |
| MC-U7 | a state constant without copy | catalogue reflection |
| MC-U8 | the back stack resurrects a deleted contact's route | navigation test |
| MC-U9 | the privacy mode not applied in a job process | process-start test (HIGH before the first session) |
| MC-U10 | an over-limit body reaches the facade | limits test |
| MC-U11 | a cold start with HIGH persisted and a payment hold due: the first session is not HIGH or not held | process-start test |
| MC-U12 | the privacy-mode step after activation (a HIGH user's trial drawn in STANDARD) | onboarding-order test |
| MC-U13 | the 24 words shown before a lock exists | onboarding model test |
| MC-U14 | the failure counter written after the check (a kill after a wrong guess loses it) | kill-point test |
| MC-U15 | the back-off timed on the wall clock (a clock change skips it) | clock-change test |
| MC-U16 | a missed backup position not carried into the next challenge | backup model test |
| MC-U17 | the words shown again after a biometric alone | re-display test |
| MC-U18 | a Keystore failure at open not mapped (the runtime thread dies) | injection test; catalogue |

Fifty-five mutants (57 identifiers, PM-U21 and MC-U5 withdrawn). Reports carry `ui mutants: N run, N detected`, pinned by a report check as `dm-report-check.sh` does, so a report cannot claim more than it ran.

### 12.5 Usability protocol (the owner can run it with 5–10 people; the rest is automated)

| Item | Rule |
|---|---|
| Rounds | **formative**: 5 participants after S4 (J1–J3 and restore), to find problems, preceded by S0a's `WordKeyboard` timing (V-U30); **summative**: ≥ 8 participants on the release candidate, all journeys, to decide the gate (Nielsen: 5 users find most problems; quantitative claims need about 20, nngroup.com) |
| Participants | adults who read Romanian, recruited outside the team: mostly non-technical people who care about privacy; at least one older adult using large text; at least one person with a higher-risk profile (journalist, activist, lawyer); a screen-reader user if one can be recruited, otherwise an expert TalkBack walkthrough recorded as such |
| Setting | provided phones (a mid-range one and a low-end one, OA-2) with the RC build on stagenet; staging relays and issuer if deployed (OA-3), else a `gate` build whose fixture gateways play a scripted engine (activation, payment states, a key change), recorded in the report as such; a stagenet wallet supplied for the payment task |
| Tasks | J1 activate an invite and back up the words; restore on a second phone (timed, NFR-10); J2 buy access up to "plata trimisă" and explain what happens next (token arrival takes hours: verified separately by the scripts); J3 add a contact by QR (including one code shown as a photo on another phone), send, change the timer, verify the safety number, handle a scripted key change; J4 join a password channel with a passphrase given on paper, compare the fingerprint, post; J5 send a photo, view a view-once item; J6 find the version and install an offered update |
| Measures | unassisted completion per task; critical errors; time on the restore task (§5.7's clock); comprehension questions after J1, J2, J3 and J4 (for example "Cine îți vede adresa IP?", "Ce se întâmplă dacă pierzi telefonul?", "Ce înseamnă «Trimis»?", "Ce poate face cel căruia i-ai dezvăluit identitatea?", and one on a `GOAL` row of "Cine vede ce": "E asta o garanție?"); SUS (informative; 68 is the usual mean, measuringu.com) |
| Critical errors | finishing onboarding with words that do not restore; believing a KYC exchange is safe after the warning; accepting a key change believing nothing changed; believing "Trimis" means read; revealing an identity without knowing the proof is transferable; pasting a link received from a stranger as a QR-verified contact; **answering "in front of me" for a code received as a photo**; **reading a design goal as a guarantee** |
| Pass (gate) | **proposed, for the owner to fix (Q42):** per journey, ≥ 80 % unassisted completion (≥ 7 of 8); a critical error in at most one participant per journey; each comprehension item right for ≥ 75 %; NFR-10 median < 3 min; a failure means a fix and a re-test with ≥ 5 new participants on that journey |
| NFR-10 p95 | reported only with ≥ 20 timed restores (the spec's rule, p.12), otherwise "unverified" and completed in the private alpha (Q23) |
| Recording | no screen recording (`FLAG_SECURE` makes it black, and it would capture participants' input): a facilitator's notes, audio with consent, optionally a camera on the hands and phone with consent; recordings deleted 30 days after the report; a consent form reviewed by counsel (GDPR; OA-4) |
| Report | per task: completion, errors, quotes, problems by severity; signed by the facilitator; kept in `docs/usability/` without names |

### 12.6 Device checklist (two phones: one on API 34+ with a hardware Keystore, one low-end; signed)

1. **T10:** hardware screenshot, the system screen recorder, casting, Recents, the assistant and any "circle to search" or OEM screen-AI feature over every P0 screen, a dialog, the keyboard over the composer and the media viewer: black or blocked.
2. **T24:** TalkBack reads a message, the 24 words and a safety number; a test service that is not a tool reads nothing (API 34+); copying an invite link: the keyboard preview is hidden (API 33+) and the clipboard is empty after 30 s in the foreground, and, after the app has been hidden for a minute, empty again once GHOST is reopened; a text-processing app (for example Translate) offers no item in the composer's menu; the keyboard warning appears for the installed default keyboard unless it is AOSP's.
3. **T11:** the lock screen with a new message (nothing shown by default), the shade (constant text), notification history.
4. **Lock:** timeouts, biometric, back-off (a force-stop after a wrong PIN and a system-clock change do not shorten it).
5. **QR:** an 876-character invite printed and on another screen, at 20–40 cm, on the low-end phone; a damaged code fails safely; a card scanned from a photo on another phone with the default answer is unverified.
6. **Restore:** the NFR-10 timing.
7. **Wipe:** the inventory after wipe; the key attestation's rollback-resistance tag read on each phone (V-U29).
8. **Update:** DC-28, then the "Install unknown apps" prompt and the platform confirmation (with Phase 14's staging mirror).
9. **Phase 9 steps 6 and 7** (app lock, restore UI), under Q51.
10. **OS records (C16):** a test app with usage access lists GHOST's resume, pause, stop and notification-interruption events (expected, declared); the privacy dashboard shows the camera use after a scan (declared); after a `ghost://` launch, `dumpsys activity recents` (ADB) shows no link.

### 12.7 Exit-gate evidence and argument

| Gate item | JVM | Emulator | Devices and people |
|---|---|---|---|
| T10 | flags at creation for every window kind; G-U1 | `dumpsys` on every window; capture refused or black; the keyboard; recents placeholder; controls; the release APK's black-box pass | §12.6 step 1 |
| T24 | toolbar, text menu, semantics, clipboard, `EditorInfo`; G-U2 … G-U4 | non-tool and tool dumps; keypad events; real-clock clear; the freezer case; the process-text stub; IME flags | §12.6 step 2 |
| Usability | the journey harness (J1–J6, restore), catalogue | the smoke of J1's first screens | §12.5 summative round; NFR-10 |

The argument: the static gates make the forbidden constructions absent from the shipped sources; the JVM suites prove the shipped components set every flag and route every write as specified, and that the journeys work over the real engines; the emulator suites prove the platform honours those flags on the tested API levels, each check paired with a control that fails without the flag, and the black-box pass shows the same on the release APK that R8 shrank; the device checklist covers what an emulator cannot (OEM features, hardware keys, real keyboards, rollback resistance); the mutants prove each check can fail. The usability round is a human judgement with thresholds the owner fixed. Nothing here covers untested OEM builds, a compromised device or the OS's own records, and the report says so.

---

## 13. Gates, CI, dependencies

### 13.1 Gates (each reads production source sets — `src/main`, `src/release`, and `src/gate` where it says so — through `source-text.pl`, fails on an empty scan, and has a negative fixture with an exact `self-test.sh` hit count and near-miss positives)

| Gate | Invariant | Rules |
|---|---|---|
| G-U1 `ui-secure-window.sh` | T10 | `FLAG_SECURE` set only in `SecureActivity.kt`, before any content call; every `Activity` subclass extends `SecureActivity`; banned: `clearFlags(`, other writes of window flags, `SecureFlagPolicy.SecureOff`, `Toast`, `PopupWindow`, `ListPopupWindow`, `android.app.Dialog`, `AlertDialog`, `DialogFragment`, `Presentation`, `WindowManager` `addView`, `Spinner`, `AutoCompleteTextView`, `PopupMenu`, `PlayerView`, `WebView`, `SurfaceView` without `setSecure(true)`, overrides of `onProvideAssist*`; merged release manifest: exactly one activity |
| G-U2 `ui-text-protection.sh` | T24, ADR-06 | banned everywhere: `SelectionContainer`, `textIsSelectable`, `setTextIsSelectable`, `ACTION_SEND`, `ACTION_SEND_MULTIPLE`, `ShareCompat`, `createChooser`, `dragAndDropSource`, `startDragAndDrop`, `Linkify`, `LinkAnnotation`, `LocalUriHandler`, `autoLink`, the AndroidX `PickVisualMedia` contracts and the picker fallback action strings (`ACTION_SYSTEM_FALLBACK_PICK_IMAGES`, Google Play services' picker action); **exits to other apps** (`ACTION_VIEW`, `ACTION_SENDTO`, `mailto:`, `Intent.parseUri`, a `Uri.parse` with a scheme, `startActivity` with a data URI) only in `SystemIntents.kt`, which holds the platform picker, `ACTION_OPEN_DOCUMENT` and the unknown-sources settings intent; `ClipData`, `setPrimaryClip`, `ClipboardManager`, `LocalClipboard`, `LocalClipboardManager` only in `SensitiveClipboard.kt` and `GhostRoot.kt`; `SensitiveClipboard.kt` must contain the sensitive key, `clearPrimaryClip` and the 30 000 ms constant; the backup, restore, passphrase and safety-number packages never import the clipboard package. Shares one exemption file with Phase 11's G-M1 |
| G-U3 `ui-sensitive-text.sh` | T24, T3 | the unwrap of `SensitiveText` only in `SensitiveTextView.kt`; plus the JVM reflection test over UI models |
| G-U4 `ui-input.sh` | T24, ADR-08 | `BasicTextField`, `TextField`, `OutlinedTextField`, `BasicSecureTextField` only in `GhostTextField.kt`, which must apply `filterTextContextMenuComponents`; `InterceptPlatformTextInput` present in `GhostRoot.kt` |
| G-U5 `ui-isolation.sh` | T53 | `ui/build.gradle.kts` has no `project(` dependency; `android/ui` names no `org.ghost.` package outside `org.ghost.ui`, no network, SQLite or file-writing API, and `android.net.` only as `android.net.Uri` in `SystemIntents.kt`; in `:app`, every method of the traffic-causing list `ui-traffic-methods.txt` (§2.4's rows: `Messaging.send`, `react`, `setTimer`, `retry`, `resetSession`, `reconnect`, `issueRevocation`, `notifyContactsOfRevocation`; `Channels.create`, `createInvite`, `acceptInvite`, `post`, `react`, `remove`, `leave`, `setPolicy`, `reveal`, `resync`; the media `sendMedia`, `retryMedia`, `setDownloadsPaused`; `Entitlement.activate`, `activateGenesis`, `startPurchase`, `requestInvoiceNow`, `checkNow`, `claimPayout`, `createInvite`, `revokeInvite`, `setAutoRenewWithCredits`, `paymentInstructions`, `paymentScreenShown`, `paymentScreenHidden`; `SyncController.requestExpedite`, `onAppForeground`, `onAppBackground`, `setPrivacyMode`, `runUserIssuerCall`; `Updates.requestCheck`, `requestDownload`, `install`) only from the files in `ui-traffic-callers.allow`, each with a reason (G-DM2's pattern); in `:ui`, gateway methods annotated `@UserAction` only from `on…` intent handlers of `*Model.kt` files (PV-14) |
| G-U6 `ui-no-persist.sh` | T54 | in `android/ui` and `org.ghost.app.ui`: no `rememberSaveable`, `SavedStateHandle`, `rememberTextFieldState`, `Parcelize`, `getSharedPreferences`, `PreferenceManager`, `DataStore`, `openFileOutput`, `FileOutputStream`, and no `onSaveInstanceState` override other than `SecureActivity`'s |
| G-U7 `ui-deps.sh` | T7, ADR-06 | an artifact-level denylist (`androidx.browser`, `androidx.webkit`, `androidx.credentials`, `androidx.ads`, `androidx.compose.ui:ui-text-google-fonts`, `com.google.mlkit`, `com.google.android.gms`); test-only groups (`androidx.test`, ATF, Robolectric, Compose test) absent from `releaseRuntimeComponents` and confined to test configurations and `:app-uitest`; the `androidx.startup` initializer set unchanged (the existing rule of `merged-manifest-lint.sh`) |
| G-U8 `ui-claims.sh` | T56 | §8.5's six rules |
| G-U9 (`messaging-no-network.sh` widened) | ADR-20, X-U8 | the `kotlinx.coroutines`, `kotlin.coroutines` and `suspend` ban applies to **every module except `:ui`** and to `:app` outside `org.ghost.app.ui`, so a module added later (Phase 14's `:update`) is covered the day it exists (FE-6) |
| G-U10 `ui-notifications.sh` | T11 | notification builders only in `GhostNotifier.kt`; banned styles, `RemoteInput`, `setNumber`, `Person`, shortcuts, bubbles, `VISIBILITY_PUBLIC`; title and text only from the allowlisted resource ids |
| G-U11 (`merged-manifest-lint.sh` extended) | T15m, T16, T54 | exactly one exported component (the launcher) with `VIEW` filters for scheme `ghost` and hosts `invite`, `contact`, `channel`, `launchMode="singleTask"` and `persistableMode="persistNever"`; no `http(s)` data, no `autoVerify`; permissions within T15 (Phase 14's `REQUEST_INSTALL_PACKAGES` when ADR-51 lands); `android.hardware.camera` not required; applied to **every flavor's** merged release manifest (the mirror flavor; Phase 14's store flavor when it exists, which must also lack `REQUEST_INSTALL_PACKAGES`) |
| G-U12 `ui-l10n.sh` | R13-1 | every string in `values` and `values-ro` with the same placeholders; Romanian plurals with `one`, `few`, `other`; no literal user-visible string in composables |

`anti-placeholder.sh` bans the words "placeholder" and "hardcoded" in production sources, so GHOST's text fields use `label` and supporting text, never Compose's `placeholder` parameter (better for accessibility as well). `no-logging.sh` and `kotlin-clearnet.sh` already cover `android/ui`. **Before the gates count** (S0b's exit), an adversarial review tries to evade each one — Phase 9's first gate set fell 27 of 27 to such a review (§22.33) — and every evasion becomes a fixture or a declared limit (D28).

### 13.2 CI jobs

| Job | Trigger | Runs |
|---|---|---|
| `static-gates` (ci.yml) | every push | G-U1 … G-U12 and `self-test.sh` (fix first: the `dm-golden-lock` case fails on a shallow clone, F-U2) |
| `android` (ci.yml) | every push | `:ui` and `:app` JVM suites (Robolectric), the journey harness, NI-UI1 and NI-UI2 at PR scale, RT-UI1, semantic snapshots, the mutant report |
| `ui-screenshots` (in `android`) | every push, Linux | pixel goldens (informative) |
| `ui-privacy` (new) | weekly and on dispatch, in the rotation | BV-1 … BV-3 at PR scale (each a privacy-world run, about 5 minutes at PR scale: the world took 300 s of `DmPrivacyWorldTest`'s 473 s, F9 §22.36 item 11) |
| `ui-emulator.yml` (new) | **by rotation, not every night** (Q44): API 29, 35 and 37 in the nightly rotation S0a sets or on dispatch at hours the laptop is otherwise idle; API 33 and 36 weekly; PRs touching `android/ui` or `android/app` run API 35 only | §12.3; concurrency group; no other heavy job at the same time (F9 §22.32 item 11) |
| `dm-emulator.yml` | as today | the release smoke test on the graph with callers |

**The emulator tier has never run on a runner.** Every `dm-emulator` run since 2026-09-28, scheduled or on a pull request, ended at its KVM step ("API 29 not run: /dev/kvm is missing or not writable by runner", run 37108821939 of 2026-10-03; `gh run list --workflow dm-emulator.yml`), because the runner user is not in the `kvm` group (read-only check in the `ghost-runner` distribution, 2026-10-03; OA-1); the only green emulator evidence in the repository is a local Windows run (F9 §22.32 item 1), which also recorded a 30-minute boot loop under load (item 11). The four runners on the owner's laptop are saturated on development days and scheduled runs start hours late (F10 §13.2, V10-14; on 2026-10-03 `dm-privacy-gate` had been queued 8 h 39 min, `gh run list`). Hence (normative, Phase 10 §19.11's rule): **S0a** proves that an emulator boots on `ghost-runner` and that the existing `dm-emulator` suites pass there, measures the total nightly occupancy and the per-level runtime of the UI suites (V-U32), and sets the rotation; the gate counts runs on the pinned closing commit, not nights (§14.3 item 3); signed local runs of the same scripts on the closing commit count as gate evidence if the owner accepts them (Q44, the F9 §22.32 precedent); the laptop dependency is declared (R-U8).

### 13.3 Dependencies and licences (closed source: only permissive licences in anything shipped)

| Coordinate | Licence | Shipped | Why | Gate changes |
|---|---|---|---|---|
| `com.google.zxing:core:3.5.4` (2025-11-11, no runtime dependency) | Apache-2.0 | yes | QR encode and decode (D23) | allowlist line `com.google.zxing` (ADR-57); verification metadata; G-L2 licence line |
| `androidx.media3:media3-ui-compose:1.11.0` (matching the pinned Media3) | Apache-2.0 | yes, with media | the player surface (D24) | Phase 11's G-M2 list gains `-ui-compose` |
| `org.robolectric:robolectric:4.17` and its `android-all-instrumented` jars | MIT (POM) | test only | JVM Compose tests, the journey harness | allowlist line marked test-only (the `org.xerial` precedent); G-U7 |
| `androidx.compose.ui:ui-test-junit4`, `ui-test-manifest`, `ui-test-junit4-accessibility` (BOM) | Apache-2.0 | test only | Compose tests; ATF checks | G-U7 |
| `androidx.test:core`, `runner`, `rules`, `androidx.test.ext:junit` | Apache-2.0 | test only, in `:app-uitest` | the emulator platform suites (Phase 9 avoided them with a plain `DeviceRunner`, which `:app`'s own androidTest keeps; ATF and the Compose rules need `AndroidJUnitRunner`, Q25) | G-U7 |
| `com.google.android.apps.common.testing.accessibility.framework:accessibility-test-framework:4.1.1` | Apache-2.0 (S0 confirms) | test only | ATF | allowlist line, test-only |

**Not added:** Navigation 3 and Navigation Compose (D6), `lifecycle-viewmodel-compose`, `material3-adaptive`, `androidx.biometric` (the platform `BiometricPrompt` suffices; the AndroidX one needs a `FragmentActivity`), `androidx.appcompat` (D22), CameraX (D23), UiAutomator (the black-box pass is `adb` from the host), Hilt, Dagger or Koin (manual composition root, as `GhostApp` already is), icon artifacts, DataStore, Coil or Glide. Every coordinate added gets verification-metadata entries, and every shipped one a G-L2 line and a notice.

---

## 14. Slices, effort, exit-gate checklist

### 14.1 Slices (each ends green in CI or, under Q44, in a recorded local run; the Q defaults apply unless the owner objects)

| Slice | Content | Depends on | Exit condition |
|---|---|---|---|
| **S0a** evidence | V-U1 … V-U34 (Appendix C.4; V-U11 withdrawn) on the API 29, 33, 35, 36 and 37 emulators and the two phones, locally first; the `WordKeyboard` timing with ≥ 5 people (V-U30); **an emulator on `ghost-runner` running the existing `dm-emulator` suites, the CI occupancy and the UI suites' per-level runtime (V-U32)** | OA-1 for V-U32's runner half; OA-2 (phones); OA-10 (people for V-U30) | every V-U result recorded in Appendix C with its consequence, and any design change made in this document first; `dm-emulator` green on `ghost-runner` on at least one level, or Q44's local fallback recorded |
| **S0b** gates and test infrastructure | the `:ui` module skeleton (`SecureActivity`, `GhostRoot`, one demo screen) so the gates scan real sources; G-U1 … G-U12 with fixtures and exact `self-test.sh` counts; the evasion review of the new gates; Robolectric pinned and offline; `ui-emulator.yml` and `ui-emulator-check.sh`; F-U2 fixed | S0a's V-U2, V-U4, V-U5, V-U6, V-U26 and V-U34 (their results change G-U1, G-U2 and G-U4) | `static-gates` green with the new gates; each gate fails on its fixture and on an empty tree; every evasion the review found fixed or declared |
| **S1** foundation | design system; `SensitiveText(View)`, `GhostTextField` with `ImeIncognito` and the text-menu filter, `SensitiveClipboard` with the persisted label, `PinPad`, `WordKeyboard`, `SecureDialog`; `QrImage`, `QrScanner`; shell (curtain, back stack, two panes); gateways, adapters, `ghost-ui-io`, `ChangeHub`, `AppPresence`, `ContentLock`, `LinkIntake`; `SettingsStore` and migration UX; `LockController`; `createDatabaseKey`, `restorePrivacyModeFrom`; the session-at-unlock wiring (X-U14) | S0b | the JVM protection suite and the open-without-unlock test green; the emulator T10 and T24 suites green on the demo screens on API 29 and 35 |
| **S1b** test seams | the journey harness (§12.1: the model relay and issuer shared into `:app`'s tests); the `GatewayFactory` build-type twin; `:app-uitest` with `AndroidJUnitRunner`; RT-UI1's rig | S1 | a smoke journey (onboarding's first steps, then home) green on the JVM harness; one `:app-uitest` test green on the gate variant; G-DM5 green with the twin in place |
| **S2** identity and lock | J1 screens and restore in D36's order; the `:identity` index API, the word list and F-U4; `inspectInvite`, `activateGenesis`; backup and verification (carried positions, the full check); the lock wiring and the content-lock hook (`GhostApp` callers, X-U15); `WipeController`; `KEYSTORE_LOST`; the notification-permission step; DC-1 … DC-5, DC-29 | S1b | the J1 and restore journeys green on the JVM harness, NFR-10's clock recording a duration in the scripted restore; T55 and T57 green (JVM and emulator); MC-U6 and MC-U11 … MC-U18 detected |
| **S3** access and payment | J2 screens; `openPurchases` with `PurchaseView.state`, `invites`; NI-UI3's world chosen and built | S2 | the J2 journey green; PM-U17, PM-U31 and PM-U32 detected; NI-UI3 equal |
| **S4** direct messages | the `:messaging` additions of §3.6; every J3 screen (the provenance question); `GhostNotifier`; `markDisplayed`; key change, safety number, requests, block, reconnect; G-DM5 and the release smoke test re-run; BV-1 … BV-3 | S2 | the J3 journey green; T11 on the emulator; NI-UI1 and NI-UI2 equal; BV-1 … BV-3 within their allowance, or Q49 and Q54's fallbacks applied; Phase 9's checklist steps 6–7 executed once on the emulator under Q51, with the output recorded. **The formative round follows** |
| **S5** channels | J4 screens on Phase 10's facade and its coordination items (F-U8, F-U10); the password flow; the fingerprint check with its epoch; NI-UI4 | Phase 10's facade on `main` (Q43) | the J4 journey green with a password channel, a same-epoch mismatch and a different-epoch case; NI-UI4 equal |
| **S6** media | J5 screens on Phase 11's facade (F-U9); NI-UI5 | Phase 11 approved and its facade on `main` (Q37) | the J5 journey green; media windows in the T10 suite; NI-UI5 equal |
| **S7** update, settings, disclosures | J6 on Phase 14's facade; Settings, Securitate, Despre, Ajutor; "Cine vede ce"; the claims register and G-U8 live; licences; local crash reports | S4; Phase 14's facade for J6 | G-U8 green over the real register; the licences screen renders the packaged asset; the J6 journey green (or the recorded fake, Q39); the T3 exception-message canary green |
| **S8** | *(withdrawn in revision 2: the strict mode; Q6)* | — | — |
| **S9** accessibility, localisation, layout | ATF, font scale 2.0, Romanian and English complete (G-U12), TalkBack walkthrough, two panes, edge to edge, `HoldToConfirm`'s alternative | S4, continuing | ATF zero errors on API 35; the semantic snapshots for both languages committed |
| **S10** evidence | the emulator runs of §14.3 item 3; mutants N of N; T4 (both paths), T6 dynamic, T20; the device checklist | S4 … S9 | §14.3 items 1–8, 10–12 and 15 (item 9 is S11's) |
| **S11** summative round | §12.5 on the release candidate, fixes, re-tests | S10, OA-3 … OA-5 | §14.3 item 9 |
| **S12** documents | Appendix B applied: INVARIANTS rows, LIMITE L11 and the amendments, THREAT_MODEL, plan errata, ADR files and index, notes in F9, F10, F11, F14 (STATUS changes with every phase change, this revision included) | S11 | committed with the closing commit |

### 14.2 Effort (calibrated on Phase 9)

**Calibration.** Phase 9's design estimated 10–12 weeks; its slices landed in about nine calendar days of parallel agent sessions, while its gate evidence did not finish (F11 §17.2; STATUS). The Phase 10 and Phase 11 reviews withdrew their team-of-five estimates for that reason (F10 §19.11, FEA-H6; F11 RV-F6). Revision 1's "10–13 calendar weeks for a team of 5–6" repeated the withdrawn model, and its own table did not support it (57.5 person-weeks at about four full-time people is over 14 weeks with perfect parallelism, and 44.5 of them were Android work for two Android engineers, FE-4); it is withdrawn.

| Slice | Implementation (agent-days) | CI per run | Owner dependency |
|---|---|---|---|
| S0a | 4–6 | local emulators; `ghost-runner` once KVM exists | OA-1, OA-2, OA-10 |
| S0b | 3–5 (twelve gates, fixtures, the evasion review) | `static-gates` | — |
| S1 | 5–7 | `android`; emulator API 29, 35 | — |
| S1b | 3–4 | `android` | — |
| S2 | 4–6 | `android`; emulator | — |
| S3 | 2–3 | `android`; NI-UI3's world (the T2 world's runs are up to 240 min and already at risk, F11 R-M13) | — |
| S4 | 5–7 | `android`; `ui-privacy` (three runs of about 5 min); emulator | the formative round after it (OA-4) |
| S5 | 4–6 | `android`; Phase 10's privacy world | Phase 10's facade on `main` |
| S6 | 2–4 | `android`; Phase 11's world | Phase 11 approved and its facade (OA-7) |
| S7 | 4–5 | `android` | Phase 14's facade (OA-7); OA-6 |
| S9 | 3–5 | `android`; emulator API 35 | a TalkBack user or an expert |
| S10 | 3–5, plus the runs | `ui-emulator` on five levels by rotation; `ui-privacy` | the KVM runner or Q44; two phones |
| S11 | 2–4 (analysis and fixes; the sessions are people's time) | — | OA-3, OA-4, OA-5 |
| S12 | 1–2 | — | — |
| **Total** | **≈ 45–70 agent-days** | | |

With S1b beside S0b's tail, S3 beside S4 after S2, S5–S7 as their facades arrive and S9 alongside, that is about **4–7 calendar weeks to "implemented and tested locally"** at two parallel sessions (the owner's pace), longer if Phases 10, 11 and 14 deliver their facades later. **The exit gate has no date this design can promise.** Its closure blockers:

| Closure blocker | Owner | Needed by | Lead time |
|---|---|---|---|
| The KVM runner (OA-1), or the owner's acceptance of signed local runs (Q44) | owner | S0a's runner half; S10 | days |
| CI capacity: the rotation fits the four laptop runners (V-U32; F10 Q20's rule) | owner | S10 | weeks of runs, bounded by the laptop's hours (R-U8) |
| Two phones (OA-2) | owner | S0a, S10 | days to weeks |
| Phases 10, 11 and 14's facades on `main`, with F-U8 … F-U10 | those phases; the owner's decisions (OA-7) | S5, S6, S7 | unknown |
| Participants, a facilitator, the consent form (OA-4) | owner | after S4; S11 | weeks |
| The editor and counsel (OA-5) | owner | S11 | counsel's calendar |
| Staging relays and issuer (OA-3), or the recorded fixture setting | owner | S11 | open since Phase 8 |
| Phase 9's gate-variant restore command (Q51) | Phase 9 | S4 | days |

A copywriter-designer is not in the plan's team; the agents write the first copy and OA-5's editor reviews it (R-U11). The plan's 4–6 weeks did not count five facades, about 55 screens with seven states each, twelve gates, the emulator matrix and two moderated rounds; Q26 asks to restate plan row 13 the Phase 11 way (its Q22): an implementation estimate in agent-days and a gate dated by owner actions.

### 14.3 Exit-gate checklist (all on the closing commit)

1. G-U1 … G-U12 green, `self-test.sh` green with every new case; the gates' evasion review closed.
2. JVM suites green with 0 skipped: protection, recording gateways, the open-without-unlock and provenance tests, the journey harness (J1–J6, restore), twins NI-UI1 … NI-UI5 (or P-U5's narrowed scope where a world does not exist yet), RT-UI1 within its bound, snapshots, crash enumerations, catalogue, limits.
3. `ui-emulator` green on the closing commit: **at least 3 runs each on API 29, 35 and 37 (`google_apis`) and at least 1 run each on API 33 and 36**, 0 skipped, in the rotation of §13.2 — or signed local runs of the same scripts on that commit, recorded as such, if the owner accepted them (Q44).
4. T10 evidence in all three tiers (§12.7), the release APK's black-box pass included.
5. T24 evidence in all three tiers, the freezer case included.
6. T53, T54, T55, T56, T57 executable and green (Q36); BV-1 … BV-3 within their allowance or their fallbacks applied (Q49, Q54).
7. `ui mutants: 55 run, 55 detected` (or the registered count), checked by the report gate.
8. The device checklist (§12.6) signed for both phones.
9. The summative usability report meets the thresholds the owner fixed (Q42); NFR-10's median recorded (and p95 if ≥ 20 restores).
10. G-DM5 and the release smoke test green on the R8 graph that ships with the UI.
11. T4 (both paths), T6 dynamic (attributed, with an update run) and T20 executed on the emulator, results recorded in INVARIANTS.
12. ATF zero errors on API 35; the TalkBack walkthrough recorded.
13. The claims register reviewed (OA-5) and the licences screen present (ADR-37 point 3).
14. Documents of §14.1 S12 applied; this review's findings (§19) corrected or recorded as owner decisions.
15. `static-gates` and `android` green **on a runner** on the closing commit (F-U2 fixed).

---

## 15. Risks

| ID | Risk | Likelihood / impact | Mitigation | Residue |
|---|---|---|---|---|
| R-U1 | Phase 10, 11 or 14 facades arrive late or change | high / high | gateways and fakes decouple the screens; S5–S7 wait (Q37, Q39, Q43) | the gate date follows theirs |
| R-U2 | The summative round fails on the seed or the payment | medium / high | the formative round after S4; copy iterations; re-test rule | schedule |
| R-U3 | Decor-level sensitivity does not reach Compose nodes or dialogs on some version | medium / medium | V-U3 in S0a; leaf marking stays as the second layer | declared per version |
| R-U4 | OEM capture features ignore `FLAG_SECURE` | low / high | device checklist; disclosure | L11-U1 |
| R-U5 | Users who need keys bound to every unlock (LIM:31) have none in Phase 13 | medium / medium | the deferral is stated (Q6); §5.3 is the next design's input; DC-1 and DC-2 point to a dedicated device | L11-U8 |
| R-U6 | The mandatory PIN annoys users into uninstalling | medium / medium | biometric convenience; timeout choices (Q5) | — |
| R-U7 | Robolectric on JDK 17 stops at SDK 35 | certain / low | API 36–37 on the emulator and devices | — |
| R-U8 | Emulator CI on the owner's laptop runners is absent (never green on a runner so far), saturated or slow | **certain** / high | S0a proves the runner first; a rotation from measured occupancy; signed local runs as fallback (Q44); report checks refuse unmeasured claims; retries forbidden | the gate's date follows the laptop's hours |
| R-U9 | Tor bootstrap time spoils onboarding | medium / medium | honest progress copy; measured in S0a; Phase 12 tuning | — |
| R-U10 | Payment takes hours, so J2 cannot finish in a session | certain / medium | the session ends at "plata trimisă" plus comprehension; token arrival verified by scripts | declared in the report |
| R-U11 | Copy quality without a dedicated writer | medium / medium | OA-5 editor; the register forces review of every security sentence | — |
| R-U12 | Facade calls on the single DM actor make the UI stutter, or UI reads delay a due actor turn | medium / low | off-main, two in flight, stale-while-loading; V-U17 measures, RT-UI1 bounds | the declared bound |
| R-U13 | "No copy" frustrates users (URLs, addresses) | high / low | stated in DS copy; usability feedback | L11-U15 |
| R-U14 | Behaviour differs across API 29–37 (clipboard, notifications, accessibility) | high / medium | the version matrix of §2.3 drives tests and copy | per version |
| R-U15 | Hand-rolled navigation bugs | medium / low | navigation tests; Navigation 3 stays the fallback (D6) | — |
| R-U16 | A screen reader vendor's cloud feature captures screens | medium / medium | DC-20; V-U20 measures | declared |
| R-U17 | The keypad-only secrets miss NFR-10's median | medium / high | V-U30 times a prototype in S0a; the word keypad completes at the unique prefix; Q15's fallback | the alpha's measurement |
| R-U18 | The cached-app freezer stops background timers (the clipboard's 30 s) | certain on Android 14+ / low | the persisted label and the next-focus clear; Q10's alarm option | L11-U19 |
| R-U19 | Phase 10 or 11 does not deliver its coordination items (invite preview, listener, pause method) | medium / medium | F-U8 … F-U10 raised now; the screens degrade (an explicit confirmation without a preview; no pause switch) | the journeys' scope |
| R-U20 | The notification-coupled use (BV-1) moves the DM statistics | medium / medium | BV-1 in S4; Q49 | declared |
| R-U21 | The Phase 9 cycle (its gate counts a checklist step that needs Phase 13's UI) delays both gates | medium / medium | Q51: Phase 9 adds the gate-variant restore command | — |
| R-U22 | Sessions at unlock surprise users (nothing syncs while only the lock screen shows) | low / low | the lock screen says "conectarea pornește după deblocare" | — |

---

## 16. Owner questions (the proposed default applies unless the owner objects)

| # | Question | Proposed default | Pe scurt (RO) |
|---|---|---|---|
| Q1 | Approve ADR-53 … ADR-57 (Appendix A) as "propus, aplicat"? | **yes** | Aprobarea ADR-53 … ADR-57 |
| Q2 | A `:ui` module with no engine dependency, `:app` as composition root, amending plan Appendix B? | **yes** | Interfața într-un modul separat, fără acces direct la motoare |
| Q3 | Own navigation instead of Navigation 3 (D6)? | **yes** | Navigare proprie, fără bibliotecă nouă |
| Q4 | One app lock: a curtain with the hide and lock duties of §3.3 (Phase 11's media duties moved to the content-lock hook, X-U15) and the DM context kept open (amends F9 §2.5, §13.7)? | **yes** | Blocarea ascunde ecranul și închide media; contextul DM rămâne deschis |
| Q5 | App lock mandatory (no "off"); timeout 1 min by default; choices 0, 1, 5, 30 min? | **yes** | PIN obligatoriu; blocare după 1 minut |
| Q6 | The strict lock (authentication-bound keys): (a) **defer** to its own design after Phase 13's gate, with §5.3's requirements; (b) build its content-bound shape (§5.3 item 2 (a)) in Phase 13, non-gating, after its engine changes and strict client profiles in the T2 and DM worlds; (c) revision 1's full strict mode, with purchases, claims, revocations and refreshes refused while it is on? | **(a) defer** | Modul strict se amână la un design separat; azi ar opri plățile și ar schimba ce văd releele |
| Q7 | Notifications on by default, constant text, no count, hidden on the lock screen, no badge; count, lock-screen display and off as options (T33 amended for the count)? | **yes** | Notificare fixă, fără număr, ascunsă pe ecranul de blocare |
| Q8 | Accessibility options A and C of §9.3 (sensitive nodes; services screen; the warning before secrets; opt-in hiding from all services, keypads included)? | **yes** | Ascundem conținutul de serviciile care nu sunt de accesibilitate; cititoarele de ecran merg |
| Q9 | Romanian and English at launch, Romanian written first, English fallback, informal "tu"? | **yes** | Română și engleză; „tu” |
| Q10 | The clipboard outside the foreground: (a) the persisted label, the clear at GHOST's next focus, and no unconditional clear more than 5 min late; (b) (a) plus an inexact alarm per copy that wakes GHOST to clear (an OS alarm record at each copy); (c) unconditional clears however late (may erase another app's newer clip)? | **(a)** | Golim clipboard-ul la 30 s cât aplicația rulează, altfel la următoarea deschidere |
| Q11 | No share sheet for invite links; QR and sensitive copy only? | **yes** | Fără „Partajează”; doar QR și copiere |
| Q12 | QR through zxing core 3.5.4 and Camera2, no CameraX? | **yes** | QR cu zxing și camera platformei |
| Q13 | URLs in messages as plain text, not tappable, no previews? | **yes** | Linkurile din mesaje nu se pot apăsa |
| Q14 | No message previews in the conversation list? | **yes** | Lista de conversații fără text din mesaje |
| Q15 | The PIN, the 24 words and channel passphrases only on in-app keypads, with no paste; if V-U30's prototype misses its budget (median 24-word entry above 120 s), first iterate the keypad, then ask again with the alternative (the system IME for restore only, flagged, with a warning)? | **yes** | Secretele se tastează doar pe tastatura aplicației; o măsurăm înainte |
| Q16 | No prompt-mode foreground service in Phase 13 (a later ADR with battery measurements)? | **defer** | Fără serviciu permanent acum |
| Q17 | No upload foreground service (F11 Q30); uploads continue in background jobs? | **none** | Încărcările continuă în fundal, fără serviciu |
| Q18 | Read receipts (F9 Q8) not built? | **not built** | Fără confirmări de citire |
| Q19 | Card rotation with contact backup, Invite v3, the reduced reply card, the governance engine (so ADR-27's abuse reports through ADR-13 flags do not exist yet while screenshots are blocked, which DC-27 says), the deniable reveal and sponsor-confirmed admission: separate designs before Phase 15, in that order of priority (card rotation first, it closes L7 rows; governance before GA)? | **yes** | Funcțiile de protocol trimise „în Faza 13” primesc designuri separate |
| Q20 | Crash reports captured and reviewed locally now; the sending path designed with an operator endpoint later (FR-8.11 partly open)? | **yes** | Rapoarte de crash locale acum; trimiterea mai târziu |
| Q21 | Genesis onboarding only in builds whose policy enables it (stagenet, the owner's one-off bootstrap build), never in distributed mainnet builds? | **yes** | Bootstrap-ul fără invitație doar în build-uri speciale |
| Q22 | PIN digits only, 6–16; the counter committed before each check; back-off from the fifth failure, doubling to 1 h, on `elapsedRealtime` and re-armed at every start; no automatic wipe? | **yes** | PIN de 6–16 cifre; așteptarea nu se ocolește; fără ștergere automată |
| Q23 | NFR-10: the gate reports the median; p95 only with ≥ 20 restores, else completed in the alpha? | **yes** | Timpul de restaurare: mediana acum, p95 în alfa |
| Q24 | Semantic snapshots (screens × languages × font scales, no theme axis) as the regression gate, pixel goldens on Linux as information, no Roborazzi or Paparazzi? | **yes** | Teste de „captură” pe arborele semantic, fără biblioteci noi |
| Q25 | Test-only dependencies: Robolectric 4.17, AndroidX Test (in the new `:app-uitest` only), ATF 4.1.1? | **yes** | Dependențe noi doar pentru teste |
| Q26 | Restate plan row 13 the Phase 11 way: ≈ 45–70 agent-days to "implemented and tested locally", the gate dated by owner actions and by Phases 10, 11 and 14's facades; if a date binds, cut first (a) J5 to after Phase 11 (Q37), then (b) J6 on the scripted fake (Q39), never T10's or T24's protections? | **yes; no cut** | Estimare în zile-agent; data porții o dau acțiunile proprietarului |
| Q27 | Wipe local only; revocation a separate P1 screen? | **yes** | Ștergerea e locală; revocarea e separată |
| Q28 | Dynamic colour on API 31+ by default, fixed safety colours? | **yes** | Culori Material You; culorile de avertizare fixe |
| Q29 | No lock grace for picker, settings or authentication round trips? | **yes** | Fără excepții de la blocare |
| Q30 | The keyboard warning for every default keyboard other than AOSP's, once and in Settings? | **yes** | Avertisment pentru orice tastatură care nu e cea AOSP |
| Q31 | **Reversed in revision 2.** The foreground session starts at unlock, never under the lock screen; an open that carries a link waits U[0, 2 min] more, or until the user's first action that causes traffic (D33)? | **yes** | Sincronizarea pornește la deblocare, nu sub ecranul de blocare |
| Q32 | The restore cliff declared with a "before changing phone" checklist; no token or contact backup in Phase 13? | **yes** | La restaurare se pierd contactele și accesul; o spunem clar |
| Q33 | Onboarding disclosures as three short mandatory cards plus reference pages? | **yes** | Trei carduri scurte la început; restul în setări |
| Q34 | Drafts kept in memory across hides and locks, lost at process death, never persisted? | **yes** | Ciornele rămân doar în memorie |
| Q35 | The channel passphrase drawn from the embedded BIP-39 English list through the identity gateway, framed distinctly from the seed? | **yes** | Parola canalului: 5 cuvinte din aceeași listă, prezentate diferit |
| Q36 | Close Phase 13 only with T53–T57 green as well as the plan's T10 and T24? | **yes** | Închidem faza și cu invarianții noi verzi |
| Q37 | The media leg of the gate waits for Phase 11's approval and facade (no cut)? | **wait** | Partea de media așteaptă Faza 11 |
| Q38 | STANDARD by default; the mode chosen in onboarding before the invite is activated, and in Settings? | **yes** | Modul standard implicit; alegerea se face înainte de activare |
| Q39 | The update leg on staging with Phase 14's updater if it has landed, otherwise a scripted fake in a non-distributed test build, recorded as such? | **yes** | Actualizarea se testează cu Faza 14 dacă e gata, altfel cu o simulare declarată |
| Q40 | The schema migration number by merge order (UX = the next free version)? | **yes** | Numărul migrației la merge |
| Q41 | After scanning a contact card, ask where the code was shown ("in front of me" → verified; the preselected "I don't know" and the other answers → unverified)? | **yes** | După scanarea unui card întrebăm de unde e codul |
| Q42 | The usability thresholds of §12.5 (≥ 8 participants; per journey ≥ 80 % completion, a critical error in at most one participant, each comprehension item ≥ 75 %; a re-test with ≥ 5 new participants), which the design proposes and the plan does not fix? | **yes** | Pragurile testului de utilizare, propuse de design |
| Q43 | The channel leg of the gate waits for Phase 10's facade on `main` (no cut)? | **wait** | Partea de canale așteaptă fațada Fazei 10 |
| Q44 | Emulator evidence: the rotation of §13.2 (API 29, 35, 37 three runs each, API 33 and 36 one run each, on the closing commit), signed local runs of the same scripts on that commit accepted when the runner cannot run them (the F9 §22.32 precedent), and the laptop dependency declared? | **yes** | Emulatorul: rulări pe rotație; rulări locale semnate acceptate ca rezervă |
| Q45 | The test seam: the journeys on the JVM over the real engines and the model peers; the emulator's fixture gateways as a build-type twin under G-DM5's existing rule (no amendment); a new `:app-uitest` module with `AndroidJUnitRunner`? | **yes** | Călătoriile se testează pe JVM; emulatorul verifică platforma |
| Q46 | A payment screen without an "open in wallet" button (QR, copy address, copy amount)? | **yes, no button** | Fără buton „Deschide în portofel” |
| Q47 | The backup check: (a) 4 positions with the missed ones carried, plus an offered full 24-word check; (b) a mandatory full check (about 2 minutes more; it catches every miscopied word)? | **(a)** | Verificăm 4 cuvinte și oferim verificarea completă |
| Q48 | Showing the words again needs the typed app PIN and the device credential (never a biometric alone)? | **yes** | Reafișarea cuvintelor cere PIN-ul tastat și deblocarea telefonului |
| Q49 | Notifications in HIGH mode: as in STANDARD, unless BV-1 moves S-DM1 or S-DM2 beyond their allowance; then off by default in HIGH? | **yes** | În modul ridicat, notificările se opresc implicit doar dacă măsurătoarea o cere |
| Q50 | A build without the updater (Phase 14's store flavor) shows the version and "updates come from the store" only? | **yes** | Varianta din magazin arată doar versiunea |
| Q51 | The Phase 9 cycle: (a) Phase 9 adds a gate-variant restore command for its checklist step 7; (b) Phase 9's gate item 11 waits for Phase 13's S4? | **(a)** | Faza 9 își adaugă comanda de restaurare pentru verificare |
| Q52 | An undecided key change is a persistent in-app banner with its bound, never a system notification (amends LIMITE L7-D17)? | **yes** | Schimbarea de cheie se arată în aplicație, nu ca notificare |
| Q53 | A channel reveal needs a same-epoch fingerprint comparison confirmed inside the reveal flow (nothing stored)? | **yes** | Dezvăluirea cere întâi compararea codului canalului |
| Q54 | J1's ACTIVATE order: (a) the device's natural order (ACTIVATE inside the running foreground session), measured by BV-2 and BV-3; (b) only if they fail, an onboarding hold in `:sync` (no relay session before ACTIVE; `RedeemInvite` on its own transport; a `:sync` change that re-runs T19 and T23)? | **(a); (b) only on failure** | Ordinea activării se măsoară; schimbăm sincronizarea doar dacă e nevoie |

---

## 17. Owner actions (not code)

| ID | Action | Before |
|---|---|---|
| OA-1 | Add the runner user to the `kvm` group (`usermod -aG kvm runner`) and restart the four runner services; allow the emulator images in the runner SDK cache; accept that gate runs depend on the laptop's hours (Q44) | S0a's runner half; S10 |
| OA-2 | Two test phones: one on API 34+ with a hardware Keystore (StrongBox if possible), one low-end; optionally an API 29–30 device | S0a |
| OA-3 | Staging deployment (issuer, three relays, two mirrors), open since Phases 8, 9 and 14 | S11 |
| OA-4 | Recruit 5 + ≥ 8 participants, incentives, a facilitator, a consent form reviewed by counsel (GDPR) | the formative round |
| OA-5 | A native Romanian editor and counsel for the payment, privacy and Tor-guide texts and the claims register | S11 |
| OA-6 | The security contact for the About screen (FR-8.6) | S7 |
| OA-7 | Decide the Phase 11 and Phase 14 designs (the media and update legs depend on them) | S6, S7 |
| OA-8 | The CI red of F-U2 (`fetch-depth: 0` for the `static-gates` checkout) | S0b |
| OA-9 | Phase 9's A-2 (the alarm under Doze) with the device check | any time |
| OA-10 | At least 5 people for about 15 minutes each to time the `WordKeyboard` prototype (V-U30; people from the owner's circle are fine for this check) | S0a |
| OA-11 | Fix Q42's usability thresholds and Q44's evidence rule | S10 |

---

## 18. Findings outside Phase 13 (proposed as separate tasks)

- **F-U1.** FR numbering errata: the plan's FR-1.5 and FR-1.6 (plan:259-260) are the spec's FR-1.6 and FR-1.7; LIMITE's FR-1.7 (LIM:31) is FR-1.8 and its FR-1.9 is right; the plan's FR-6.8 (plan:270) and `Disclosure.kt`'s comment are the spec's FR-6.9 (spec p.8, p.10, read with `pdftotext -table`). Appendix B.1.
- **F-U2.** `static-gates` is red on one of 707 self-test cases (`dm-golden-lock`, "unreadable base" on a shallow clone; needs `fetch-depth: 0`), verified on run 36434212692 at `197b2b4` (706 cases ok, this one failing; `gh run view`, 2026-10-03) and reported by the research for run 36403499762: fix before Phase 13 adds gates, or a new red hides.
- **F-U3.** The runner user is not in the `kvm` group (`/dev/kvm` exists with `kvm_intel nested=Y`), so `dm-emulator.yml` fails on permission, not on missing virtualization (checked read-only in the `ghost-runner` distribution, 2026-10-03; every run since 2026-09-28 ended at its KVM step, `gh run list`): OA-1.
- **F-U4.** `Bip39.encode` and `decode` build the entropy as a `String` of '0' and '1' (`Bip39.kt:29-56`): an unzeroizable copy of the root in the heap (the A-1 family of the Phase 9 review). Fixed in S2 because Phase 13 touches the code.
- **F-U5.** Phase 10 §4.5's channel sentence compares channels with DMs (`faza10-forum.md:365`), a PQ claim before ADR-36's evidence (X-U11): an erratum to F10.
- **F-U6.** T7's allowlist admits every `androidx.` artifact, including GMS-bound ones, and the denylist lacks Annex D's `androidx.ads` and `androidx.credentials` (plan:464): G-U7 adds an artifact-level list; the plan should name it.
- **F-U7.** LIMITE rows that name "rotația cardului (Faza 13)" and F11 Q15's "CameraX in Phase 13" need errata once Q19 is decided.
- **F-U8.** Phase 10 coordination: per-channel unread counts, per-post timer and expiry, and a content-free `ChannelListener` in the facade's first slice.
- **F-U9.** Phase 11 has no method or state for the "pause media download" switch (prose only, `faza11-media.md:548`), although it changes a relay-visible read schedule, and its lock duties hang on `GhostApp.onLock` (F11:978), which X-U1 leaves uncalled: Phase 11 needs `setDownloadsPaused` and `downloadsPaused` persisted in its schema with a twin in its world, and its duties callable from `onContentLock` (X-U15).
- **F-U10.** Phase 10: `acceptInvite(link, null)` on an open link runs `CH-ACCEPT` at once (F10 §10.3), so the accept screen's preview needs `inspectInvite(link)` (local parse, no state); and the fingerprint copy of F10 Q49 should show the epoch, since two honest members at different epochs see different codes.
- **F-U11.** Phase 14: the `GHRM` release record carries a version code and name, no release notes (`faza14-distribution.md:397`), while F14 §0.4 and §1.3 list "release notes" as Phase 13's: either a format field or the item is withdrawn.
- **F-U12.** Phase 9's gate item 11 includes checklist steps 6–7, and step 7 needs Phase 13's restore UI or a gate-variant restore command (`faza9-dm.md:3677`), while the plan makes Phase 13 depend on Phase 9: a cycle (Q51).
- **F-U13.** `AppDatabase.open` catches only `UserNotAuthenticatedException` (`AppDatabase.kt:43-48`): any other Keystore failure would end the sync runtime's thread. Fixed in S2 (§5.4) because Phase 13 owns the screen it needs.
- **F-U14.** LIMITE L7-D17's mitigation, "notificare persistentă în Faza 13" (`LIM:286`), conflicts with T11's constant text: amended to an in-app banner (X-U17, Q52).
- **F-U15.** F9's T35 report lists LINK-sourced sealing from the world's record of how each card arrived (§22.8.7 rule 6); on a device that record is the user's provenance answer (D34), and the listing's text should say so.
- **F-U16.** The strict lock needs its own design with §5.3's requirements; it touches F7 (`SyncRuntime`'s open and a latch), F8 (quiet runs), F9 (the key wrappers), F10 (`mls_state_key`) and F14 (update runs) (Q6).
- **F-U17.** Phase 11's picker sentence ("on API 29 it falls back to `ACTION_OPEN_DOCUMENT`", `faza11-media.md:472`) is incomplete: since AndroidX Activity 1.10 the `PickVisualMedia` contract tries the public `ACTION_SYSTEM_FALLBACK_PICK_IMAGES` first where the platform picker is missing, and on GMS devices Google Play services implements it (FX-1; V-U34).

---

## 19. Design review, round 1 (2026-10-03): findings and dispositions

Three adversarial reviews examined revision 1 (`4aee8ce`): **protocol and cryptographic soundness** (`CR-1 … CR-22`, the reviewer's F1 … F22: 3 high, 2 medium-high, 7 medium, 3 medium-low, 7 low), **privacy, metadata and threat coverage** (`PV-1 … PV-21`: 5 high, 2 medium-high, 9 medium, 2 medium-low, 3 low) and **feasibility, testability, scope and consistency** (`FE-1 … FE-18`: 3 high, 7 medium, 8 low). Every finding was checked before anything changed: in the repository at the cited lines (the code is identical at `197b2b4` and `8a480a7`), in Phase 14's revision 2 (`bab523e`, merged into this branch), in the CI run history (`gh run list`, `gh run view`), in AOSP sources (the privacy reviewer's fetched copies of `Task.java`, `TaskPersister.java`, `ActivityRecord.java`, `Intent.java`, `UsageEvents.java` and `UsageStatsService.java` re-read; `BackupEligibilityRules.java` and `LocalTransportParameters.java` fetched again), or at a primary source (Appendix C.2). **None was found wrong.** Three were adopted in a different form, with the reason stated: CR-1, PV-1 and FE-5 (the strict lock is deferred rather than patched, since every fix the reviews list is a cross-phase engine change); PV-6 (every open, not only the non-launcher ones, waits for an unlock, since the launch source cannot be authenticated); CR-10 and PV-10 (no alarm per copy by default, since it would add an OS activity record; Q10 keeps it as an option). "Confirmed" means the evidence was re-examined, not taken from the review.

| Finding | Claim (short) | Verdict | Disposition |
|---|---|---|---|
| CR-1, PV-1, FE-5 | strict mode stops every quiet run (paid purchases never deliver tokens), update runs and background DM and channel steps; its relay- and issuer-visible cadence is unanalysed; it hides cross-module work and has no invalidation path | confirmed (`AppDatabase.kt:22-23, 41-42`; `SyncRuntime.kt:97, 112, 476-482`; F8 D14, §12.2, §19.14; F14 §7.3) | adopted in a different form: **deferred** (D14, §5.3, Q6, F-U16); §5.3 records every consequence and both candidate shapes; S8, MC-U5, PM-U21, DC-26, revision 1's CS-U3 and the strict rows of §2.4, T55 and L11 withdrawn or rewritten |
| CR-2 | every QR scan is recorded `QR_IN_PERSON`, so verified; it falsifies T35's PQ-R8 listing | confirmed (`ContactSteps.kt:441-445`; F9 §8.4, `faza9-dm.md:1243, 3264`) | D34, X-U16, §4.7, §6.4, DC-11, DC-33, PM-U30, a critical error in §12.5, Q41, F-U15 |
| CR-3 | (a) instructions before `PAYMENT_READY`; (b) the underpaid top-up bypasses the hold; (c) a strict cold start loses the hold and the mode; (d) a copied address can be swapped | confirmed (`EntitlementEngine.kt:200-206, 230-251`; `GhostApp.kt:136`; `AppDatabase.kt:43-48`) | (a) `PurchaseView.state` follows the predicate (§3.6), D35, §6.3, CS-U3, PM-U31; (b) `UNDERPAID` returns to `PaymentInstructions`, PM-U32; (c) moot with the strict lock deferred, kept as §5.3 item 6, and MC-U11 for the standard cold start; (d) DC-32 |
| CR-4, PV-12 | the standard lock skips Phase 11's lock duties; one-shot routes survive a lock | confirmed (`faza11-media.md:686, 719, 738, 978`; L9-M7, R-M11) | `onContentLock` at every hide and lock (§3.3, X-U15, F-U9); the routes popped at lock; PM-U35; T55 |
| CR-5 | the wipe resumption would wipe a strict device at its next start | confirmed (`DatabaseKeyProvider.kt:17-24`; `SyncWiring.kt:36`) | moot with the strict lock deferred; §5.3 item 3 and §5.5's resumption note |
| CR-6, PV-19 | the PIN back-off can be skipped by moving the clock, the check is not ordered against the counter's write, and the retry time is an activity time | confirmed (the `*_minute` convention, `Schema.kt:105-108`; revision 1 §5.1, §10) | §5.2 (counter first, `elapsedRealtime`, re-armed at start, no time column); D15; MC-U14, MC-U15; Q22 |
| CR-7, PV-5 | the words shown before a PIN exists; the mode chosen after the trial's slot was drawn; a weak 4-of-24 check; re-display behind any re-authentication | confirmed (`TrialSteps.kt:204`, `Slots.kt:30-35`, `GhostApp.kt:48`; the arithmetic re-done: 20/24 and 380/552) | D36's order; D17 and §5.6 (carried positions, the offered full check, Q47); re-display behind the typed PIN and the device credential (Q48); MC-U12, MC-U13, MC-U16, MC-U17 |
| CR-8 | a 32-bit check code presented as protection against substituted links | confirmed (arithmetic; FR-7.7 asks only that a damaged code fail safely, spec p.10) | "sumă de control" (§4.7, DC-33); removed from L11-U13's mitigation |
| CR-9 | the channel fingerprint lacks its epoch; a captured member reveals to a puppet; the reveal copy omits the DM card | confirmed (`faza10-forum.md:993, 1582, 2001`; L7-D25) | §6.5 (the epoch rule, the reveal gated on a same-epoch comparison, the card in the warning), DC-17, Q53, F-U10 |
| CR-10, PV-10 | background timers do not run under the cached-app freezer; the lock applies only at the return | confirmed (source.android.com cached-apps freezer; F7:965) | adopted in part: the persisted label and the next-focus clear, the late-timer rule, P-U2 and T24 reworded, V-U28, L11-U19, Q10 (the alarm an option, not the default); hidden UI state dropped at every hide (§3.3); the strict half moot (§5.3 item 7) |
| CR-11 | re-wrapping keeps old keys recoverable; W3 overstated; a device unlock opens the authentication window | confirmed (KeyMint implementer reference; KeyGenParameterSpec javadoc, Microsoft Learn) | W3 and W4 reworded (§5.5), D16, DC-5, V-U29, L11-U21; the strict items in §5.3 items 4 and 5 |
| CR-12 | `FEATURE` sentences escape the evidence gate | confirmed | §8.5 rules 1 and 2 (effect sentences are `CLAIM`s; coverage); the copy of §6.2, §6.6, §6.7, §7.2 and §7.3 split by kind; PM-U37 |
| CR-13 | the post-quantum wording implies that DMs are protected | confirmed (ADR-36 points 4 and 6) | §8.4 ("no post-quantum claim"), DC-31, X-U11 |
| CR-14 | Compose's text menu can offer `PROCESS_TEXT` actions | confirmed for the API (`ProcessTextKey`, the release notes, search summary); its default in 1.12.1 left to V-U26 | D9, §4.2, G-U4, V-U26, PM-U34 |
| CR-15 | no single source for the BIP-39 list; the passphrase's random source unspecified | confirmed (revision 1 §3.1, §3.3, §6.5.1) | the identity gateway's word list and passphrase indices (§3.2); the hash and round-trip tests (§3.3) |
| CR-16 | L7-D17's "persistent notification" neither built nor amended | confirmed (`LIM:286`) | X-U17, D13, §6.4, Q52, F-U14 |
| CR-17 | the keyboard warning misses preinstalled cloud keyboards | confirmed | D12, §4.5, DC-21, PM-U39, Q30 |
| CR-18, PV-7, FE-13 | the twins cannot see timing; "cannot cross a minute" is unachievable; the hold is absent from the DM world; channels and media lack twins; no HIGH | confirmed (`faza9-dm.md:4515-4522`, §22.36 items 2 and 9) | D19, RT-UI1, NI-UI3 on a world with the hold, NI-UI4 and NI-UI5, P-U5's DM-and-STANDARD scope stated |
| CR-19 | accessibility honesty: window events; a self-declared flag where Play Protect does not run; the IME claim unverified | confirmed as gaps (the facts left assumed are marked so) | §2.3 rows, §4.3, §9.3, DC-20, V-U1, V-U33, L11-U2, L11-U20 |
| CR-20, PV-9 | a link launch persists in the OS's task records; `setIntent(Intent())` clears only the app's copy | confirmed (developer.android.com `<activity>`; AOSP `Task.saveToXml`, `TaskPersister`, `ActivityRecord.isPersistable`, re-read) | D7, §3.4, G-U11, T54, V-U31, PM-U33, L11-U13 |
| CR-21, PV-8 | the ACTIVATE order is unfixed; notification-coupled use is unmodelled | confirmed (`faza9-dm.md:4522` items 9(e) and 9(g)) | D36, BV-1, BV-2, BV-3, Q49, Q54 |
| CR-22 | reading the 60 digits aloud exposes who talks to whom | confirmed (§2.1's own asset row) | §6.4, DC-14 |
| PV-2 | a strict cold start loses the hold and HIGH | confirmed | moot with the deferral; §5.3 item 6; MC-U11 for the standard path |
| PV-3 | the lock is decided only at `onStart`; UI state waits in a hidden process | confirmed | §3.3's hide duties, T55, PM-U35; the strict half in §5.3 item 7 |
| PV-4 | the in-app "verify this app" was removed by Phase 14's revision 2, which also requires new alarms, the release information's age and a Play Protect disclosure | confirmed (`faza14-distribution.md:266, 735-739, 844, 1324`) | `main` merged; D25, §6.7, §6.1's banners, DC-24, DC-28, §8.2's rows, §2.4's install row; the signer fingerprint removed from the copy kinds |
| PV-6 | another app or a web page can choose when GHOST opens, and an open starts a session | confirmed (developer.android.com package visibility; `GhostApp.kt:154-158`) | adopted in a stronger form: every open waits for an unlock (the launcher intent is unauthenticated; `getLaunchedFromPackage` needs the caller's opt-in), and a link open adds U[0, 2 min]; D33, X-U14, C17, L11-U18, PM-U29, Q31 reversed |
| PV-11 | the OS's records of use are undeclared | confirmed (Microsoft Learn `UsageEventType`; AOSP `UsageEvents`, `UsageStatsService` re-read; the camera history from a secondary source) | C16, DC-30, L11-U17, §12.6 step 10 |
| PV-13 | keypad presses reach every accessibility service on API 29–33 | confirmed (nothing is enforced below API 34) | D10, §4.3 (the warning, the keypads in the opt-in), V-U33, L11-U20 |
| PV-14 | G-U5's list is incomplete, and no test forbids calls outside intents | confirmed | G-U5's full list and its `@UserAction` rule; the recording suite's zero rule; PM-U27, PM-U28 |
| PV-15 | exits to other apps are ungated; the wallet button | confirmed | G-U2's exit rule; plain-text references (§4.2, §8.6); no wallet button (D35, Q46) |
| PV-16, FE-11 | evidence IDs are not unique (`NI-U*` collides with Phase 14); the green list is unverified; GOAL rows may read as guarantees | confirmed (`faza14-distribution.md:16, 64, 965-969`) | the `NI-UI*` renaming; §8.5 rules 4 and 5; the GOAL comprehension item and critical error (§12.5) |
| PV-17 | the platform's crash records (logcat, DropBox, tombstones, the file's time) | confirmed | §10 (no chaining, modification time 0), the T3 canary, L11-U23, PM-U36 |
| PV-18 | re-display of the words behind an unspecified re-authentication | confirmed | §5.6 (typed PIN and device credential), MC-U17, Q48 |
| PV-20 | T6's capture cannot attribute packets or see delegated traffic | confirmed | T6's change, V-U27, §2.4's install row |
| PV-21 | (a) strict mode visible from names; (b) a biometric can be compelled; (c) open-channel links are kept | confirmed | (a) §5.3 item 9; (b) DC-29, L11-U22; (c) §6.5 |
| FE-1 | no composition root for emulator journeys | confirmed (`DeviceWorld.kt` in `:messaging`'s androidTest; `AndroidSyncController.kt:116-120`; G-DM5's header; the model peers in JVM test sources; `app/build.gradle.kts:23`) | D27, §12.1's journey harness, the `GatewayFactory` twin, `:app-uitest`, S1b, Q45 |
| FE-2 | the emulator tier has never been green; "three nights on five levels" is not plannable | confirmed (`gh run list`: every `dm-emulator` run ended at its KVM step; the queue times) | §13.2's normative rule, S0a's exit, §14.3 item 3, Q44, R-U8, V-U32 |
| FE-3 | T4, T6 and T20 can pass vacuously | confirmed (AOSP `BackupEligibilityRules.java`, `LocalTransportParameters.java`; the manifest and both rule files) | the T4, T6 and T20 changes; V-U25, V-U27, V-U18 |
| FE-4 | the effort headline repeats a withdrawn model; Q26 is unsupportable | confirmed (F10 §19.11; F11 RV-F6; the table's own arithmetic) | D32, §14.2 in agent-days with closure blockers, X-U6, Q26 |
| FE-6 | the facade and seam inventory is incomplete | confirmed (F11:548; F10 §10.3; F14 §8.2 (c) and `faza14-distribution.md:933`; G-DM1's list; `GhostApp.kt:185-188`) | §3.6's rows, F-U9, F-U10, F-U11, the null `UpdateGateway`, `SystemIntents.kt`, G-U9's "every module except `:ui`", W2 |
| FE-7 | the emulator's build variant is unspecified, and §2.5 claimed "the release build" | confirmed (F9 §22.32 item 3) | §12.1's build column, §12.3, the black-box pass, §2.5 narrowed |
| FE-8 | NFR-10 is at risk from the keypads | accepted as a risk (the estimate is the reviewer's, not a measurement) | V-U30, R-U17, Q15's fallback, the word keypad's completion rule |
| FE-9 | exit conditions are circular or not pass/fail | confirmed | §14.1's exits (S10 and S11, S0b's dependencies, S2, S4), F-U12, Q51 |
| FE-10 | owner questions are missing | confirmed | Q41 … Q54 |
| FE-12 | `HoldToConfirm` has no alternative; WCAG 3.3.8 cited, not applied | confirmed | §9.2 |
| FE-14 | T33 says "constant text" while the count option is not | confirmed | T33's change (§11.2, Appendix B.2) |
| FE-15 | ADR-27's compensating abuse-report path is absent | confirmed (`ADR-27:41`) | DC-27, Q19, ADR-54's consequences |
| FE-16 | the evidence labels are inconsistent; Appendix B.2 wrote T10's outcomes before measuring them | confirmed | the header's wording; T10's change; Appendix B.2 |
| FE-17 | the gates' cost; the snapshots' theme axis | confirmed | the evasion review budgeted in S0b; the theme axis dropped |
| FE-18 | STATUS was not updated with the design | confirmed (`docs/STATUS.md`'s update rule) | the STATUS row in this revision's commit |
| FX-1 (found while fixing) | the AndroidX photo-picker contract can route to Google Play services where the platform picker is missing | from the AndroidX Activity release notes (search summary, 2026-10-03); which component resolves is S0's (V-U34) | D24, §6.6, G-U2, F-U17 |

---

## Appendix A: ADR drafts (Romanian)

### ADR-53 — Stratul de interfață: modulul `:ui`, porți de acces, flux unidirecțional, coroutines doar în interfață, navigare proprie, sesiuni la deblocare

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13, `docs/design/faza13-ux.md`, revizia 2) |
| Sursă | plan §6.2 rândul 13; spec §6.1 (modulul `ui`), FR-7.1 |
| Modifică | plan Anexa B (`app/ # Compose UI, DI, navigare`); ADR-20 punctul 1 („fără coroutines”), doar pentru interfață; designul Fazei 9 §16.3; ADR-06 („+ un foreground service opțional «mod prompt»”), amânat; designurile Fazelor 7 și 8 și `SyncWiring` („vizibilitatea pornește și oprește sesiunea de prim-plan”): sesiunea pornește la deblocare |

**Context.** Fazele 3–11 au livrat motoare fără interfață, în spatele unor fațade blocante: actorul DM rulează pe un singur fir și așteaptă rezultatul fiecărui apel, iar apelurile JNI blochează. Interfața trebuie să le folosească fără să blocheze firul principal, fără să ocolească motoarele și fără să producă trafic pe care releele să-l poată lega de ce face utilizatorul pe ecran. Orice aplicație de pe telefon poate deschide GHOST la un moment ales de ea, iar o pagină web o poate face cu o singură atingere pe un link.

**Decizie.**
1. Un modul nou `:ui` (bibliotecă Android, Compose) conține ecranele, sistemul de design, componentele de protecție, deținătorii de stare, modelele de interfață și interfețele porților de acces. `:ui` nu depinde de niciun modul `org.ghost.*` (poarta G-U5). `:app` rămâne rădăcina de compoziție și adaugă adaptoarele porților, notificatorul, controlerele de blocare și de ștergere, primirea legăturilor și depozitul de setări.
2. Flux unidirecțional: compozabil → intenție → model de ecran → poartă (`suspend`) → adaptor în `:app`, care apelează fațada blocantă pe executorul `ghost-ui-io` (două fire, deci cel mult două apeluri în zbor), niciodată pe firul principal → stare imutabilă într-un `StateFlow`. Schimbările ajung ca indicii fără conținut prin `ChangeHub`; starea motoarelor se citește la 2 s doar cât aplicația e vizibilă și deblocată. Întârzierea pe care citirile interfeței o adaugă unui pas programat al actorului DM se măsoară pe firul real al actorului și are o limită (RT-UI1).
3. Coroutines sunt permise doar în `:ui` și în `org.ghost.app.ui`; în orice alt modul rămân interzise (G-U9 extinde G-DM1 la toate modulele în afară de `:ui`, inclusiv la cele adăugate mai târziu).
4. Starea interfeței trăiește cât sesiunea deblocată și se golește la fiecare ascundere a aplicației. Nicio valoare sensibilă nu intră în `rememberSaveable`, `SavedStateHandle`, `rememberTextFieldState` sau în pachetul de stare salvată al activității, care se golește (T54).
5. Navigare proprie: o stivă tipizată în memorie, niciodată persistată; fără Navigation 3.
6. O singură activitate, singura componentă exportată, cu `launchMode="singleTask"` și `persistableMode="persistNever"`; legăturile `ghost://invite`, `ghost://contact`, `ghost://channel` sunt intrări neîncrezute, citite o singură dată în memorie, după care activitatea se relansează într-un task curat, ca sistemul să nu păstreze linkul; se acționează doar după deblocare și confirmare.
7. Doar acțiunile din lista închisă a designului (§2.4) produc trafic către relee, issuer sau mirror-uri. **Sesiunea de prim-plan și reîncercarea invitației pornesc când aplicația e vizibilă și deblocată, nu când devine vizibilă; o deschidere care aduce un link mai așteaptă U[0, 2 min] după deblocare, sau până la prima acțiune a utilizatorului din lista închisă**; ascunderea și blocarea opresc sesiunea; nimic altceva din interfață nu produce trafic și nu schimbă programul de citire (T53).
8. Fără serviciu în prim-plan în Faza 13 (nici „mod prompt”, nici pentru încărcări): un ADR separat, cu măsurători de baterie.
9. Funcțiile de protocol trimise „în Faza 13” de documentele anterioare (rotația cardului cu copia contactelor, Invitația v3, cardul redus de răspuns, motorul de guvernanță al ADR-13, dezvăluirea negabilă, confirmarea intrării de către sponsor) și **blocarea strictă cu chei legate de autentificarea dispozitivului** primesc designuri separate, înaintea Fazei 15.
10. Testarea: călătoriile se rulează pe JVM peste motoarele reale, cu modelele de releu și de issuer ale Fazelor 7 și 8; emulatorul verifică platforma pe varianta `gate`, ale cărei porți de acces vin dintr-un fixture printr-un geamăn de tip de build (regula existentă a G-DM5, fără nicio deschidere în codul release), plus o verificare din exterior, prin `adb`, a APK-ului release micșorat de R8.

**Consecințe.** (+) Izolarea interfeței e impusă de Gradle, nu de un text; (+) ecranele și călătoriile se testează pe JVM; (+) o aplicație sau o pagină nu mai poate alege momentul unei sesiuni fără deblocarea utilizatorului; (+) motoarele nu se schimbă, cu excepția adaosurilor la fațade enumerate în design §3.6, fiecare cu porțile fazei ei rulate din nou. (−) Cod de mapare între tipurile motoarelor și cele ale interfeței; (−) o excepție declarată de la „fără coroutines”; (−) la ecranul de blocare nu se sincronizează nimic, iar releele văd momentul deblocării; (−) funcțiile amânate lasă deschise reziduurile L7 care le numesc, până la designurile lor.

**Alternative respinse.** Totul în `:app` (fără perete la compilare); module per funcționalitate (prea multe pentru o singură activitate); Navigation 3 1.2.0 (persistă cheile și starea pe intrare, dependențe noi); ViewModel cu `SavedStateHandle` (pachetul pleacă din proces); Hilt, Dagger sau Koin (în afara allowlist-ului; rădăcina de compoziție manuală există deja); sesiunea pornită la vizibilitate (o aplicație sau o pagină ar alege momentul ei); călătoriile pe emulator (nu există rădăcină de compoziție pentru ele, iar o deschidere în codul release e refuzată de G-DM5).

**Teste.** G-U5, G-U6, G-U9, G-U11; suita porților înregistratoare; testul deschiderii fără deblocare; gemenii NI-UI1 … NI-UI5; RT-UI1; T53, T54.

### ADR-54 — Protecția ecranului și a textului, implementată (precizează ADR-27 punctele 1–6)

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13, revizia 2) |
| Completează | ADR-27 punctele 1–6, ADR-08, FR-7.8, FR-7.14 |
| Modifică | T24 („un singur modul aprobat” devine un singur fișier aprobat); ADR-27 punctul 5 (verificarea „mai conține datele GHOST” doar cu focus); ADR-27 punctul 6 (secretele nu mai au câmp cu tastatura sistemului); T11 („cu dispozitiv blocat” devine „blocat sau nu”); X-M11 al Fazei 11 (suprafețele video); LIMITE L7-D17 (o schimbare de cheie nedecisă: banner în aplicație, nu notificare) |

**Context.** ADR-27 a fixat regulile; implementarea lor pe Android are limite care diferă de la o versiune la alta (designul Fazei 13, §2.3). UI-ul nu are voie să promită mai mult decât face platforma. Pe Android 14+ procesele din cache sunt înghețate la 10 s după ce intră în cache, cu toate firele oprite, deci temporizatoarele GHOST nu rulează în fundal.

**Decizie.**
1. **Ferestre.** O clasă `SecureActivity` pune FLAG_SECURE înaintea oricărui conținut, apelează `setRecentsScreenshotEnabled(false)` pe API 33+, marchează decorul ca sensibil pentru accesibilitate pe API 34+, exclude autofill-ul și golește pachetul de stare salvată. Dialogurile, meniurile, ferestrele pop-up și foile se fac doar prin Compose, care moștenesc FLAG_SECURE. Sunt interzise `Toast`, `PopupWindow`, `android.app.Dialog`, `Spinner`, `AutoCompleteTextView`, `PopupMenu`, `PlayerView` și `WebView`. Video și previzualizarea camerei rulează pe `TextureView`.
2. **Text.** Fără selecție nicăieri; fără copiere, partajare, „Trimite către” sau tragere pentru mesaje, postări, media și pseudonime; URL-urile din mesaje sunt text simplu, fără legături și fără previzualizări. Câmpul de compunere rămâne normal, iar copierea și tăierea din el trec prin clipboard-ul sensibil. **Meniul de text al fiecărui câmp editabil păstrează doar tăierea, copierea, lipirea și selectarea totală**: nicio acțiune `PROCESS_TEXT` (traducere, alte aplicații) nu primește textul. Adresele din ajutor, licențe și contact sunt text simplu: GHOST nu deschide browserul, clientul de e-mail sau altă aplicație cu o adresă.
3. **Accesibilitate.** Decorul fiecărei ferestre e marcat sensibil (API 34+) și fiecare element de conținut poartă `isSensitiveData`; toate semanticile rămân pentru instrumentele de accesibilitate (TalkBack, Switch Access, Voice Access); anunțurile sunt fără conținut („Mesaj nou”); acțiuni personalizate înlocuiesc meniurile la apăsare lungă. Ecranul „Cine poate citi ecranul” arată serviciile active și oferă, opțional, ascunderea conținutului și a etichetelor tastaturilor aplicației de toate serviciile. **Înaintea tastării unui secret** (PIN-ul, cuvintele, parola de canal), dacă un serviciu ar vedea apăsările — orice serviciu care nu e de sistem pe API 29–30, orice serviciu care nu e instrument pe API 31–33 — un avertisment îl numește.
4. **Clipboard.** Un singur fișier (`SensitiveClipboard.kt`) scrie în clipboard, doar date cerute de utilizator care nu sunt conținut: linkuri de invitație, de contact și de canal, subadresa și suma de plată. Fiecare scriere are `EXTRA_IS_SENSITIVE` și o etichetă aleatoare, păstrată în bază. Ștergerea are loc la 30 s cât procesul rulează, la blocare și la ștergerea datelor: cu focus, doar dacă datele sunt încă ale GHOST; fără focus, necondiționat, dar nu mai târziu de 5 minute după termen. Un clip rămas după ce procesul a fost înghețat sau oprit se șterge la următoarea deschidere a GHOST, dacă eticheta e tot a lui. Cuvintele seed-ului, parolele de canal, cifrele de siguranță și PIN-ul nu se copiază niciodată.
5. **Tastatură.** `IME_FLAG_NO_PERSONALIZED_LEARNING` pe fiecare câmp cu tastatura sistemului, printr-un interceptor la rădăcina fiecărei ferestre. PIN-ul, cele 24 de cuvinte și parola de canal se tastează doar pe tastaturile aplicației, fără lipire și fără autofill. **Orice tastatură implicită care nu e cea AOSP** (`com.android.inputmethod.latin`), inclusiv cele preinstalate, primește un avertisment, o dată și în setări, care pomenește și dictarea.
6. **Notificări.** Un singur canal; un text constant („Ai mesaje noi”), opțional cu număr; fără expeditor, conversație sau conținut, cu telefonul blocat sau nu; ascunse implicit pe ecranul de blocare; fără insignă; fără `MessagingStyle`, răspuns direct, scurtături sau bule. Plata, accesul, actualizările și **o schimbare de cheie nedecisă** nu sunt niciodată notificări; schimbarea de cheie e un banner persistent în aplicație, cu limita de reținere.
7. **Accesibilitate WCAG.** `HoldToConfirm` are o alternativă accesibilă (o a doua confirmare explicită). Abaterea de la WCAG 2.2 3.3.8 e declarată: PIN-ul se tastează fără lipire și fără manager de parole (alternativa e biometria opțională), iar cuvintele se tastează la restaurare.

**Consecințe.** (+) Ce garantează fiecare versiune de Android e scris, iar UI-ul nu spune mai mult. (−) Pe API 29–30 tastatura poate apărea în capturi (și pe nivelurile următoare până la măsurătoarea V-U1); pe API 29–33 orice serviciu de accesibilitate citește textul și apăsările; pe API 34+ un serviciu care pretinde fals că e instrument citește și el; ștergerea necondiționată poate șterge un text copiat de altă aplicație după GHOST; un clip poate rămâne după înghețarea procesului până la următoarea deschidere; utilizatorul retastează URL-urile; rapoartele de abuz prin flag-urile ADR-13 nu există încă, deși capturile sunt blocate (pagina „Limite” o spune).

**Alternative respinse.** Ascunderea conținutului de toate serviciile, implicit (exclude utilizatorii nevăzători); foaia de partajare pentru linkuri; clipboard-ul implicit al Compose; meniul de text implicit al Compose; tastatura sistemului pentru secrete; notificări cu expeditor sau text; o notificare pentru schimbarea de cheie; o alarmă de sistem la fiecare copiere (o urmă de activitate în plus).

**Teste.** T10, T11, T24 (rândurile din INVARIANTS), G-U1 … G-U4, G-U10; mutanții PM-U1 … PM-U13, PM-U22, PM-U23, PM-U34, PM-U38, PM-U39; pașii 1–3 ai listei de dispozitive.

### ADR-55 — Blocarea aplicației, ștergerea locală, copia și restaurarea cuvintelor (blocarea strictă amânată)

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13, revizia 2) |
| Completează | ADR-08 (auto-lock și PIN de aplicație), ADR-14 (PIN-ul de constrângere rămâne P2), FR-1.4, FR-1.8, FR-7.13 |
| Modifică | designul Fazei 9 §2.5 și §13.7 (nicio blocare din Faza 13 nu închide contextul DM); designul Fazei 11 (obligațiile media de la blocare trec la `GhostApp.onContentLock()`, la fiecare ascundere și blocare); LIMITE L1 (autentificarea per deblocare are design separat) și L7-D19; ADR-20 Q6 rămâne |

**Context.** Cu chei care nu cer autentificare (ADR-20 Q6), contextul DM se redeschide din Keystore la orice pornire de proces; închiderea lui la fiecare blocare ar opri primirea și notificările în procesul pe care îl împarte cu jobul de fundal, fără să protejeze de cineva care poate folosi Keystore-ul. FR-1.8 cere o politică biometrică sau PIN configurabilă, iar LIMITE L1 numește „autentificare per deblocare”. Legarea cheilor de autentificarea dispozitivului ar opri însă rulările liniștite din fundal, singura cale a apelurilor automate către issuer (ADR-23): o plată nu și-ar mai primi token-urile, revocările și plățile referral n-ar mai rula, iar releele și issuer-ul ar vedea un client diferit.

**Decizie.**
1. Blocarea e obligatorie: un PIN de 6–16 cifre pe tastatura aplicației, biometrie opțională (utilizatorul află că biometria poate fi forțată, iar PIN-ul nu); implicit, blocare după 1 minut în fundal (alegeri: imediat, 1, 5, 30 de minute).
2. **La fiecare ascundere** modelele ecranelor își golesc starea, iar obligațiile de blocare ale Fazei 11 (cititoarele și playerele închise, previzualizările șterse, „vezi o dată” închis ca văzut) rulează prin `GhostApp.onContentLock()`. **La blocare:** perdeaua înaintea primului cadru, închiderea sesiunii deblocate, ecranele de unică folosință scoase din stivă (vizualizarea media, plata, cuvintele, dezvăluirea), clipboard-ul golit dacă e al GHOST. Contextul DM, baza de date și sincronizarea rămân pornite, deci primirea, ștergerea mesajelor expirate și notificările continuă.
3. **Blocarea strictă** (chei legate de autentificarea dispozitivului, ieșirea din proces la blocare) **nu se construiește în Faza 13.** Designul ei separat pornește de la cerințele din design §5.3: rulările liniștite, de actualizare și pașii DM și de canal din fundal; varianta cu cheia bazei nelegată; envelope-urile și aliasurile; re-cheierea bazei; fereastra de autentificare; pornirea la rece; blocarea la ascundere; invalidarea; vizibilitatea modului (Q6).
4. Verificatorul PIN e HMAC-SHA256 cu o cheie Keystore neexportabilă peste o etichetă, o sare de 16 octeți și cifre; contorul de eșecuri se scrie înaintea verificării și se resetează la deblocare; de la al cincilea eșec, așteptare exponențială până la o oră, măsurată pe `elapsedRealtime` și reluată întreagă la fiecare pornire de proces; niciun timp salvat; fără ștergere automată.
5. **Ștergerea locală**: oprirea tuturor motoarelor (DM și canale, media, actualizări, sincronizare), apoi plicurile cheilor, apoi aliasurile Keystore — punctul de distrugere criptografică, definitiv cât permite Keystore-ul telefonului (rezistența la rollback) —, apoi fișierele, apoi ieșirea din proces; o ștergere întreruptă se termină la pornirea următoare. Revocarea identității e un ecran separat (P1). Dacă o cheie Keystore nu mai poate deschide datele, aplicația arată starea și calea: reîncercare, apoi ștergere și restaurare din cuvinte.
6. Onboarding-ul pune PIN-ul și modul de confidențialitate înaintea invitației și a cuvintelor. Cele 24 de cuvinte apar doar după ce activarea e `ACTIVE`; se verifică 4 poziții aleatoare, iar o poziție greșită revine în verificarea următoare, după reafișarea cuvintelor; se oferă verificarea tuturor celor 24; pasul nu se poate sări; reafișarea cere PIN-ul tastat și deblocarea telefonului, niciodată doar biometria; cuvintele nu se copiază și nu se exportă. Restaurarea: cheia bazei, PIN-ul, modul, apoi cuvintele, doar prin `Entitlement.restore`, după ecranul „ce se întoarce și ce nu”.

**Consecințe.** (+) FR-1.8 e îndeplinit (PIN, biometrie, durată); (+) plățile, revocările și cadența de fundal rămân cele dovedite în Fazele 7–9; (+) cuvintele nu apar niciodată pe un telefon fără blocare, iar accesul de probă urmează modul ales. (−) În blocarea standard cheile DM stau în memoria nativă cât trăiește procesul (L7-D19 actualizat); (−) cine are nevoie de chei legate de fiecare deblocare nu le are încă; (−) PIN-ul nu rezistă unui atacator cu root pe telefon; (−) ștergerea e cât de definitivă permit memoria flash și Keystore-ul.

**Alternative respinse.** Modul strict în Faza 13 (revizia 1: oprea rulările liniștite); închiderea contextului DM la fiecare blocare standard; o blocare doar de interfață, fără obligațiile media; un verificator Argon2id fără Keystore; PIN-ul dispozitivului ca PIN al aplicației; un timp de reîncercare salvat în bază; revocare și ștergere într-un singur pas; cuvintele arătate în timpul activării sau înaintea PIN-ului.

**Teste.** T55, T57, CS-U1, CS-U2, CS-U7; mutanții MC-U1 … MC-U4, MC-U6, MC-U11 … MC-U18, PM-U19, PM-U20, PM-U35; pașii 4, 6 și 7 ai listei de dispozitive.

### ADR-56 — Afirmații și disclosure-uri în interfață (CP-10)

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13, revizia 2) |
| Completează | CP-10, FR-8.7, C-10, ADR-36 punctul 6, ADR-38 punctul 11, designul Fazei 14 §2.6 |
| Modifică | designul Fazei 10 §4.5 (fraza pentru canale apare fără comparația cu mesajele directe până la dovezile ADR-36) |

**Context.** `docs/STATUS.md` spune „Afirmații permise în marketing/UI: niciuna”. O interfață are totuși nevoie să spună ce nu protejează GHOST, cum se comportă o setare și care sunt obiectivele de design, fără să afirme ce nu e dovedit. Revizia 1 lăsa autorul să-și aleagă tipul frazei, așa că o afirmație putea ieși ca „funcționalitate”, fără dovezi.

**Decizie.**
1. Registrul `ghost/android/ui/claims/claims.tsv` conține fiecare frază de confidențialitate sau securitate, cu tipul ei (`LIMIT` — o limită; `FEATURE` — cum funcționează o setare; `GOAL` — un obiectiv de design; `CLAIM` — o afirmație despre ce poate sau nu poate face un adversar), dovezile, reziduul care o însoțește și sursa. **O frază care spune ce poate sau nu poate face un adversar, alt dispozitiv, un releu, rețeaua sau platforma e un `CLAIM`, oricum ar numi-o autorul**: o listă revizuită de declanșatori, în română și engleză, o prinde. Fiecare text al ecranelor de securitate, plată, media, canale și încredere are un rând.
2. Un `CLAIM` intră într-un release doar dacă toate dovezile lui sunt în lista verde `ghost/test-harness/privacy/claims-evidence.txt` (azi goală); fiecare linie a listei numește rularea CI, commit-ul, verificarea raportului și suma SHA-256 a raportului arhivat; identificatorii dovezilor sunt unici în tot proiectul. Un `GOAL` se afișează mereu cu starea lui („obiectiv de design — neverificat încă”).
3. Formulările interzise, în română și engleză, sunt cele din design §8.4. Nicio **afirmație** post-cuantică până când modelul ADR-36 a rulat și revizia externă e publicată; apoi doar fraza ADR-36, pentru mesajele directe. Limitările apar de acum, în paralel: pentru canale, criptografia clasică, fără comparație; pentru mesajele directe, ratchet-ul și autentificarea clasice și metadatele de rețea neprotejate post-cuantic; stratul X-Wing al plicurilor DM apare doar ca obiectiv, cu starea lui.
4. Trei straturi de disclosure: onboarding (trei carduri scurte), la momentul acțiunii riscante, pagini de referință („Cine vede ce” după tabelul din plan §4, cu oglinzile de actualizare, Google pe telefoanele cu servicii Google și aplicațiile cu acces la utilizare; „Limite”; „Cine poate citi ecranul”).
5. Disclosure-urile DC-1 … DC-33 ale designului (DC-26 retras) sunt obligatorii; un redactor nativ și un jurist revizuiesc textele de plată, de confidențialitate și ghidul Tor; lista de afirmații semnată (FR-8.7) e condiție de release.

**Consecințe.** (+) CP-10 devine o regulă verificată la build, iar o afirmație nu mai poate trece drept descriere. (−) Azi interfața nu spune nici măcar „criptat end-to-end” și nici „captura de ecran e blocată” până la dovezile lor (porțile Fazelor 9, 10 și 13, auditul Fazei 15); (−) lista de declanșatori cere revizie la fiecare text nou.

**Alternative respinse.** Textele revizuite „din ochi”, fără registru; tipul ales doar de autor.

**Teste.** T56, G-U8, mutanții PM-U24 și PM-U37.

### ADR-57 — Componente și permisiuni noi: notificări, camera pentru QR, zxing, legături `ghost://`

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13, revizia 2) |
| Completează | ADR-06, ADR-05, ADR-10 (setul de permisiuni T15), T15m, T16 |
| Modifică | designul Fazei 11 Q15 („CameraX în Faza 13”) și fraza despre selectorul de fotografii; designul Fazei 9 §8.4 (un card scanat e „în persoană” doar când utilizatorul spune asta); nota din `MessagingPorts.kt` despre ADR-ul permisiunii de notificare |

**Context.** Interfața are nevoie de notificări, de scanarea codurilor QR (invitații, carduri, numere de siguranță, canale) și de legături `ghost://`, fără SDK-uri terțe, fără biblioteci native noi și fără componente exportate noi. Camera nu poate deosebi telefonul unei persoane de o fotografie a codului primită prin altă aplicație.

**Decizie.**
1. `POST_NOTIFICATIONS` (deja în lista T15) se declară și se cere la sfârșitul onboarding-ului (API 33+), după ce utilizatorul vede exact textul notificării.
2. `CAMERA` (în lista T15) se declară, cu `android.hardware.camera` neobligatoriu, doar pentru scanarea codurilor QR în fereastra securizată, prin Camera2 al platformei; fără CameraX, fără aplicația de cameră a sistemului, fără ML Kit. **După scanarea unui card, aplicația întreabă unde a fost arătat codul**; doar „pe telefonul persoanei, în fața mea” îl înregistrează ca scanat în persoană (verificat); implicit e „nu știu”, adică un link neverificat.
3. `com.google.zxing:core` 3.5.4 (Apache-2.0, fără dependențe la rulare) intră în allowlist (grupul `com.google.zxing`), cu notificare și sume în `verification-metadata.xml`. Suma de control afișată pentru un link (8 caractere) arată doar că linkul nu e deteriorat, nu cine l-a trimis.
4. Activitatea de lansare primește filtre `VIEW` pentru schema `ghost` cu gazdele `invite`, `contact` și `channel`; fără `http` sau `https`, fără `autoVerify`; cu `launchMode="singleTask"` și `persistableMode="persistNever"`, ca sistemul să nu păstreze linkul în înregistrările task-urilor; după citire, activitatea se relansează într-un task curat; legăturile sunt intrări neîncrezute.
5. `USE_BIOMETRIC` (în lista T15) pentru deblocare, prin `BiometricPrompt` al platformei; fără `androidx.biometric`.
6. Selectorul de fotografii e al platformei, unde există; altfel `ACTION_OPEN_DOCUMENT`, direct, niciodată varianta de rezervă pe care o implementează serviciile Google Play.
7. Dependențe doar pentru teste: Robolectric 4.17 (MIT), AndroidX Test (doar în modulul de test `:app-uitest`), Accessibility Test Framework 4.1.1; absente din graful release (G-U7).

**Consecințe.** (+) Nicio bibliotecă nativă nouă și nicio componentă exportată nouă; (+) un cod QR primit ca fotografie nu mai devine „verificat”. (−) Cod propriu pentru previzualizarea camerei; (−) o întrebare în plus după scanarea unui card; (−) o altă aplicație poate revendica schema `ghost://` și intercepta un link deschis din afara GHOST (reziduu L11-U13; QR-ul în persoană rămâne calea recomandată).

**Alternative respinse.** CameraX (bibliotecă nativă nouă), ML Kit (Google Play services), zxing-cpp (nativ), intentul camerei sistemului (o aplicație terță vede imaginea); foaia de partajare; `androidx.biometric` (cere `FragmentActivity`); contractul `PickVisualMedia` de la AndroidX așa cum e (poate ajunge la serviciile Google Play); orice scanare înregistrată automat ca „în persoană”.

**Teste.** G-U2, G-U7, G-U10, G-U11, T15m, T16; testul de proveniență; verificările V-U8, V-U31, V-U34.

---

## Appendix B: Text changes in other documents (applied in S12, except B.6's STATUS row)

### B.1 Master plan and LIMITE errata (Romanian)

- **Plan §6.2, rândul 13:** durata „4–6 s” devine „implementare ≈ 45–70 de zile-agent (până la «implementat și testat local»); data porții o dau acțiunile proprietarului și fațadele Fazelor 10, 11 și 14 (design `docs/design/faza13-ux.md` §14.2, Q26)”; la „Depinde de” se adaugă „(în fapt și fațadele Fazei 8 și ale Fazei 14 pentru actualizare)”; poarta rămâne, cu nota „T53–T57 verzi (Q36)”.
- **Plan §6.6 (Anexa B revizuită):** se adaugă `ui/ # Compose: ecrane, sistem de design, componente de protecție (Faza 13, ADR-53)`; `app/` devine `# rădăcina de compoziție, DI, adaptoare, navigarea e în ui/`.
- **Plan §5:** notă: „Numerotarea FR din acest tabel e decalată față de spec: FR-1.5 (payload-ul invitației) e FR-1.6 în spec, FR-1.6 (eligibilitatea) e FR-1.7, FR-6.8 (avertismentul KYC) e FR-6.9 (spec p.8, p.10; design Faza 13 F-U1).”
- **LIMITE L1, rândul „Prevenire” cu Keystore:** „(FR-1.7)” devine „(FR-1.8)”; se adaugă „autentificarea per deblocare (blocarea strictă) cere un design separat: legarea cheilor ar opri rulările liniștite, rulările de actualizare și pașii DM și de canal din fundal (design Faza 13 §5.3, Q6); implicit cheile nu cer autentificare (ADR-20 Q6)”.
- **LIMITE L1.1** (ce păstrează sistemul): se adaugă „evenimentele de utilizare (deschiderea, trecerea în fundal, notificările, cu canalul ascuns) și istoricul permisiunii camerei, citite de aplicațiile cu acces la utilizare și la o examinare a telefonului (design Faza 13 C16, L11-U17)”.
- **LIMITE L7-D17:** atenuarea „notificare persistentă în Faza 13” devine „banner persistent în aplicație, cu limita de reținere; nu o notificare de sistem, care ar spune aplicațiilor ce ascultă notificările că s-a schimbat o cheie (T11; design Faza 13 X-U17, Q52)”.
- **LIMITE L7-D19:** „blocarea și wipe-ul nu au încă apelant” devine „nicio blocare din Faza 13 nu închide contextul: cheile rămân în memoria nativă cât trăiește procesul, iar starea ecranelor se golește la fiecare ascundere; wipe-ul le șterge (ADR-55); blocarea strictă are design separat (Faza 13 Q6)”.
- **LIMITE, rândurile care numesc „rotația cardului (Faza 13)”:** devin „rotația cardului (design separat, Faza 13 Q19)”.

### B.2 `ghost/test-harness/privacy/INVARIANTS.md` (rânduri noi și modificate)

| ID | Invariant | Verificare | Executabil din | Cod |
|---|---|---|---|---|
| T53 | Doar acțiunile utilizatorului din lista închisă (design Faza 13 §2.4) produc trafic către relee, issuer sau mirror-uri, iar nicio sesiune de prim-plan nu pornește înaintea deblocării; nicio altă acțiune sau stare a interfeței (deschiderea unui ecran, ecranul de blocare, derularea, afișarea, notificările, citirile de stare) nu schimbă programul de citire, momentele sesiunilor sau ce se trimite, în afara întârzierii limitate pe care citirile interfeței o adaugă unui pas programat al actorului DM | G-U5; suita porților înregistratoare (fiecare intenție a fiecărui model de ecran, contra fațadelor înregistratoare; niciun apel care produce trafic în afara intențiilor); testul deschiderii fără deblocare; gemenii NI-UI1 (lumea de confidențialitate DM cu un șofer de interfață care citește fiecare metodă de fațadă la rata maximă permisă, față de niciuna: vederi de releu identice, înregistrări în același minut), NI-UI2 (o conversație deschisă și afișată față de nu), NI-UI3 (instrucțiunile de plată citite față de nu, pe o lume care modelează reținerea de plată), NI-UI4 și NI-UI5 (lumile Fazelor 10 și 11); RT-UI1 (ceas real, pe firul actorului DM) | Faza 13 (JVM) | `android/ui`, `android/app` (`org.ghost.app.ui`), lumile DM, T2, canale și media |
| T54 | Interfața nu păstrează nimic sensibil în afara SQLCipher și a memoriei: pachetul de stare salvată e gol; nicio preferință, DataStore sau fișier, în afara fișierului tranzitoriu de crash (criptat, fără timp, declarat); nicio valoare sensibilă într-un `toString`; niciun link în task-ul pe care îl păstrează sistemul | G-U6; G-U11 (`persistNever`, `singleTask`); scanarea canarilor în pachetul fiecărui ecran; testul de reflecție pe `toString`; inventarul sandbox-ului și scanarea `recent_tasks` după o lansare dintr-un link, pe emulator | Faza 13 | `android/ui`, `android/app` |
| T55 | Cât aplicația e blocată nu se compune niciun ecran cu conținut; decizia de blocare precede primul cadru după revenire; un proces nou pornește blocat; la fiecare ascundere modelele ecranelor nu mai țin conținut și obligațiile de blocare (inclusiv cele media ale Fazei 11) au rulat | testele JVM ale mașinii de stări, ale cadrelor și ale ascunderii, pe ceas virtual; emulator (`uiautomator dump`; nicio resursă media deschisă după ascundere) | Faza 13 | `android/ui`, `android/app` |
| T56 | Nicio frază care spune un efect (ce poate sau nu poate face un adversar, alt dispozitiv, un releu, rețeaua sau platforma) nu ajunge într-un release decât ca afirmație (`CLAIM`) cu toate dovezile în lista verde; fiecare obiectiv (`GOAL`) apare cu starea lui; fiecare text al ecranelor sensibile e înregistrat; identificatorii dovezilor sunt unici, iar fiecare linie a listei verzi numește rularea, commit-ul și suma raportului arhivat; nicio formulare interzisă, în română sau engleză | G-U8 cu fixture-uri; testul JVM care citește toate resursele și registrul | Faza 13 | `android/ui/claims/`, `scripts/gates/ui-claims.sh` |
| T57 | După ștergere: niciun plic de cheie, niciun alias Keystore GHOST, nicio bază de date sau WAL, niciun fișier în `no_backup`, `files` sau `cache`, niciun job sau alarmă programată, nicio notificare; o ștergere întreruptă se termină la pornirea următoare | enumerarea crash-urilor peste pașii W2–W7 (JVM); inventarul `run-as` și `dumpsys jobscheduler`, `alarm`, `notification` pe emulator; dispozitiv | Faza 13 | `android/app` |

Rânduri modificate (text adăugat la coloana „Verificare”):
- **T10:** „Faza 13 (ADR-54): fiecare fereastră a pachetului (activitate, dialog, meniu, foaie, player Compose) e securizată de la primul cadru (G-U1); pe emulator, API 29, 33, 35, 36 și 37: `dumpsys window` arată `SECURE` pe fiecare fereastră a fiecărui ecran scriptat; captura ADB e refuzată sau neagră, după cum măsoară V-U1 pe fiecare nivel; tastatura e capturată explicit; instantaneul din recents e un înlocuitor (nu „absent”), fiecare verificare cu un control nesecurizat; aceleași verificări, din exterior, pe APK-ul release micșorat de R8; pașii de dispozitiv. Regula ferestrelor media a Fazei 11 (X-M11) e inclusă.”
- **T11:** „blocat sau nu (Faza 9 Q19); un text constant și, opțional, numărul; ascunsă implicit pe ecranul de blocare; fără insignă; nicio notificare pentru o schimbare de cheie (banner în aplicație); scanarea canarilor în `dumpsys notification --noredact` și pasul istoricului notificărilor pe dispozitiv.”
- **T24:** „Fișierul aprobat e `SensitiveClipboard.kt`, plus rădăcina care îl folosește drept clipboard-ul Compose; ștergerea verifică proprietatea cu focus și e necondiționată fără focus, în 30 s cât procesul rulează și la următoarea deschidere altfel (eticheta clipului păstrată); meniul de text nu are acțiuni `PROCESS_TEXT`; marcarea de accesibilitate pe decor și pe frunze; secretele nu au câmp cu tastatura sistemului; pe emulator, API 34+: zero canari printr-un client care nu e instrument, canari prezenți prin unul care e; cazul procesului înghețat.”
- **T3:** canarii includ aliasurile, textul mesajelor și al postărilor, cuvintele și parolele, PIN-ul, adresele de plată și conținutul linkurilor; scanarea include logcat-ul fiecărei suite de emulator, `dumpsys dropbox --print`, rapoartele de crash și pachetele de stare; un canar pus în mesajul unei excepții nu apare nicăieri.
- **T4:** „executat pe emulator în Faza 13 (felia S10), pe ambele căi: copia în cloud prin transportul local (unde `allowBackup="false"` e respectat) și transferul între dispozitive (`is_device_transfer=true`), unde `allowBackup` e ignorat pentru aplicațiile cu target ≥ 31, deci la target 37 protejează doar excluderile `<device-transfer>`; fiecare cu un APK de control cu reguli relaxate, al cărui fișier-canar trebuie să apară; API 29–30 separat”, cu rezultatul.
- **T6 (dinamic):** „executat pe emulator în Faza 13 (felia S10), cu pachetele atribuite UID-ului GHOST, o aplicație de control care rezolvă un nume și trebuie văzută, o captură geamănă (călătorii vs repaus), Tor inaccesibil și o rulare de actualizare: zero pachete în afara Tor și zero interogări DNS de la UID-ul GHOST”, cu rezultatul.
- **T20 (inventarul):** „executat pe emulator în Faza 13 (felia S10), după o sesiune și după o ștergere, față de linia de bază a unei instalări noi (V-U18)”, cu rezultatul.
- **T25:** „definiția «afișat» din design Faza 13 §3.5 pornește numărătoarea destinatarului.”
- **T33:** „notificări cu text constant” devine „notificări cu text constant, opțional cu numărul de mesaje necitite (Faza 13 Q7)”; „`ui_lock` și `ui_settings` nu țin niciun timp”.

### B.3 `docs/THREAT_MODEL_v2.1.md` (română)

- **§7, scenariu nou S14. Aplicații de pe telefon care citesc ecranul, tastatura, clipboard-ul sau notificările.** Obține: ce afișează GHOST, dacă protecțiile nu se aplică. Mitigări: FLAG_SECURE pe fiecare fereastră, marcarea de accesibilitate (API 34+), avertismentul înaintea secretelor, clipboard sensibil cu ștergere la 30 s, secrete doar pe tastaturile aplicației, meniul de text fără acțiuni `PROCESS_TEXT`, notificări cu text constant (ADR-27, ADR-54). **Rezidual:** API 29–33 pentru accesibilitate (inclusiv apăsările pe tastaturile aplicației), API 29–30 pentru tastatură în capturi (până la V-U1), serviciile care mint că sunt instrumente, instrumentele de sistem, cameră sau alt dispozitiv, root. **Test:** T10, T11, T24.
- **§7, scenariu nou S15. O aplicație sau o pagină web deschide GHOST la un moment ales.** Obține: dacă utilizatorul deblochează, momentul sesiunii; colaborând cu un releu, legătura dintre dispozitiv sau browser și namespace-urile clientului. Mitigări: sesiunea pornește doar la deblocare; după o deschidere cu link, încă U[0, 2 min] (ADR-53). **Rezidual:** momentul deblocării (L11-U18). **Test:** T53.
- **§6, rând nou „Interfața (Faza 13)”:** releele văd prezența (aplicația deblocată) și acțiunile din lista închisă; nimic din navigare, afișare, ecranul de blocare sau notificări; un atacator cu baza deschisă (AD-8) vede setările (modul ridicat, durata blocării, contorul de eșecuri ale PIN-ului); sistemul păstrează propriile evidențe de utilizare (L11-U17).

### B.4 `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`: secțiunea nouă L11 (reziduurile interfeței, Faza 13)

| ID | Reziduu | De ce rămâne | Atenuare |
|---|---|---|---|
| L11-U1 | Ecranul poate fi fotografiat cu alt dispozitiv; un client modificat sau un telefon cu root anulează FLAG_SECURE; funcțiile de captură ale unor producători nu sunt testate | aplicația rulează pe sistemul utilizatorului | lista de dispozitive testate; timere scurte |
| L11-U2 | Pe Android 10–11 (API 29–30) tastatura poate apărea în capturi; pe nivelurile următoare, până la măsurătoarea V-U1 | platforma nu securizează fereastra IME înainte de API 31 (după sursele AOSP, nemăsurat încă) | secretele pe tastaturile aplicației |
| L11-U3 | Pe API 29–33 orice serviciu de accesibilitate citește textul; pe 34+ un serviciu care pretinde fals că e instrument, iar pe un telefon fără servicii Google nimic nu verifică declarația; instrumentele de sistem (din Android 16 QPR2, după sursele AOSP) pot captura ferestre securizate; funcții ale cititoarelor de ecran care trimit capturi în cloud la cererea utilizatorului | `isAccessibilityTool` e declarat de serviciu | ecranul „Cine poate citi ecranul”; opțiunea de ascundere |
| L11-U4 | Clipboard-ul: 30 s de expunere cât procesul rulează; dacă procesul e înghețat sau oprit, clipul rămâne până la următoarea deschidere a GHOST sau până la ștergerea sistemului (~1 h pe Android 13+), iar pe Android 10–12 până e înlocuit; istoricul de clipboard al tastaturilor; ștergerea necondiționată poate șterge textul altei aplicații | Android permite citirea clipboard-ului doar aplicației cu focus și îngheață procesele din cache | doar date care nu sunt conținut; eticheta clipului păstrată; secretele nu se copiază |
| L11-U5 | O tastatură terță sau preinstalată vede tot ce scrii în câmpul de compunere, inclusiv prin dictare | câmpul de compunere folosește tastatura sistemului (ADR-27 punctul 3) | flagul fără învățare (doar o recomandare); avertisment pentru orice tastatură în afară de cea AOSP |
| L11-U6 | Aplicațiile care ascultă notificările (ceasuri, automatizări) văd textul constant și momentul lui, care e momentul decriptării unui mesaj; istoricul notificărilor (24 h, dacă e activ); evidențele de utilizare ale sistemului (L11-U17) | notificarea există | text constant; ascunsă pe ecranul de blocare; opțiunea „fără notificări” |
| L11-U7 | Textul decriptat din ecrane (șiruri JVM) nu se poate șterge; după ascundere și blocare devine eligibil pentru GC | limbajul | starea ecranelor se golește la fiecare ascundere |
| L11-U8 | PIN-ul aplicației oprește pe cineva care ține telefonul deblocat, nu un atacator cu root (încearcă PIN-uri cu cheia Keystore de pe telefon); contorul de eșecuri e un artefact; cheile nu sunt legate de fiecare deblocare (blocarea strictă are design separat) | HMAC-ul cu Keystore e un oracol pe dispozitiv | PIN de până la 16 cifre; așteptarea care nu se poate ocoli; designul separat al blocării stricte |
| L11-U9 | Blocarea standard: contextul DM, cheile lui și ciornele rămân în memoria procesului cât acesta trăiește, și în fundal | primirea în fundal are nevoie de ele | starea ecranelor se golește la ascundere; ștergerea datelor |
| L11-U10 | Setările (modul ridicat, durata blocării, opțiunile de notificare) și contorul de eșecuri ale PIN-ului sunt vizibile unui atacator cu baza deschisă | trebuie citite de procesele de fundal | — |
| L11-U11 | După ștergere rămân: istoricul de joburi și alarme al sistemului, istoricul notificărilor (dacă e activ), înregistrarea canalului de notificare, evidențele de utilizare, blocuri de flash sub sistemul de fișiere, copiile de pe relee până la TTL, copiile contactelor | în afara aplicației | ștergerea criptografică înaintea fișierelor |
| L11-U12 | Deblocarea aplicației pornește sesiunea de prim-plan, deci releele văd când aplicația e folosită | sincronizarea urmează folosirea | nimic la ecranul de blocare (LIMITE L2.1 punctul 4) |
| L11-U13 | O altă aplicație poate revendica schema `ghost://` și intercepta sau înlocui un link deschis din afara GHOST; până la relansarea curată, sistemul ține linkul în memoria task-ului | schemele nu se pot verifica | QR în persoană; numărul de siguranță pentru carduri, amprenta pentru canale (suma de control arată doar deteriorarea) |
| L11-U14 | Raportul de crash stă criptat într-un fișier tranzitoriu, fără timp, până la pornirea următoare | handler-ul nu poate scrie sigur în baza de date | fără mesaje, fire sau căi în raport |
| L11-U15 | Fără copiere din mesaje, utilizatorul retastează URL-urile și adresele (risc de greșeală) | ADR-27 punctul 3 | — |
| L11-U16 | Selectorul de fotografii al sistemului și DocumentsUI pot păstra istoricul selecțiilor | scris de sistem | Faza 11 L9-M15 |
| L11-U17 | Sistemul păstrează evenimente de utilizare (deschiderea, trecerea în fundal, notificările, cu canalul ascuns), istoricul permisiunii camerei (fiecare scanare QR) și intrările de crash; le citesc aplicațiile cu acces la utilizare și o examinare a telefonului | le scrie sistemul | notificări opționale; DC-30 |
| L11-U18 | O aplicație sau o pagină web poate deschide GHOST la un moment ales; dacă utilizatorul deblochează atunci, sesiunea pornește la câteva secunde sau minute după, iar un releu care colaborează poate lega momentul de dispozitiv sau de browser | Android lasă orice aplicație să pornească activitatea de lansare | sesiunea doar la deblocare; încă U[0, 2 min] după o deschidere cu link |
| L11-U19 | Înghețarea proceselor din cache (Android 14+) oprește temporizatoarele GHOST în fundal; ștergerea clipboard-ului și alți pași locali întârzie până rulează din nou | decizia sistemului | eticheta clipului păstrată; ștergerea la următoarea deschidere |
| L11-U20 | Pe API 29–33 apăsările pe tastaturile aplicației ajung la orice serviciu de accesibilitate activ; pe API 34+ la un serviciu care pretinde fals că e instrument; evenimentele de fereastră pot spune unui serviciu care nu e instrument când GHOST e în față | platforma nu impune nimic sub API 34 | avertismentul înaintea secretelor; opțiunea de ascundere |
| L11-U21 | Ștergerea unei chei din Keystore e definitivă doar dacă Keystore-ul telefonului are rezistență la rollback; ștergerea unui fișier nu îl suprascrie pe flash | hardware-ul și sistemul de fișiere | distrugerea criptografică prin aliasuri; V-U29 citește proprietatea pe telefoanele testate |
| L11-U22 | Deblocarea biometrică poate fi forțată (amprenta, fața) | biometria nu e un secret | PIN-ul rămâne; reafișarea cuvintelor cere PIN-ul tastat |
| L11-U23 | Un crash nativ în procesul principal lasă un tombstone scris de sistem, care poate conține memorie din jurul erorii | scris de sistem | fără mesajul excepției în jurnale (handler-ul nu predă excepția) |

### B.5 Other designs (English forward notes)

- **F9 §2.5, §13.7:** "Phase 13 (ADR-55, X-U1): no Phase 13 lock closes the DM context; `ctxClose` runs at wipe; the strict lock is deferred to its own design (Phase 13 Q6, §5.3)." **F9 §8.4:** "Phase 13 records `QR_IN_PERSON` only after the user says the code was on the person's own phone in front of them (X-U16); T35's PQ-R8 listing reads that answer (F-U15)." **F9 §22.36 item 9(g):** "Phase 13 fixes the order (ACTIVATE inside the running foreground session) and measures it (BV-2, BV-3; Q54)." **F9 §15.10 step 7:** "a gate-variant restore command (Phase 13 Q51)."
- **F10 §4.5:** the channel sentence loses its comparison clause until ADR-36's evidence (X-U11). **F10 §10.3:** coordination items F-U8 and F-U10 (`inspectInvite(link)`). **F10 Q49's copy:** the fingerprint is compared with its epoch. **F10 `mls_state_key` (`faza10-forum.md:1021`):** "held in native memory while unlocked" reads, after Phase 13's X-U1, "while the process lives": no Phase 13 lock closes the context that holds it.
- **F11 §6.5, §8 (`faza11-media.md:978`):** "the lock duties run through `GhostApp.onContentLock()` at every hide and every lock (Phase 13 X-U15)"; the pause switch needs a method and persisted state (F-U9); the picker sentence at `faza11-media.md:472` (F-U17); Q15, Q30, G-M2 as before (the camera serves QR only through Camera2; no upload service in Phase 13; G-M2 admits `media3-ui-compose`).
- **F14 §0.4, §1.3, F-D8:** consumed by §6.7; release notes need a format field or are withdrawn (F-U11); the dynamic T6 test includes an update run (F14 §10.2); Q16 (no silent updates) unchanged.
- **F7 §5.4, F8 §8.3, `SyncWiring.kt:18-21`:** "the foreground starts at unlock, not at visibility (Phase 13 X-U14, D33)."

### B.6 STATUS and the ADR index

- **`docs/STATUS.md`** (aplicat în commit-ul acestei revizii, după regula fișierului „se modifică în același commit cu orice schimbare de fază”, FE-18): rândul nou „Faza 13 (UX de producție)” — design propus, neaprobat, revizia 2; blocarea strictă amânată (Q6); sesiunea pornită la deblocare; estimarea în zile-agent; 54 de întrebări și 11 acțiuni ale proprietarului; niciun cod; emulatorul încă nerulat pe vreun runner — iar „Faze 12, 13, 15–18” devine „Faze 12, 15–18”. La închiderea fazei, rândul spune ce a rulat și unde.
- **`docs/adr/README.md`:** secțiunea „Propuse (Faza 13)” cu ADR-53 … ADR-57 (S12).

---

## Appendix C: Evidence, verified vs assumed

### C.1 Verified in the repository (at `8a480a7`, whose code is identical to `197b2b4`; read 2026-10-03)

| Fact | Where |
|---|---|
| Plan row 13, its gate, effort and dependencies; the plan's team | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md:317, 341` |
| The only `FLAG_SECURE` today; no other window code | `ghost/android/app/src/main/kotlin/org/ghost/app/MainActivity.kt:31` |
| No production caller of `onLock`, `onUnlock`, `onWipe`, `onDatabaseKeyCreated`, `setNotificationPort`, `markDisplayed`, `requestExpedite` (only tests and comments) | grep over `android/*/src/main` and `app/src` |
| `AUTH_BOUND = false`; background opening refused for bound keys, and refused before the cached handle is returned; only `UserNotAuthenticatedException` caught | `AppDatabase.kt:16, 22-23, 40-51` |
| A job returns while the foreground is wanted; a job opens the database for BACKGROUND before it starts a quiet run; foreground sessions are never quiet; a user issuer call needs the foreground wanted | `SyncRuntime.kt:95-99, 108-113, 465-490, 776-804` |
| The Keystore wrapper's authentication parameters (30 s, biometric or device credential); no rollback-resistance request | `AndroidKeystoreWrapper.kt:44-75` |
| Fixed aliases and envelope names | `KeystoreKeyWrappers.kt:161, 182`; `DatabaseKeyProvider.kt:17-24, 30`; `IdentityManager.kt:103` |
| The backup challenge and its check | `IdentityManager.kt:80, 88` |
| The BIP-39 encoder builds a `String` of bits | `Bip39.kt:29-36,43-56` |
| The DM facade lacks `setListener` and names; `MessageView` fields | `Messaging.kt:11-27,78,375-398` |
| `NotificationPort` carries only an `Int` | `MessagingPorts.kt:35-38` |
| `locked` starts false; `onLock` posts the close; `onWipe` waits for the pass | `MessagingWiring.kt:162-163,347-374` |
| Facade calls wait on a future without a timeout; `IllegalStateException` after retire | `DmActor.kt:194-216` |
| `paymentInstructions` checks only the invoice and the disclosures and marks the purchase shown; the U[1 h, 6 h] delay is only in the status predicate | `EntitlementEngine.kt:200-206, 230-251` |
| A pending trial retries at every foreground | `EntitlementEngine.kt:142-145` |
| The trial's slot is drawn in the mode current at finalization, read from the in-memory runtime mode | `TrialSteps.kt:204`; `Slots.kt:30-35`; `GhostApp.kt:48` |
| The entitlement engine unwraps the root for invite keys and drop opening | `IdentityAdapters.kt:26-50` |
| `QR_IN_PERSON` maps to `VERIFIED` | `ContactSteps.kt:441-445` |
| Transport states, status flags; controller methods; the privacy-mode default | `SyncStatus.kt:4-28`; `SyncController.kt:10,12,44,50,56,68`; `sync/api/Types.kt:103-104`; `SyncRuntime.kt:191` |
| The payment-hold read at process start, opening the database for the foreground | `SyncWiring.kt:34-39`; `GhostApp.kt:136` |
| The visibility hooks: the DM stack build, the trial retry, the payment moment at hide | `GhostApp.kt:138-142, 154-158`; `MessagingWiring.kt:202-204`; `EntitlementWiring.kt:84-92` |
| Schema version 5; `name_env`; `*_minute` columns are Unix seconds; `dm_self`'s wrapped keys | `Schema.kt:105-108, 120, 898-905, 936` |
| T15's permissions; anti-placeholder's words; the dependency lists; G-DM1's coroutine ban; G-DM5's build-type-twin rule | `scripts/gates/common.sh:15`; `anti-placeholder.sh:6-20`; `dependency-allowlist.txt`, `dependency-denylist.txt`; `messaging-no-network.sh:21-24`; `apk-no-debug-hooks.sh` (header) |
| Toolchain pins; `compileSdk` and `targetSdk` 37, `minSdk` 29 | `libs.versions.toml:4-12` |
| `:app`'s instrumentation runner is `AppDeviceRunner`; `:app`'s JVM tests already share `storage/src/testShared` | `app/build.gradle.kts:23, 102` |
| The emulator's loopback delivery lives in `:messaging`'s androidTest; the controller hard-wires the Tor transport | `messaging/src/androidTest/kotlin/org/ghost/messaging/device/DeviceWorld.kt:41-56`; `AndroidSyncController.kt:116-120` |
| The release APK already ships coroutines 1.9.0, `navigationevent` 1.0.0, `savedstate-compose` 1.4.0, `runtime-retain` 1.12.1, `autofill` 1.0.0, `window` 1.5.0; not `lifecycle-viewmodel-compose`, any navigation library or `material3-adaptive` | `ghost/licenses/THIRD_PARTY_NOTICES-android.txt` |
| The manifest's permissions and launcher (no `launchMode`, no `persistableMode`), `allowBackup="false"`, the removed emoji2 initializer; both backup rule files exclude every domain | `app/src/main/AndroidManifest.xml`; `app/src/main/res/xml/backup_rules.xml`, `data_extraction_rules.xml` |
| Phase 10's facade, password decisions, Q4, Q7, Q14, Q15, Q35, Q42–Q50; the channel PQ sentence; the partition flag; open-channel invite links kept; the fingerprint with its epoch; `mls_state_key`; the captured member's reveal | `docs/design/faza10-forum.md:365, 673, 912, 975-1000, 993, 1021, 1391-1456, 1582, 1900-2021` |
| Phase 11's facade, view-once and media rules, Q15, Q30; the pause switch in prose; the lock duties on `onLock`; the picker sentence | `docs/design/faza11-media.md:470-531, 472, 548, 686, 719, 738, 978, 1339, 1354` |
| Phase 14 revision 2: update runs, `Updates`, the removed signer fingerprint, `manifestIssuedDay`, the release record's fields, the store flavor, the Play Protect and developer-verification facts, F-D8, the dynamic T6, `NI-U1 … NI-U5` | `docs/design/faza14-distribution.md:16, 64, 266, 397, 631-639, 715-739, 816-844, 933, 965-969, 1324` |
| Phase 9's world limits (virtual time, the facade unattached to the actor, no entitlement participant or payment hold, no HIGH mode, no process death) and the unmeasured ACTIVATE order | `docs/design/faza9-dm.md:4515-4525` (§22.36 items 2 and 9) |
| Phase 8: automatic issuer calls only in quiet runs; `PAYMENT_READY`'s surfacing; `BlindSign` attempts; revocation never in the foreground | `docs/design/faza8-issuer.md:36, 749-760, 1790-1800, 2380-2392` |
| `static-gates` red on `197b2b4`: 706 "self-test ok", 1 failure (`dm-golden-lock` on an unreadable base) | `gh run view 36434212692` (2026-10-03) |
| Every `dm-emulator` run since 2026-09-28 (six scheduled, four on a pull request) failed; the latest at its KVM step ("API 29 not run: /dev/kvm is missing or not writable by runner"); `dm-privacy-gate` queued 8 h 39 min on 2026-10-03 | `gh run list --workflow dm-emulator.yml`; `gh run view 37108821939`; `gh run list` (2026-10-03) |
| The runner user is in `runner` and `docker` only; `/dev/kvm` is `root:kvm 0660`; nested virtualization on | `wsl -d ghost-runner` read-only (2026-10-03) |
| FR numbering and the texts of FR-1.4 … FR-1.9, FR-4.x, FR-6.9, FR-7.x, FR-8.x, NFR-10, §13, roadmap row 13, DoD, R-01, C-10 | spec PDF pages 6–13, 21–25, 28 via `pdftotext -table` |

### C.2 Verified at external sources (accessed 2026-10-03)

| Fact | Source |
|---|---|
| Navigation 3: 1.2.0 stable 2026-09-23, 1.0.0 stable 2025-11-19; 1.2.0 depends on `navigationevent` 1.1.1, `savedstate-compose` 1.4.0, `kotlinx-serialization-core` 1.7.3 | developer.android.com releases page; dl.google.com POMs |
| BOM 2026.09.00 → `ui`, `foundation`, `ui-test-junit4` 1.12.1, `material3` 1.4.0 | developer.android.com BOM mapping |
| `View.setAccessibilityDataSensitive` since API 34, limiting interaction to `isAccessibilityTool` services | Microsoft Learn mirror of the AOSP javadoc |
| `AccessibilityServiceInfo.isAccessibilityTool()` since API 31 | Microsoft Learn |
| Compose `isSensitiveData`, its semantics | AndroidX `SemanticsProperties.kt` (androidx-main); listed in the Compose UI 1.9.0-rc01 API reference (composables.com) |
| The December 2025 Android security post (the snippet names `sensitiveData`; the source names `isSensitiveData`) | developer.android.com blog, 2025-12-11 |
| `setRecentsScreenshotEnabled` since API 33, Overview only | Microsoft Learn |
| `EXTRA_IS_SENSITIVE`, the string key below API 33, Android 13's visual confirmation | developer.android.com copy and paste |
| Android 10 clipboard access limited to the focused app and the default IME | developer.android.com Android 10 privacy changes |
| Android 12: untrusted overlay touches blocked (0.8), a toast on clipboard reads, `getPrimaryClipDescription` without a toast | developer.android.com behaviour changes 12 |
| Android 13 clears the clipboard automatically; Android 12's paste toast; the sensitive flag hides keyboard previews | developer.android.com secure clipboard handling |
| Android 15 hides notification content and sensitive fields during screen sharing; `setPublicVersion` | developer.android.com behaviour changes 15 (all apps) |
| Android 17: `setContentCaptureEnabled(false)` ignored for apps targeting 37, use `FLAG_SECURE`; no large-screen opt-out | developer.android.com behaviour changes 17 (updated 2026-10-01) |
| **The cached-apps freezer:** cached processes frozen 10 s after entering the cached state (Android 14+), all threads suspended, repetitive tasks suspended; a lifecycle event, a job or a manifest broadcast unfreezes; supported from Android 11; on by default on Pixel and some Samsung devices (secondary, search summary) | source.android.com/docs/core/perf/cached-apps-freezer |
| **Rollback resistance:** without it, a deleted key "could potentially" be restored by an attacker who earlier retrieved the key material | source.android.com, Keystore implementer reference |
| Keys requiring authentication: authorized "by authenticating to the device using a secure lock-screen credential … or biometric authentication"; a duration or per-use; irreversibly invalidated when the secure lock screen is disabled; `setUnlockedDeviceRequired` bugs on 12–14 | Microsoft Learn (KeyGenParameterSpec.Builder: `setUserAuthenticationRequired`, `setUserAuthenticationParameters`, `setUnlockedDeviceRequired`) |
| `DEVICE_CREDENTIAL` combinations unsupported on API ≤ 29; no `CryptoObject` with a credential fallback | developer.android.com biometric authentication |
| **`persistableMode`:** `persistRootOnly` is the default and keeps "the root activity's launching intent" across restarts; `persistNever` keeps nothing; `singleTask` routes a new intent to `onNewIntent` | developer.android.com `<activity>` element |
| **AOSP task persistence:** `Task.saveToXml` writes the base intent (`Intent.saveToXml` writes `mData.toString()`), `last_time_moved` and the calling package; `TaskPersister` writes `recent_tasks/<id>_task.xml` under `/data/system_ce`; `ActivityRecord.isPersistable` is false for `persistNever` | AOSP `frameworks/base` (`Task.java:3931-3996`, `TaskPersister.java:70-71, 527`, `ActivityRecord.java:3181-3185`, `Intent.java:12826-12831`), the privacy review's fetched copies, re-read |
| **Package visibility:** "You can start another app's activity using either an implicit or explicit intent regardless of whether that app is visible to your app" | developer.android.com training/package-visibility/automatic |
| **`getLaunchedFromPackage`** (API 34) returns the launching app only if it opted in (`setShareIdentityEnabled`), has the same uid, or is platform-signed | Microsoft Learn (Activity.LaunchedFromPackage) |
| **Usage events:** `ACTIVITY_RESUMED`, `ACTIVITY_PAUSED`, `ACTIVITY_STOPPED` per activity; `NOTIFICATION_INTERRUPTION` events with the channel id obfuscated for callers without `MANAGE_NOTIFICATIONS` | Microsoft Learn (UsageEventType); AOSP `UsageEvents.java:206, 751`, `UsageStatsService.java:757-767`, re-read |
| **Backup eligibility:** the cloud destination returns `allowBackup`; `IGNORE_ALLOW_BACKUP_IN_D2D` (enabled since S) ignores `allowBackup` for device-to-device transfers of apps targeting 31+ | AOSP `services/backup/.../BackupEligibilityRules.java` (fetched) |
| **LocalTransport parameters:** `is_device_transfer`, `fake_encryption_flag`, `non_incremental_only`, `is_encrypted`, `log_agent_results`, `no_restricted_mode_packages`, from `Settings.Secure` `backup_local_transport_parameters` | AOSP `packages/LocalTransport/.../LocalTransportParameters.java` (fetched) |
| **Compose text menu:** `ProcessTextKey` for items of `PROCESS_TEXT` activities; `Modifier.addTextContextMenuComponents` and `filterTextContextMenuComponents` (Compose Foundation 1.9) | developer.android.com compose-foundation release notes and reference (search summary); whether the menu shows them by default in 1.12.1 is V-U26 |
| **Photo picker contract:** `PickVisualMedia` prefers `MediaStore.ACTION_PICK_IMAGES`, then a system app's `ACTION_SYSTEM_FALLBACK_PICK_IMAGES` (since Activity 1.10 the public action replaces the direct Google Play services delegation), then `ACTION_OPEN_DOCUMENT` | developer.android.com activity release notes and the `PickVisualMedia` reference (search summary) |
| `dataSync` and `mediaProcessing` foreground services: 6 h per 24 h on Android 15+ | developer.android.com FGS timeout |
| Per-app language: Android 13; `generateLocaleConfig` (AGP 8.1); AppCompat's back-port needs `AppCompatActivity` | developer.android.com app languages |
| Compose accessibility checks: `ui-test-junit4-accessibility`, Compose 1.8.0, `enableAccessibilityChecks()` | developer.android.com Compose accessibility testing |
| Robolectric 4.17 supports SDK 37 (Maven `lastUpdated` 2026-09-10); 4.16 notes require JDK 21 for SDK 36; MIT licence | GitHub releases; Maven Central metadata and POM |
| zxing core 3.5.4 (Maven `lastUpdated` 2025-11-11), Apache-2.0, only a test-scope dependency | Maven Central metadata, `core` and `zxing-parent` POMs |
| CameraX 1.6.2 stable 2026-08-26 | developer.android.com camera releases |
| `media3-ui-compose` published up to 1.11.1; ATF up to 4.1.1 | Google Maven group indexes |
| AOSP emulator images exist to API 36; API 37.0 only as `google_apis` | `dl.google.com/android/repository/sys-img/{android,google_apis}/sys-img2-3.xml` |
| Android 17 Advanced Protection blocks non-tool accessibility services (secondary) | thehackernews.com (2026-10), securityaffairs.com |
| TalkBack 16.0 can send a screenshot of the screen to Gemini on request (secondary, search summary) | support.google.com/accessibility/android/answer/16294093 |
| Android 14 scales fonts up to 200 %, non-linearly | developer.android.com Android 14 features |
| WCAG 2.2 (Recommendation 2024-12-12): 1.4.3 contrast 4.5:1 (3:1 large), 1.4.4 resize to 200 %, 1.4.11 non-text 3:1, 2.5.8 targets ≥ 24 × 24 CSS px, 3.3.8 accessible authentication, all AA | w3.org/TR/WCAG22; w3.org/WAI/WCAG22/Understanding |

### C.3 Corrected claims

**Research-digest claims corrected in revision 1:**

1. `isAccessibilityTool()` is readable from API 31, not 34 (Microsoft Learn `ApiSince=31`); enforcement of data sensitivity starts at 34.
2. The randomized-subset backup rule is FR-1.4 and the configurable biometric/PIN policy FR-1.8 (spec p.8, table extraction), not FR-1.9 and FR-1.7.
3. The payment disclosure is spec FR-6.9; "FR-6.8" is the plan's and the code's numbering.
4. "`REQUEST_INSTALL_PACKAGES` is outside the T15 set" is true today but not for good: Phase 14's ADR-51 (proposed) adds it, and Phase 13 relies on that for J6.
5. (Not a digest error, a source note.) Robolectric 4.17's date is 2026-09-10 (Maven metadata); a fetched page summary that read 2024 was a summariser artefact.

**Revision 1's own claims corrected in revision 2 (§19):**

6. "Every load-bearing claim re-checked": the facts marked "src" in §2.3 were not re-read (Appendix D said so); the header now says what was checked and how.
7. T10's capture outcomes ("refused" up to API 34, "black" from 35) were written before V-U1 measured them; now "as V-U1 measures".
8. "The IME window is secured from API 31" rests on sources not re-read and on reports that disagree; marked unverified.
9. "In strict mode nothing decrypts until the user authenticates" and "no GHOST process outlives the lock": the hidden process outlived the lock; withdrawn with the strict lock.
10. W3's "the database file is ciphertext nobody can open": file deletion is not erasure, and key deletion is final only with rollback resistance; reworded.
11. "Cleared within 30–35 s in the background": not achievable under the cached-apps freezer; reworded.
12. "The invite link … is not kept on the phone": true for password channels only.
13. "10–13 calendar weeks for a team of 5–6": not derivable from the table; withdrawn.
14. "Verifică aplicația" on `signerCertificateSha256()`: removed by Phase 14's revision 2.

### C.4 Assumed, checked in S0a (each with the fallback if it fails)

| ID | Assumption | Fallback |
|---|---|---|
| V-U1 | `dumpsys window` shows `SECURE` per window on API 29–37; `screencap` refused or black (recorded per level); the recents snapshot is a placeholder; `screenrecord` frames black; **the keyboard over a secure window is captured or not, per level** | rely on `dumpsys` and the device checklist; declare the gap (L11-U2) |
| V-U2 | A `TextureView` inside a secure window is covered; a `SurfaceView` needs `setSecure(true)` | ban `SurfaceView` (already the design) |
| V-U3 | Decor-level `setAccessibilityDataSensitive` hides Compose nodes and dialog content from a non-tool client on API 34–37; the hidden non-tool `UiAutomation` flag works | a test-only spy service declaring `isAccessibilityTool=false`; leaf marking only |
| V-U4 | The interceptor's flag reaches the AOSP keyboard and Gboard (`dumpsys input_method`) | a View-based `EditText` bridge for the composer only |
| V-U5 | Compose 1.12.1's text fields use the provided `LocalClipboard`; background `clearPrimaryClip` works; `getPrimaryClipDescription` with focus reads the label without a toast | disable copy and cut in the composer's toolbar instead |
| V-U6 | Decor-level autofill exclusion stops every autofill request on Compose 1.12.1 | per-field `contentType` with no autofill semantics |
| V-U7 | Robolectric 4.17 with Compose tests on JDK 17 at SDK 35, offline jars, `captureToImage` under native graphics | emulator-only pixel goldens |
| V-U8 | zxing decodes an 876-character invite (version 21, level L) from Camera2 YUV on the low-end phone at 20–40 cm in under 2 s | a larger on-screen code; paste |
| V-U9 | The platform `BiometricPrompt` with a device-credential fallback works on API 29 and 30+ without `androidx.biometric`; `DEVICE_CREDENTIAL` alone on API 30+; whether API 29's credential confirmation stops the activity | add `androidx.biometric` with a `FragmentActivity` (ADR amendment); on API 29 the re-display needs the typed PIN only |
| V-U10 | Keystore HMAC keys work on API 29–37, StrongBox where present; the time per check | a TEE key; declare the speed |
| V-U11 | *(withdrawn in revision 2: strict mode's unwrap window and invalidation; the strict lock is deferred)* | — |
| V-U12 | `captureToImage` in instrumentation on a test activity without the flag | JVM goldens only |
| V-U13 | `getEnabledAccessibilityServiceList` gives labels and packages under package visibility on API 30+ | show packages only |
| V-U14 | The default IME's package is readable under package visibility, and AOSP's LatinIME is recognisable (`com.android.inputmethod.latin`) | warn for every keyboard |
| V-U15 | `VISIBILITY_SECRET` hides the notification on a secure lock screen on 29–37; the channel's lock-screen and badge settings take effect | per-notification settings only |
| V-U16 | Clearing the saved bundle and passing `null` to `super.onCreate` cause no AndroidX failure across configuration changes and process death | clear selected keys only |
| V-U17 | DM actor latency of UI reads during passes (p50, p99) on the emulator and the low-end phone; **the bound RT-UI1 enforces** | lower the poll rate; stale-while-loading |
| V-U18 | The files a fresh install creates (profile installer, code cache): the wipe's and T20's baseline | extend the baseline |
| V-U19 | Predictive back with `PredictiveBackHandler` on API 33–37 at target 37 | plain `BackHandler` |
| V-U20 | Whether an accessibility tool (TalkBack's describe-screen) can capture a secure window on API 36 QPR2+ and 37 | declare (it is declared either way) |
| V-U21 | `LocaleManager` and `generateLocaleConfig` with AGP 9.4 | system language only |
| V-U22 | `media3-ui-compose` 1.11.0 renders on a `TextureView` inside a secure window with no View popup | own `TextureView` player surface |
| V-U23 | Two apps claiming `ghost://`: the platform's chooser behaviour | declare; QR only |
| V-U24 | Edge-to-edge, IME insets and two panes at target 37 on a 600-dp emulator | single pane on large screens |
| V-U25 | **T4 on both paths**: the cloud path with the local transport (API 29–30 separately) and the device-to-device path with `is_device_transfer=true`; a relaxed-rules control APK whose canary file appears | declare the path that cannot be emulated; the device checklist |
| V-U26 | **Compose 1.12.1's text menu**: which items appear by default on API 29–37 (with a stub app handling `ACTION_PROCESS_TEXT` installed) and that `filterTextContextMenuComponents` leaves only cut, copy, paste and select-all | an own text toolbar in `GhostTextField` |
| V-U27 | **T6 attribution**: per-UID capture on the emulator (the root shell with an `iptables` owner match, or per-UID accounting), a control app that resolves a name and is seen, a twin capture (journey vs idle) | per-UID byte counters only; declare |
| V-U28 | **The freezer**: on an API 34+ emulator with the freezer on and GHOST demoted to cached, when the 30-s clear runs; the persisted label's clear at the next focus; the commands that reproduce it in CI | the alarm option of Q10 |
| V-U29 | **Rollback resistance** of the test phones' Keystore, read from key attestation (the `rollbackResistance` / `ROLLBACK_RESISTANCE` field of the attestation record) | declare per device (L11-U21) |
| V-U30 | **`WordKeyboard` timing**: a prototype with ≥ 5 people entering 24 words from paper; budget: median ≤ 120 s, so NFR-10's 3 minutes keep their margin | Q15's fallback path |
| V-U31 | **Task records**: after a cold launch from a `ghost://` link with `persistNever` and the clean relaunch, `/data/system_ce/0/recent_tasks` and `dumpsys activity recents` hold no link; a control without them shows it | declare the in-memory record until the relaunch |
| V-U32 | **CI**: an emulator boots on `ghost-runner` after OA-1 and the `dm-emulator` suites pass there; the nightly occupancy of the four runners and the UI suites' runtime per level (Phase 10's V10-14 method) | Q44's signed local runs |
| V-U33 | **Accessibility events**: keypad presses seen by a non-tool test service on API 29–33 and not on 34+; the window events a non-tool service still receives on 34+ | declare (L11-U20) |
| V-U34 | **The photo picker's route**: on API 29 and 30 images with and without Google Play services, which component resolves `ACTION_PICK_IMAGES`, the fallback action and `ACTION_OPEN_DOCUMENT` | `ACTION_OPEN_DOCUMENT` on every level without the platform picker (already the design) |

---

## Appendix D: Sources (accessed 2026-10-03 unless stated)

**Repository** (at `8a480a7`; code identical to `197b2b4`): `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`; `output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf`; `docs/adr/ADR-01` … `ADR-39`; `docs/THREAT_MODEL_v2.1.md`; `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`; `docs/STATUS.md`; `docs/ci-self-hosted.md`; `docs/design/faza7-sync-engine.md`, `faza8-issuer.md`, `faza9-dm.md`, `faza10-forum.md`, `faza11-media.md`, `faza14-distribution.md` (revision 2, `bab523e`); `docs/reviews/2026-09-25-faza9-review.md`; `ghost/test-harness/privacy/INVARIANTS.md`; the Kotlin sources and gates cited in Appendix C.1; the CI run history (`gh run list`, `gh run view`).

**Android platform**
- https://developer.android.com/about/versions/17/behavior-changes-17
- https://developer.android.com/about/versions/14/features
- https://developer.android.com/about/versions/15/behavior-changes-all
- https://developer.android.com/about/versions/12/behavior-changes-all
- https://developer.android.com/about/versions/10/privacy/changes
- https://developer.android.com/develop/ui/views/touch-and-input/copy-paste
- https://developer.android.com/privacy-and-security/risks/secure-clipboard-handling
- https://developer.android.com/identity/sign-in/biometric-auth
- https://developer.android.com/develop/background-work/services/fgs/timeout
- https://developer.android.com/guide/topics/resources/app-languages
- https://developer.android.com/guide/topics/manifest/activity-element (`persistableMode`, `launchMode`)
- https://developer.android.com/training/package-visibility/automatic
- https://developer.android.com/blog/posts/enhancing-android-security-stop-malware-from-snooping-on-your-app-data (2025-12-11)
- https://source.android.com/docs/core/perf/cached-apps-freezer
- https://source.android.com/docs/security/features/keystore/implementer-ref
- https://learn.microsoft.com/en-us/dotnet/api/android.views.view.setaccessibilitydatasensitive
- https://learn.microsoft.com/en-us/dotnet/api/android.accessibilityservices.accessibilityserviceinfo.isaccessibilitytool
- https://learn.microsoft.com/en-us/dotnet/api/android.app.activity.setrecentsscreenshotenabled
- https://learn.microsoft.com/en-us/dotnet/api/android.app.activity.launchedfrompackage
- https://learn.microsoft.com/en-us/dotnet/api/android.app.usage.usageeventtype
- https://learn.microsoft.com/en-us/dotnet/api/android.security.keystore.keygenparameterspec.builder.setuserauthenticationrequired
- https://learn.microsoft.com/en-us/dotnet/api/android.security.keystore.keygenparameterspec.builder.setuserauthenticationparameters
- https://learn.microsoft.com/en-us/dotnet/api/android.security.keystore.keygenparameterspec.builder.setunlockeddevicerequired
- https://dl.google.com/android/repository/sys-img/android/sys-img2-3.xml and `…/google_apis/sys-img2-3.xml`

**AOSP sources**
- https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/main/services/backup/java/com/android/server/backup/utils/BackupEligibilityRules.java
- https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/main/packages/LocalTransport/src/com/android/localtransport/LocalTransportParameters.java
- `frameworks/base` `Task.java`, `TaskPersister.java`, `ActivityRecord.java`, `Intent.java`, `UsageEvents.java`, `UsageStatsService.java` (main branch through github.com/aosp-mirror/platform_frameworks_base; the privacy review's fetched copies, re-read for this revision)

**Jetpack, libraries, tools**
- https://developer.android.com/jetpack/androidx/releases/navigation3; https://dl.google.com/android/maven2/androidx/navigation3/ (POMs 1.2.0)
- https://developer.android.com/develop/ui/compose/bom/bom-mapping
- https://developer.android.com/develop/ui/compose/accessibility/testing
- https://developer.android.com/jetpack/androidx/releases/compose-foundation (`ProcessTextKey`, text context menu modifiers; search summary)
- https://developer.android.com/jetpack/androidx/releases/activity and https://developer.android.com/reference/androidx/activity/result/contract/ActivityResultContracts.PickVisualMedia (the picker's fallback order; search summary)
- https://raw.githubusercontent.com/androidx/androidx/androidx-main/compose/ui/ui/src/commonMain/kotlin/androidx/compose/ui/semantics/SemanticsProperties.kt
- https://raw.githubusercontent.com/androidx/androidx/androidx-main/compose/ui/ui/src/commonMain/kotlin/androidx/compose/ui/platform/PlatformTextInputModifierNode.kt
- https://raw.githubusercontent.com/androidx/androidx/androidx-main/compose/foundation/foundation/src/androidMain/kotlin/androidx/compose/foundation/text/input/internal/EditorInfo.android.kt
- https://composables.com/docs/androidx.compose.ui/ui/modifiers/semantics
- https://developer.android.com/jetpack/androidx/releases/camera
- https://dl.google.com/android/maven2/androidx/media3/group-index.xml
- https://dl.google.com/android/maven2/com/google/android/apps/common/testing/accessibility/framework/group-index.xml
- https://github.com/robolectric/robolectric/releases (4.17, 4.16); https://repo1.maven.org/maven2/org/robolectric/robolectric/maven-metadata.xml
- https://repo1.maven.org/maven2/com/google/zxing/core/maven-metadata.xml; `core-3.5.4.pom`; `zxing-parent-3.5.4.pom`

**Accessibility and usability**
- https://www.w3.org/TR/WCAG22/ (W3C Recommendation, 12 December 2024: SC 1.4.3, 1.4.4, 1.4.11, 3.3.8 at level AA) and https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html (2.5.8, AA: at least 24 by 24 CSS pixels)
- https://developer.android.com/guide/topics/ui/accessibility/apps (48 dp; via the research digest)
- https://www.nngroup.com/articles/why-you-only-need-to-test-with-5-users/ and https://www.nngroup.com/articles/how-many-test-users/ (via the research digest)
- https://measuringu.com/interpret-sus-score/ (via the research digest)
- https://support.google.com/accessibility/android/answer/16294093 (TalkBack 16.0; search summary)
- https://thehackernews.com/2026/10/android-17-advanced-protection-locks.html; https://securityaffairs.com/189497/security/advanced-protection-mode-in-android-17-prevents-apps-from-misusing-accessibility-services.html (secondary)
- https://www.androidauthority.com/android-privacy-dashboard-1233846/ (the privacy dashboard's camera history; secondary, via the privacy review)

**AOSP and AndroidX sources read by the research digests** (not re-read for this design unless listed above under AOSP sources; each fact marked "src" in §2.3 and checked by a V-U item): `frameworks/base` (`AbsAppSnapshotController.java`, `AssistStructure.java`, `DisplayContent.java`, `WindowState.java`, `ClipboardService.java`, `ClipDescription.java`, `AbstractAccessibilityServiceConnection.java`, `AccessibilityManagerService.java`, `View.java`), `frameworks/native` (`screencap.cpp`, `LayerFE.cpp`), `frameworks/support` (`AndroidDialog.android.kt`, `AndroidPopup.android.kt`, `ModalBottomSheet.android.kt`, `AndroidComposeView.android.kt`, `AndroidComposeViewAccessibilityDelegateCompat.android.kt`, `AndroidClipboardManager.android.kt`, `ComposeUiTestExt.android.kt`).
