# GHOST Phase 13: Production UX — Design (proposed)

| Field | Value |
|---|---|
| Status | **Proposed, 2026-10-03, for the owner's approval before any code** (the owner's rule: an approved design before implementation). ADR-53 … ADR-57 (Appendix A, Romanian) are "propus"; they become "propus, aplicat" only if the owner approves this design or lets the question defaults of §16 stand under the standing instruction to continue between phases. Nothing in this document is a UI claim (CP-10; `docs/STATUS.md:26`: "Afirmații permise în marketing/UI: niciuna"). |
| Revision | 1 (branch `p13-design`, based on `197b2b4`). The drafting author's synthesis of five research digests (requirements; architecture; screen, text and accessibility protection; journeys and UX; testing and gates, 2026-10-03), with every load-bearing claim re-checked in the repository or at a primary source for this draft (Appendix C). Four digest claims were found wrong and are corrected here (Appendix C.3): `AccessibilityServiceInfo.isAccessibilityTool()` is readable from API 31, not 34; the randomized-subset backup rule is spec FR-1.4, not FR-1.9; the payment disclosure is spec FR-6.9, not FR-6.8; `REQUEST_INSTALL_PACKAGES` is not excluded for good, since Phase 14's ADR-51 (proposed) adds it to T15. |
| Date | 2026-10-03 |
| Phase | 13 (plan §6.2 row 13, the authoritative scope): "UX de producție: Compose, high-privacy mode, disclosures aliniate la §4, accesibilitate, stări offline/eroare, protecția ecranului și a textului (FLAG_SECURE permanent, mesaje fără selecție sau copiere, câmpuri sensibile pentru accesibilitate, clipboard sensibil cu ștergere automată; ADR-27)" (`docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md:317`) |
| Exit gate | "usability pe călătoriile P0 (invite → identitate → plată → DM/canal/media → update); T10 și T24 verzi" (plan:317), read with the spec's usability layer ("Mnemonic, invite, payment disclosure, recovery and safety warnings — moderated test with representative users", spec §13 p.22), FR-7.1's acceptance ("Automated accessibility and theme tests pass on supported devices", p.10), FR-7.8's ("Mnemonic/seed does not appear in screenshots, recents or persistent clipboard", p.10), NFR-10 (seed recovery < 3 min median, < 5 min p95, p.12) and C-10 (UI and legal disclosures match the guarantee matrix, p.28). §1.1 states what the gate proves and what it does not |
| Depends on | Phases 9, 10, 11 (plan:317). **In fact:** the Phase 8 code (the entitlement facade, `Entitlement.kt`), the Phase 9 code on `main` (the DM facade; Phase 9's own exit gate is open, `docs/STATUS.md`), the Phase 10 `Channels` facade (design approved 2026-09-27; code only as S1a WIP on branch `p10-s1a`), the Phase 11 media facade (design **proposed, not approved**), and Phase 14's `Updates` facade (design proposed on branch `p14-design`, `58117c0`) for the update leg of the gate |
| ADR impact | New: **ADR-53** (the UI layer: `:ui` module, gateways, unidirectional flow, coroutines confined to the UI, own navigation, no sensitive saved state), **ADR-54** (screen and text protection as implemented; refines ADR-27 points 1–6), **ADR-55** (app lock, strict mode, local wipe, seed backup and restore), **ADR-56** (claims and disclosures in the UI: the claims register and its gate), **ADR-57** (new components and permissions: notifications, camera for QR, zxing core, `ghost://` links). Deviations X-U1 … X-U13 (§0.3). **Numbering:** Phase 10 uses ADR-40 … 43, T36–T41, LIMITE L8, migrations 6 and 7; Phase 11 ADR-44 … 47, T42–T47, L9, migration 8; Phase 14 (branch `p14-design`) ADR-48 … 52, T48–T52, L10, migration U. This design takes **ADR-53 … 57, T53–T57, LIMITE L11** and **migration UX**, the next free schema version at merge (Phase 14's X-D12 rule) |
| Sources | Master plan v2.1; spec v2.0 PDF (text extracted with `pdftotext -table`, since the Read tool cannot render it on this host: CP-01 … CP-10 and the guarantee matrix p.6, release stages p.7, FR-1.x p.8, FR-3.x/FR-4.x p.9, FR-6.x/FR-7.x p.10, FR-8.x p.11, NFR p.12, §6.1 modules p.13, §12.2 p.21, §13 p.22, roadmap row 13 p.23, DoD p.24, risks p.25, Appendix C p.28); ADR-01 … ADR-39; THREAT_MODEL v2.1; LIMITE; INVARIANTS T1–T35; STATUS; the Phase 7, 8, 9, 10 and 11 designs and the Phase 14 design on its branch (read with `git show`, its worktree untouched); `docs/reviews/2026-09-25-faza9-review.md`; the Kotlin facades and gates at `197b2b4`. Repository citations are `path:line` relative to the worktree root (`ghost/…` for the monorepo). `F7` … `F11`, `F14` = `docs/design/faza7-sync-engine.md` … `faza11-media.md`, `faza14-distribution.md` (branch `p14-design`); `INV` = `ghost/test-harness/privacy/INVARIANTS.md`; `TM` = `docs/THREAT_MODEL_v2.1.md`; `LIM` = `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`. Appendix C separates verified from assumed; Appendix D lists sources with access dates |

**How to read this document.** §0 is the summary: decisions, guarantees, deviations, non-goals. §1 fixes scope, requirements, the debts other phases left to Phase 13, and the contradictions found. §2 is the threat and privacy model of the UI layer, including what each Android protection does on API 29–37. §3–§10 are normative: the architecture (§3), the protection components (§4), lock, wipe, backup and restore (§5), the journeys and every screen state (§6), modes, timers and media honesty (§7), disclosures and the claims register (§8), the design system, accessibility and localisation (§9), the one schema migration (§10). §11 lists invariants, §12 tests and the exit-gate argument, §13 gates, CI and dependencies, §14 slices and effort, §15 risks, §16 owner questions, §17 owner actions, §18 findings outside the phase. Appendix A holds the ADR drafts (Romanian), Appendix B the text changes in other documents, Appendix C the evidence and the S0 checks, Appendix D the sources. A section marked "(normative)" wins over a summary table.

**Identifier conventions.** Decisions `D1…D32`; requirements `R13-1…`; guarantees `P-U1…` (privacy) and `CS-U1…` (correctness and safety); deviations `X-U1…`; leak channels `C1…C15`; journeys `J1…J6`; disclosures `DC-1…DC-27`; invariants `T53…T57`; gates `G-U1…G-U12`; mutants `PM-U…` (privacy) and `MC-U…` (correctness); twin worlds `NI-U1…`; S0 checks `V-U1…`; risks `R-U1…`; questions `Q1…Q40`; owner actions `OA-1…`; findings `F-U1…`; residues `L11-U1…` (new LIMITE section L11). Slices `S0a`, `S0b`, `S1…S12`.

---

## 0. Summary

### 0.1 Decisions

| # | Decision | Rejected alternatives (why) | Plan / ADR alignment |
|---|---|---|---|
| D1 | **Scope, exactly as the plan states.** P0: the six journeys J1–J6 (§6) with every state, screen and text protection of ADR-27 points 1–6, high-privacy mode, disclosures aligned with plan §4 and §7, accessibility, offline and error states, and the callers the engines are waiting for (lock, wipe, key creation, notifications, display, payment hold). **Not designed here** although earlier documents pointed them at "Phase 13": card rotation with the P1 contact backup (F9 §12.5, Q27), Invite v3 (F9 Q32), opt-in read receipts (F9 Q8), the deniable reveal (F10 Q35), the ADR-13 governance engine (F10 Q15), history transfer, the prompt-mode foreground service (F7, ADR-20), the crash-report transport (FR-8.11), in-app media capture (F11 Q15). Each is a protocol or engine change with relay-visible behaviour; §1.4 gives each a successor and Q19 asks the owner | absorbing them (roughly doubles the phase and mixes UX with protocol work that the T27, T31, T32 and channel privacy worlds would have to re-prove) | plan:317; spec §3 (P1 may be off in a labelled private alpha, p.7) |
| D2 | **A new `:ui` Android library** holds the screens, the design system, the protection components, the state holders, the UI models and the gateway interfaces, and **depends on no `org.ghost.*` module**; `:app` stays the composition root and adds the gateway adapters, the notifier, the lock and wipe controllers and the settings store (§3.1) | everything in `:app` (no compile-time wall: UI code could import storage, network or a facade internal, as `:messaging`'s `api` exports of `:sync` show); per-feature modules (eleven more build files for a single-activity app) | spec §6.1 lists a `ui` module (p.13); plan Appendix B folds "Compose UI" into `app/` (plan:352; X-U7) |
| D3 | **Unidirectional data flow over blocking facades.** Composable → intent → screen model → gateway (`suspend`) → adapter in `:app` (the blocking facade call on a bounded `ghost-ui-io` executor, never the main thread) → immutable `UiState` in a `StateFlow`; engine change hints arrive content-free through one `ChangeHub` (conflated, drop-oldest) and trigger re-queries; status is polled every 2 s only while visible and unlocked (§3.2) | composables calling facades (main-thread blocking: `DmActor.call` waits on a future without timeout, `DmActor.kt:199-216`); an MVI framework (no allowlisted library; plain state holders suffice) | ADR-19 (no protocol logic in Kotlin UI); FR-7.1 |
| D4 | **Coroutines only in the UI.** `kotlinx.coroutines` (already shipped, 1.9.0) may be used in `:ui` and in `org.ghost.app.ui`; every engine module keeps ADR-20's "no coroutines", now enforced for all of them by G-U9 (G-DM1 covered only `:messaging` and `:crypto-bridge`) | callbacks everywhere (Compose's effects, `StateFlow` and `InterceptPlatformTextInput` are coroutine APIs); coroutines in engines (undoes the blocking-JNI model of ADR-20) | ADR-20 point 1 (X-U8); ADR-53 |
| D5 | **State dies with the unlock.** Screen models live in an `UnlockedSession` created at unlock and closed at lock (standard) or ended with the process (strict); **no sensitive value in `rememberSaveable`, `SavedStateHandle`, `rememberTextFieldState` or any `Bundle`**, and the activity's saved-state bundle is cleared (§3.3, T54); sensitive strings are typed `SensitiveText` (redacted `toString`, one unwrap site); the mnemonic is held as 24 word indices in an `IntArray` zeroed after use | Jetpack `ViewModel` per screen with `SavedStateHandle` (the bundle leaves the process to `system_server`, outside GHOST's encryption) | ADR-27; FR-7.8; T3 |
| D6 | **Own navigation:** a typed back stack (`sealed interface Route`) owned by the session, `AnimatedContent`, activity-compose `BackHandler` and `PredictiveBackHandler`, a two-pane layout from 600 dp; never persisted, so a new process starts at the lock or home screen (§3.4) | Navigation 3 1.2.0 (stable since 2026-09-23; its `rememberNavBackStack` and saveable-state decorator persist keys and per-entry state, which GHOST would have to disable; +2 artifacts and a `navigationevent` bump for features worth ~500 lines); Navigation Compose (bundle-based graph) | Q3 |
| D7 | **One activity, one exported component.** `MainActivity` (a `SecureActivity`) is the launcher and the only target of `ghost://invite/`, `ghost://contact/` and `ghost://channel/` links; every link is untrusted input that lands on a confirmation screen, never acted on automatically (§3.4, G-U11) | an activity per flow (more exported or task surfaces; T15m allows only the launcher) | ADR-05 (scheme only), T15m, T16 |
| D8 | **Secure windows by construction** (§4.1): `SecureActivity` sets `FLAG_SECURE` before the first frame, `setRecentsScreenshotEnabled(false)` on API 33+, decor-level `setAccessibilityDataSensitive(YES)` on API 34+ and autofill exclusion on the decor; Compose `Dialog`, `Popup` and `ModalBottomSheet` inherit the flag (`SecureFlagPolicy.Inherit`); every View-based window GHOST could open by accident (`Toast`, `PopupWindow`, `android.app.Dialog`, `Spinner`, `AutoCompleteTextView`, `PopupMenu`, Media3 `PlayerView`) is banned (G-U1) | the flag per screen (forgettable); allowing `Toast` (a text toast is drawn by SystemUI, outside GHOST's window) | ADR-27 point 1; T10 |
| D9 | **Text cannot leave through the UI** (§4.2): no `SelectionContainer` anywhere; message, post, caption and media views expose no copy, share, "Trimite către" or drag; the root replaces Compose's `LocalClipboard`, so even the composer's own copy and cut go through the sensitive clipboard; URLs in messages are plain text (no link detection, no tap, no preview) | Linkify or `LinkAnnotation` (a tap opens a clearnet browser; phishing; ADR-08 "no link previews"); Compose's default clipboard (writes without `EXTRA_IS_SENSITIVE`, invisible to a grep gate) | ADR-27 point 3, ADR-08; T24 |
| D10 | **Accessibility without content leaks, and without excluding users** (§9.3): every window decor-level sensitive on API 34+ plus `isSensitiveData` on every content leaf; all semantics kept for accessibility tools (TalkBack, Switch Access, Voice Access); new-message announcements content-free; long-press menus replaced by custom actions; a screen lists the enabled accessibility services with their tool and system flags (API 31+), and when a non-tool or unknown service is enabled an opt-in hides content from all services | hiding content from all services by default (excludes blind users; ADR-27 keeps screen readers working); doing nothing below API 34 (ADR-27 point 4 asks for the warning) | ADR-27 point 4; Q8 |
| D11 | **One sensitive clipboard** (`SensitiveClipboard.kt`, the "approved module" of T24): only user-requested, non-message data (the three link kinds, the own contact link, the payment subaddress, the app's signer fingerprint); always `EXTRA_IS_SENSITIVE`; cleared after 30 s and at lock, with an ownership check when GHOST has focus and an unconditional clear when it has not (Android forbids the background read the check needs); the seed, a channel passphrase, safety digits, the PIN and message text are never copied | the share sheet (`ACTION_SEND`) for invite links (another exposure path; Phase 11's proposed G-M1 bans it too); clearing only when the check is possible (would leave clips forever while GHOST is in the background) | ADR-27 point 5 (X-U3); T24 |
| D12 | **Keyboards** (§4.5): one `InterceptPlatformTextInput` at every window root ORs `IME_FLAG_NO_PERSONALIZED_LEARNING` into every editor; **the PIN, the 24 words and the 5-word channel passphrase are typed on in-app keypads** (no system IME, no paste, no autofill); a one-time warning names a non-system default keyboard | the system IME for secrets (cloud keyboards, keyboard clipboard histories, the flag is only a hint) | ADR-08, ADR-27 point 6 (X-U4) |
| D13 | **Notifications carry nothing** (§4.6): one channel; one constant text; no sender, conversation, content or (by default) count; `VISIBILITY_SECRET` by default; no badge; no `MessagingStyle`, `RemoteInput`, shortcut, bubble or person; payment, access and update states are never notifications | the OS default (sender and text); notifying `PAYMENT_READY` (F8 §19.11, E15: a timing signal) | ADR-06, ADR-27 point 2, F9 Q19; T11 (X-U13) |
| D14 | **App lock is mandatory and has two strengths** (§5): an app PIN (6–16 digits, optional biometric), auto-lock 1 min after the app is hidden by default. **Standard lock** = a curtain plus the end of the unlocked session; the DM context stays open, so background receipt, sweeps and notifications continue. **Strict lock** (opt-in) = database, identity, content and state keys bound to device authentication, and the process exits at lock: nothing decrypts until the user authenticates, and nothing syncs in the background (ADR-20 Q6) | lock = `ctxClose` in the live process (F9 §2.5's wording; it stops RECV and notifications in the shared process and protects against nothing a Keystore-capable attacker cannot undo, X-U1); a UI curtain as the only option (FR-1.8 asks for a configurable biometric/PIN policy) | FR-1.8 (p.8), FR-7.13, LIM:31-32, ADR-55 |
| D15 | **PIN verifier bound to the device:** `tag = HMAC-SHA256(K_pin, label ‖ salt ‖ PIN)` with `K_pin` a non-exportable Keystore key, stored in SQLCipher; exponential back-off; no automatic wipe (duress is P2) (§5.2) | an Argon2id-only verifier (a 6-digit PIN falls offline from a database copy in about an hour on one 24-thread host at the channel-password profile, F10 E-73); the device credential as the app PIN (often shared) | ADR-08 "PIN de aplicație" |
| D16 | **Local wipe, crypto-shred first** (§5.5): DM and sync stop, key envelopes deleted, Keystore aliases deleted, files deleted, process exit; an interrupted wipe finishes at the next start, keyed on the missing database-key envelope; revocation is a separate P1 screen | revoke-and-wipe as one action (revocation is staggered over 24 h, ends the identity, and needs the device online, F9 §8.5) | FR-7.13; ADR-55 |
| D17 | **Seed backup before completion** (§5.6): the 24 words appear only after activation is `ACTIVE`, then 4 random positions are checked, with no skip; onboarding is incomplete until verified; re-display behind re-authentication; never copied or exported. **Restore** only through `Entitlement.restore`, then a "what was lost" screen | showing the words during activation (backs up an identity a failed trial wipes, F8 §8.3); a skippable backup (spec R-01 "mandatory verified backup") | FR-1.4 (p.8), R-01 (p.25) |
| D18 | **High-privacy mode** STANDARD by default, HIGH offered at the end of onboarding and in settings; **persisted in SQLCipher and applied by the sync runtime at database open in every process, before any session** (§7.1) | HIGH by default (sends delayed up to 10 min, extra days before new tokens are usable); SharedPreferences (a plaintext file saying "HIGH"); today's in-memory default (`SyncRuntime.kt:191`), which a job process never changes | ADR-20 point 3, plan:263 |
| D19 | **Closed list of UI-caused traffic** (T53, §2.4): only the user actions of §2.4 reach relays, the issuer or a mirror; no pull-to-refresh, no "check for messages now", no read of `paymentInstructions` outside the payment screen; UI facade calls are rate-limited so they cannot move a time-triggered step across a minute | refresh affordances (a user-timed list event breaks T19) | T19, T23, T28, T31 |
| D20 | **Claims register** (§8): every privacy or security sentence has an entry with its kind (`LIMIT`, `FEATURE`, `GOAL`, `CLAIM`), evidence IDs and residue; a `CLAIM` reaches a release only when its evidence is in the green list (today none is); forbidden phrases are gated in Romanian and English; the "Cine vede ce" page mirrors plan §4 with an evidence status per row | copy reviewed by eye (FR-8.7 wants a signed checklist; CP-10 wants traceability) | CP-10, FR-8.7, C-10, ADR-38 point 11 |
| D21 | **Design system:** Material 3 from BOM 2026.09.00 (`material3` 1.4.0), dynamic colour on API 31+ with fixed semantic colours for warnings, system fonts only, light, dark and system themes, bundled vector icons, no image library (§9.1) | bundled fonts (licence review, size); `ui-text-google-fonts` (a Google Play services font provider); `material-icons-extended` (size) | FR-7.1; ADR-06 |
| D22 | **Romanian and English at launch** (`values-ro` written first, `values` English as the fallback), informal "tu"; per-app language through `LocaleManager` on API 33+; BIP-39 words stay English (§9.4) | AppCompat for per-app language on API 29–32 (a large dependency for a settings convenience); Romanian only | Q9 |
| D23 | **QR through zxing core 3.5.4** (Apache-2.0, no runtime dependency) for encoding and decoding, with scanning on the platform Camera2 API inside GHOST's secure window (§4.7) | CameraX (adds `libimage_processing_util_jni.so` and several artifacts); ML Kit (Google Play services); zxing-cpp (native); the system camera intent (a third-party app sees the frame) | FR-7.7 (p.10, P1), ADR-05; X-U10 |
| D24 | **Media UI on Phase 11's facade**: system photo picker, a Compose player over Media3 `media3-ui-compose` (no View popups), a `TextureView` surface inside the secure window, view-once and ephemeral copy that claims nothing the engine does not do; the pause-download switch says that relays see it (§6.6, §7.3) | Media3 `PlayerView` (its settings menu is a `PopupWindow`, outside `FLAG_SECURE`) | F11 §6.5, §11; L9-M3 |
| D25 | **Update UI on Phase 14's `Updates` facade**: user-requested check and download, install through `PackageInstaller` with the "Install unknown apps" prompt, alarms for `CONFLICT`, `STALE` and `UNSUPPORTED`, and a "verify this app" screen; nothing at app start (§6.7) | a check at start (X-D1 of F14: the mirror would see app opens) | F14 §7.3, §9.5, F-D8 |
| D26 | **No foreground service in Phase 13** (neither prompt mode nor an upload service); Doze delays are declared | `remoteMessaging` or `dataSync` FGS now (needs its own ADR, unmeasured battery, `dataSync` capped at 6 h per 24 h on Android 15+, and it changes the relay-visible cadence) | F7 §5.4, F11 Q30 (Q16, Q17) |
| D27 | **Three test tiers** (§12): JVM (Robolectric 4.17 at SDK ≤ 35 on JDK 17, Compose UI tests, semantic-tree dumps, pixel goldens on Linux only), emulator nightly (AOSP images API 29, 33, 35, 36; `google_apis` 37.0), two physical phones; plus moderated usability rounds | emulator only (CI blind until the KVM fix); Paparazzi or Roborazzi (new groups, no interaction, no dialogs) | FR-7.1 acceptance; INV T10, T24 |
| D28 | **Twelve gates G-U1 … G-U12** on the shared lexer (`source-text.pl`), the merged release manifest and the R8 mapping, each failing on an empty scan, each with a negative fixture, near-miss positives and an exact `self-test.sh` hit count (§13.1) | line greps (the §22.33 evasion review broke 27 of 27) | ADR-10; the Phase 9 gate practice |
| D29 | **Usability protocol** (§12.5): a formative round (5 participants, after S4) and a summative round (≥ 8, on the release candidate); per journey ≥ 80 % unassisted completion, no critical error in more than one participant, comprehension items; NFR-10 timed; observation and audio with consent, no screen recording (`FLAG_SECURE` forbids it) | an expert walkthrough only (the spec asks for representative users) | spec §13 p.22, NFR-10 |
| D30 | **One schema migration (UX)**: `ui_settings`, `ui_lock`, `ui_crash`; nothing else of the UI is persisted (§10) | SharedPreferences or DataStore (plaintext files; T20's discipline extended by T54) | T20, T33 |
| D31 | **Facade additions are the minimum the screens need** (§3.6): F9 §13.2's designed-but-unbuilt `setListener` and contact names, conversation summaries without text, the conversation timer, per-message timer and expiry, reactions; entitlement `inspectInvite`, `openPurchases`, `invites`, `activateGenesis`; identity mnemonic indices; each re-runs its phase's gates | screens that persist ids of their own (a second store of state the engine owns) | F9 §13.2, F8 §11.2 |
| D32 | **Effort, honestly:** 50–62 person-weeks, **10–13 calendar weeks** for a team of 5–6, not 4–6; the gate is dated by owner actions (devices, the KVM runner, staging, participants) and by Phases 10, 11 and 14 delivering their facades (§14.2) | the plan's 4–6 weeks (no calibration; the scope is five facades, about 55 screens, twelve gates and a human study) | plan:317 (X-U6) |

### 0.2 Guarantees claimed (each has a test in §12; none is a UI claim before the gate closes, CP-10)

| ID | Guarantee | Proof |
|---|---|---|
| P-U1 | **Secure windows.** Every window GHOST opens (activity, dialog, popup, menu, sheet, player) carries `FLAG_SECURE` from its first frame; no code path clears it; API 33+ activities also refuse recents screenshots. What this does and does not stop on each Android version is §2.3, never a stronger sentence | T10: G-U1, JVM window-flag tests, emulator `dumpsys window` on every window, capture and recents checks with positive controls, device checklist; PM-U1 … PM-U3 |
| P-U2 | **No text path out.** No message, post, caption, media or pseudonym can be selected, copied, shared or dragged; every clipboard write GHOST makes is marked sensitive and cleared after 30 s or at lock; the seed, passphrases, safety digits and the PIN are never written to the clipboard | T24: G-U2, G-U3, JVM toolbar and clipboard spies on a virtual clock, emulator real-clock clear; PM-U4 … PM-U8, PM-U22 |
| P-U3 | **Content hidden from non-tool accessibility services on API 34+**, visible to tools | T24: JVM semantics canary walk; emulator dumps through a non-tool and a tool client; PM-U9 … PM-U11 |
| P-U4 | **Notifications carry nothing but a constant text** (and an optional count), locked or not | T11: G-U10, JVM notification shadow, emulator `dumpsys notification --noredact` canary scan; PM-U12, PM-U13 |
| P-U5 | **No UI-caused traffic outside §2.4's closed list** | T53: G-U5, the recording-gateway suite, twin worlds NI-U1 … NI-U3; PM-U16, PM-U17 |
| P-U6 | **No sensitive UI state outside SQLCipher and RAM**: no saved-state bundle content, no preference or file written by the UI except the declared ones | T54: G-U6, JVM bundle canary scans, emulator sandbox inventory; PM-U14, PM-U15 |
| P-U7 | **Lock curtain.** While locked no content screen is composed; the lock decision precedes the first frame after a return; a new process starts locked; in strict mode no GHOST process outlives the lock | T55: JVM frame tests, state-machine tests, emulator process checks; PM-U19 … PM-U21 |
| P-U8 | **No unbacked claim.** No string of kind `CLAIM` reaches a release without its evidence in the green list; no forbidden phrase appears in either language | T56: G-U8; PM-U24 |
| CS-U1 | **Wipe completeness and resumability**: after a wipe, the inventory of §5.5 holds; a crash at any step finishes at the next start | T57: JVM crash enumeration of the wipe steps; emulator inventory; MC-U3, MC-U4 |
| CS-U2 | **Lock state machine**: every legal and illegal transition tested; PIN failures persist and back off | JVM; MC-U1, MC-U2 |
| CS-U3 | **Strict-mode rewrap is crash-safe**: a crash at any step leaves an openable database under exactly one wrapping | JVM crash enumeration over a software Keystore; emulator; MC-U5 |
| CS-U4 | **Every engine outcome has copy and an action** in both languages | reflection test over every enum the gateways map; MC-U7 |
| CS-U5 | **Limits are enforced before a facade call** (NFR-14) | JVM; MC-U10 |
| CS-U6 | **No facade call on the main thread; no deadlock with the DM actor** | thread assertions in every adapter, StrictMode in debug; PM-U26 |

### 0.3 Deviations from approved documents (each recorded in an ADR of Appendix A)

| # | Document | Deviation | Why | ADR |
|---|---|---|---|---|
| X-U1 | F9 §2.5, §13.7 ("Lock and wipe call `ctxClose`") | the **standard** lock does not close the DM context; the strict lock does, then the process exits | without authentication-bound keys the context reopens from the Keystore at any process start, so closing it protects against nothing, while it stops RECV and notifications in the process the background job shares | ADR-55 |
| X-U2 | INV T24 ("`setPrimaryClip` în afara unui singur modul aprobat") | the approved unit is one file, `SensitiveClipboard.kt`, plus the root that installs it as Compose's `LocalClipboard` | a Gradle module per file is overhead; the gate checks the file | ADR-54 |
| X-U3 | ADR-27 point 5 ("ștearsă … doar dacă clipboard-ul mai conține datele puse de GHOST") | the ownership check runs only while GHOST has focus; in the background the clear is unconditional | Android 10+ lets only the focused app or the default IME read the clipboard (developer.android.com, Android 10 privacy changes) | ADR-54 (Q10) |
| X-U4 | ADR-08, ADR-27 point 6 (`IME_FLAG_NO_PERSONALIZED_LEARNING` "pe toate câmpurile") | the flag is on every system-IME field; the secrets have no system-IME field at all | the flag is a hint (`EditorInfo` javadoc); keypads remove the IME from the secret path | ADR-54 |
| X-U5 | ADR-06 ("+ un foreground service opțional «mod prompt»"), F7 §5.4, F11 Q30 | no foreground service in Phase 13 | needs its own ADR and battery measurement; changes the relay-visible cadence (L2.1 point 4) | ADR-53 (Q16, Q17) |
| X-U6 | plan row 13 ("4–6 s") | 10–13 calendar weeks for a team of 5–6 | §14.2 | Appendix B.1 |
| X-U7 | plan Appendix B (`app/ # Compose UI, DI, navigare`) | Compose UI in `:ui`; DI and wiring in `:app` | D2 | ADR-53 |
| X-U8 | ADR-20 point 1 ("fără coroutines"), F9 §16.3 | coroutines allowed in `:ui` and `org.ghost.app.ui` only | Compose is coroutine-based; the engines keep the rule, now gated for all of them | ADR-53 |
| X-U9 | F9 §12.5 (cut-off, Invite v3), F9 Q8, F10 Q15 and Q35, F11 Q15, LIM rows "rotația cardului (Faza 13)" | not designed in Phase 13; each gets a successor (§1.4) | protocol changes, not UX (D1) | ADR-53 (Q19) |
| X-U10 | F11 Q15 ("in-app CameraX in Phase 13") | the camera is used only for QR scanning, through Camera2; no CameraX | no new native library; media capture stays out (D23) | ADR-57 |
| X-U11 | F10 §4.5 (channel copy that compares channels with DMs) | the comparison clause waits for ADR-36's evidence; the channel limitation sentence ships alone | a sentence saying DMs are protected is a PQ claim before M-1 … M-7 and the external review (ADR-36 point 6) | ADR-56 |
| X-U12 | ADR-27 point 1 ("pe fiecare fereastră a aplicației") read with Phase 11's X-M11 | unchanged in substance; made exact: `SurfaceView` layers inside secure windows are also marked secure (`setSecure(true)`) | a video surface is its own layer (V-U2) | ADR-54 |
| X-U13 | INV T11 ("Notificările cu dispozitiv blocat …") | constant text **locked or not**, hidden on the lock screen by default, no badge | F9 Q19: Android's notification history keeps what was posted | ADR-54 |

### 0.4 What this design deliberately does not do

- It changes no relay, issuer or mirror protocol and no observable field (`allowed-observables.json` unchanged, T1 untouched); it adds no JNI function and no Rust crate (the closed lists G-R6, G-M6 and G-D5 are unchanged); every engine change is a facade addition listed in §3.6.
- It does not detect root, malware or "unsafe devices": any such check runs on the attacker's system (LIM L1); it says so instead.
- It does not protect what is on screen from a camera, a second device, a modified client or a rooted phone (ADR-27 residues), nor speech heard by bystanders when a screen reader reads aloud.
- It does not disguise the app (no fake icon or name) and does not hide that GHOST is installed.
- It builds no duress PIN (P2, plan §6.5), no multi-device, no backup of contacts or tokens (E11, F9 §8.6), no bridge configuration (Phase 12, ADR-16), no in-app installer of other apps' payments (ADR-03).
- It makes no privacy, security or post-quantum statement in the UI: every such sentence is a blocked `CLAIM` in the register until its evidence is green (§8).

---

## 1. Scope, requirements, non-goals

### 1.1 The exit gate, read precisely (normative)

The gate has three items. **(a) "usability on the P0 journeys"** is defined by §12.5: a summative moderated round with at least 8 representative participants on the release-candidate build, in which every journey J1–J6 reaches the completion, critical-error and comprehension thresholds of §12.5, NFR-10 is timed, and the automated journey scripts (§12.3) are green on the emulator. **(b) "T10 green"** is the evidence matrix of §12.7 for T10: G-U1, the JVM window tests, the emulator matrix on API 29, 33, 35 and 36 (AOSP) plus 37 (`google_apis`), and the signed device checklist. **(c) "T24 green"** is the same matrix for T24: G-U2 … G-U4, the JVM clipboard, toolbar and semantics tests, the emulator accessibility dumps on API 35 (a tool and a non-tool client) and the device checklist.

**What the gate proves:** that the shipped UI opens no unprotected window, offers no text exit for message content, writes the clipboard only sensitively and briefly, hides content from non-tool accessibility services where Android enforces it, and that representative users complete the P0 journeys and understand the disclosures the spec names. **What it does not prove:** anything about relays, cryptography or payments (other phases' gates), behaviour on device builds outside the tested matrix, protection against a compromised device (a non-goal, plan:377), or that a user who understood a warning will act on it. The new invariants T53–T57 are in the closing checklist (§14.3) although the plan's gate names only T10 and T24 (Q36).

### 1.2 Requirements (normative; each has a source and a test in §12)

| ID | Requirement | Prio | Source |
|---|---|---|---|
| R13-1 | Compose, Material You, light and dark themes, accessibility labels, scalable text; "automated accessibility and theme tests pass on supported devices" | P0 | FR-7.1 (spec p.10) |
| R13-2 | Every window `FLAG_SECURE`, no off switch; `setRecentsScreenshotEnabled(false)` on API 33+; screenshots and recordings black; nothing in recents; "mnemonic/seed does not appear in screenshots, recents or persistent clipboard" | P0 | ADR-27 point 1; FR-7.14 (plan:276); FR-7.8 (p.10); INV T10 (`INV:18`) |
| R13-3 | Messages and media: no selection, copy, share, "Trimite către" or drag out; the composer stays normal | P0 | ADR-27 point 3; INV T24 (`INV:32`) |
| R13-4 | Messages, pseudonyms, safety numbers and seed words `accessibilityDataSensitive` on API 34+; below 34, a settings warning when a third-party accessibility service is on; screen readers keep working | P0 | ADR-27 point 4 and consequences |
| R13-5 | Clipboard only for user-requested non-message data; seed never; `EXTRA_IS_SENSITIVE`; cleared after 30 s or at lock | P0 | ADR-27 point 5; FR-7.8 |
| R13-6 | `IME_FLAG_NO_PERSONALIZED_LEARNING` on all fields; a one-time third-party-keyboard warning; no link previews | P0 | ADR-08; FR-7.12 (plan:274) |
| R13-7 | Notifications without content, locked or not; an option to hide the count | P0 | ADR-06; ADR-27 point 2; F9 Q19 (`faza9-dm.md:2769`) |
| R13-8 | Auto-lock (default 1 min in background) and an app PIN; "biometric/PIN policy MUST be configurable"; duress wipe P2 | P0 (duress P2) | FR-7.13 (plan:275); FR-1.8 (p.8); LIM:32, LIM:40 |
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
| R13-22 | Update: version, offers, platform install, alarms; no check at start | P0 | FR-7.5 (p.10); F14 §7.3, §9.5, F-D8 |
| R13-23 | Licences screen before the first distribution (with the MPL note); security contact; the ADR-38 residue sentence beside any allowed claim | P0 | ADR-37 point 3; FR-8.6 (p.11); ADR-38 point 11 |
| R13-24 | No Google Play services, Firebase, analytics or crash SDK; every UI dependency allowlisted; no font, CDN or network outside the relay client | P0 | ADR-06; FR-7.11 (plan:273); INV T7 |
| R13-25 | Crash reports local, encrypted, user-reviewed, scrubbed; sending manual via Tor | P0 (sending: §1.4) | FR-8.11 (plan:280) |
| R13-26 | No relay, issuer or mirror traffic caused by the UI beyond declared user actions | P0 | derived from T19, T23, T28, T31 (`INV:27,31,36,39`) |
| R13-27 | Limits enforced by the UI before a call | P0 | NFR-14 (p.12); F9 §12.6; F10 (100 members, 9 channels, 16 000 B posts); F11 §6.6 |
| R13-28 | Payment timing: the payment-screen hold; `PAYMENT_READY` never an immediate notification; "invoice now" and "check now" in STANDARD only | P0 | F8 §19.11; LIM E3, E15 |
| R13-29 | Non-technical P0 copy: compromised phone; dedicated device or GrapheneOS; "rezistență, nu imunitate"; a regional Tor guide; channel rules at entry; remote-deletion limits | P0 | LIM:41, :33, :87, :159, :141; FR-4.7 |
| R13-30 | The copy obligations of Phases 9, 10 and 11 (listed with their sources in §8.3) | P0 | F9, F10, F11 |
| R13-31 | Doze, offline, retry and process-death behaviour of the UI | P0 | FR-7.3 acceptance (p.10) |
| R13-32 | Backup and device-transfer inspection finds no seed, DB key, protocol state or plaintext cache | P0 | FR-7.9 (p.10); INV T4 (`INV:12`) |
| R13-33 | Callers for what the engines wait on: lock, wipe, key creation, notification port, `markDisplayed`, `setConversationOnScreen`, payment screen, privacy mode, expedite | P0 | `GhostApp.kt:161-188`; F9 §10.3; F11 §6.5; F8 §19.11 |
| R13-34 | Emulator and device evidence the earlier phases left here: T6 dynamic, T20 device inventory, T4 inspection, G-DM5 and the release smoke test on the graph that ships | P0 | `INV:14,28,12`; F7:1301; `docs/reviews/2026-09-25-faza9-review.md:122` |

### 1.3 Debts other documents left to Phase 13, and their disposition

| Debt | Source | Disposition |
|---|---|---|
| Callers for `GhostApp.onLock`, `onUnlock`, `onWipe` | `GhostApp.kt:167-188`; F9 §22.17; LIM L7-D19 | **In scope** (§5); `onLock` only in strict mode (X-U1) |
| A creator of the database key, then `onDatabaseKeyCreated` | `GhostApp.kt:161-165`; `DatabaseKeyProvider.kt:19` | **In scope** (§3.6, §6.2) |
| Callers for the DM facade, then G-DM5 and the release smoke test re-run on the graph that ships (R8 strips the facade today) | Phase 9 review A-4 (`docs/reviews/2026-09-25-faza9-review.md:55,122`) | **In scope** (S10) |
| `setListener` (designed, never built) | F9 §13.2; `Messaging.kt:11-27` | **In scope** (§3.6) |
| `NotificationPort` implementation, its permission ADR, notification evidence | `MessagingPorts.kt:16-38`; F9 §21.10 point 9 | **In scope** (§4.6, ADR-57) |
| `markDisplayed` (recipient countdown) | F9 §10.3 | **In scope** (§3.5) |
| `setConversationOnScreen`, previews, the pause-download switch | F11 §6.5, L9-M3 | **In scope** (§3.5, §6.6) |
| `paymentScreenShown` / `Hidden`; copy for E11, E15, E21, E23, E25 | `Entitlement.kt:64-71`; F8 §19.11; LIM L6 | **In scope** (§6.3) |
| `SCHEDULE_CONFLICT`, `ISSUER_MISMATCH`, `REFUSED_BY_RELAY` as security alarms | F8:432; `EntitlementStatus` | **In scope** (§6.1, §6.9) |
| Licences screen | ADR-37 point 3; STATUS licence row | **In scope** (§6.8) |
| Privacy-mode UI | `sync/api/Types.kt:103-104`; F7:1616 | **In scope** (§7.1) |
| Emulator CI "in Phase 13"; T6 dynamic; T20 inventory; T4 | F7:1301; `INV:14,28,12`; LIM:66 | **In scope** (S10); runner KVM is an owner action (OA-1) |
| Device checklist steps 6–7 of Phase 9 (app lock, restore UI) | F9 §15.10; `faza9-dm.md:3677` | **In scope** (§12.6) |
| Reactions UI; "send again" for INDETERMINATE; reconnect counts; "the contact's clock looks wrong" | F9 §7.1, :1079, §8.6, :1100 | **In scope** (§6.4) |
| Phase 14's update screens, the "Install unknown apps" prompt, the alarms, the copy of F14 §2.6 and L10 | F14 §0.4, F-D8 | **In scope** (§6.7) |
| Prompt-mode foreground service; an upload service | F7 §5.4, ADR-20 consequences; F11 Q30 | **Deferred** (D26; Q16, Q17) |
| Card rotation (cut-off) with the P1 contact backup; the reduced reply card | F9 §12.5, Q27, Q70; LIM L7 rows | **Deferred** to a separate protocol design (Q19) |
| Invite v3 (a card inside the invite) | F9 Q32, X-13; ADR-05 note | **Deferred** (Q19) |
| Opt-in read receipts (`read_upto`) | F9 Q8 | **Not built** (Q18) |
| Flags, quarantine, strikes, exclusion lists, verified channels | F10 Q15, ADR-13 (P1) | **Deferred** to an engine design (Q19) |
| The deniable reveal | F10 Q35 ("designed with Phase 13's reveal UX") | **Deferred** to a protocol design; Phase 13 ships the warning (Q19) |
| In-app media capture | F11 Q15 | **Deferred**; the camera serves QR only (X-U10) |
| Crash-report transport | FR-8.11; ADR-06 | **Local part in scope**, transport deferred (Q20) |
| The alarm under Doze (A-2) | Phase 9 review A-2 | **Owner** (recorded, §17) |

### 1.4 Non-goals and deferrals (each with the constraint that decides it)

| Item | Status | Constraint |
|---|---|---|
| Card rotation, contact backup, Invite v3, reduced reply card | separate protocol design before Phase 15 (Q19) | new registrations and card indices are relay-visible; they reopen T27, T31, T32 |
| ADR-13 governance (flags, quarantine, strikes) | engine design with the channel engine, then its UI (Q19) | Phase 10 reserved formats only (`faza10-forum.md:735`); P1 may be off in a labelled alpha (spec p.7) |
| Deniable reveal | protocol design (Q19) | changes `CH-REVEAL` and the first DM; the warning ships now |
| Read receipts, typing, delivery receipts | none | F9 D10, Q8; a reflex-free opt-in needs its own world |
| Prompt mode, upload FGS | a later ADR (Q16, Q17) | FGS type and cadence; battery unmeasured |
| Crash-report sending | designed with an operator endpoint (Q20) | no endpoint exists; a new onion service is Phase 14/15 work |
| Duress PIN | P2 | plan §6.5; LIM:40 |
| Bridges and pluggable transports UI | Phase 12 | ADR-16; `client-core/net` refuses obfs4, webtunnel, snowflake lines today (STATUS Phase 6 row) |
| History transfer in channels | not designed | F10 Q11 (approved "none") |
| App disguise, hidden icon | not designed | not in the plan; the APK name and package are visible anyway |
| Multi-device, device linking | P2 | plan §6.5 |
| Root or malware detection | never | LIM L1: the check runs on the attacker's system |

### 1.5 Contradictions between documents and how this design resolves them

1. **FR numbering.** The spec's table (p.8, read with `pdftotext -table`) numbers the randomized-subset rule FR-1.4, the invite payload FR-1.6, inviter eligibility FR-1.7 and the configurable biometric/PIN policy FR-1.8; the plan (plan:259-260) and LIMITE (LIM:31) cite them one lower, and the plan's FR-6.8 (KYC warning, plan:270) is the spec's FR-6.9. This design cites the spec's numbers and lists the errata (Appendix B.1, F-U1).
2. **What "lock" does.** F9 §2.5 and §13.7 say lock closes the DM context; with the default unbound keys (ADR-20 Q6, `AppDatabase.kt:16`) the context reopens at any process start, so a closed context in the live process only stops RECV and notifications. Resolution: X-U1 (standard curtain, strict keys and process exit).
3. **T24's "single approved module"** vs a Compose app whose text fields write the clipboard through `LocalClipboard`: resolved by replacing `LocalClipboard` at every window root (X-U2).
4. **ADR-27 point 5's ownership check** needs a clipboard read Android allows only to the focused app: X-U3.
5. **ADR-08's IME flag "on all fields"** vs the flag being a hint: secrets move to keypads (X-U4).
6. **The channel PQ sentence** (F10 §4.5) states that DMs are protected, which ADR-36 point 6 forbids before the model and the review: X-U11.
7. **"Startup update checks"** (FR-7.5) vs Phase 14's update runs (F14 X-D1): Phase 13 follows Phase 14; nothing happens at start.
8. **Phase 9's facade** (`Messaging.kt`) lacks what its own design promised the UI (`setListener`, names; F9 §13.2): built here (§3.6).
9. **NFR-10's p95** needs about 20 restore trials; a moderated round of 8–10 cannot produce it: the gate reports the median and the p95 only with ≥ 20 trials, otherwise "unverified" by the spec's measurement rule (p.12) (Q23).
10. **LIM L1 asks for keys "cu autentificare biometrică/PIN per deblocare"** (LIM:31) while ADR-20 Q6 keeps the key unbound by default: the strict mode is the opt-in that gives L1's row; the default stays ADR-20's (ADR-55).

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
| Invite links and the own contact link (bearer) | share screens | an invite burned; "may message me" handed to a stranger (L7-D25) |
| Payment instructions (subaddress, amount, deadline) | payment screen | ties a person to an invoice (E7, E15) |
| The app PIN | lock screen | defeats the curtain |
| Entitlement and update states, notification activity | banners, notifications | activity timeline |
| UI settings (HIGH mode, lock mode) | settings | tells an examiner what the user chose |

### 2.2 Leak channels, controls, residues (normative)

| # | Channel | Adversary (TM §3) | Control (section) | Residue (LIMITE L11) | Test |
|---|---|---|---|---|---|
| C1 | A person holding the unlocked phone | AD-8 without root | mandatory app lock, curtain before the first frame (§5.1) | the PIN is a UI gate; with root it is brute-forceable on the device (L11-U8) | T55 |
| C2 | Screenshots, screen recording, casting by apps or the OS | malware, MediaProjection clients | `FLAG_SECURE` on every window (§4.1) | a camera; a modified client; root (ADR-27); API 29–30 keyboards (L11-U2) | T10 |
| C3 | Recents thumbnails and task snapshots on disk | AD-8 | `FLAG_SECURE` + `setRecentsScreenshotEnabled(false)` | a placeholder snapshot is still written (`isRealSnapshot=false`, src) | T10 |
| C4 | Accessibility services | malware with accessibility access; services that lie about being tools | decor-level and leaf sensitivity on API 34+; the services screen and opt-in hiding below (§4.3) | everything on API 29–33; lying services on 34+; system tools (L11-U3) | T24 |
| C5 | Keyboards (third-party IMEs, cloud dictation, keyboard clipboard history) | IME vendor | IME flag; keypads for secrets; warning (§4.5) | the composer's text reaches the keyboard (L11-U5) | T24, EditorInfo test |
| C6 | Clipboard (other apps at paste time, keyboards, cross-device clipboard sync) | apps, IMEs | one sensitive helper, 30 s clear, no secrets (§4.4) | the 30-s window; keyboard histories; unconditional background clear can erase another app's newer clip (L11-U4) | T24 |
| C7 | Notifications (lock screen, listeners, wearables, history) | onlookers, listener apps | constant text, `VISIBILITY_SECRET`, no badge (§4.6) | the moment a notification appears equals a decryption moment (L11-U6) | T11 |
| C8 | Assistant, Content Capture, OEM screen AI | system and OEM | `FLAG_SECURE` (assist structure and Content Capture off for secure windows; on API 37 `setContentCaptureEnabled(false)` no longer works, developer.android.com behaviour changes 17) | OEM features not tested (L11-U1) | T10 device steps |
| C9 | Autofill services | password managers | autofill exclusion on the decor; secrets on keypads (§4.5) | manual autofill requests (src) | V-U6 |
| C10 | Shoulder surfing, cameras | bystanders | short timers, lock | always possible | — |
| C11 | Forensic examination of a seized phone | AD-8 with root, AD-12 | nothing outside SQLCipher and RAM (T54); wipe (§5.5); strict mode (§5.4) | settings and PIN-failure counter in SQLCipher; OS residues (L11-U10, L11-U11) | T54, T57 |
| C12 | Relays and the network observing UI-caused traffic | AD-1, AD-2, AD-4 | the closed list of §2.4; rate limits | app presence, including at the lock screen (L11-U12) | T53 |
| C13 | The user's own mistakes | — | plain-language disclosures, usability study (§8, §12.5) | understanding is not action | §12.5 |
| C14 | Hostile `ghost://` intents from other apps; link hijacking by apps claiming the scheme | malicious apps | strict parse, confirmation screen, QR in person recommended (§3.4) | a link opened elsewhere can be intercepted (L11-U13) | G-U11, JVM |
| C15 | Tapjacking and overlays | overlay apps | Android 12+ blocks touches from untrusted overlays above 0.8 opacity (developer.android.com, behaviour changes 12); `filterTouchesWhenObscured` on confirm screens (§4.1) | partial overlays below API 31 | V-U1 |

### 2.3 What each protection does on Android 10 … 17 (API 29 … 37)

Legend: **doc** = verified at developer.android.com or its Microsoft Learn mirror of the AOSP javadoc (2026-10-03); **src** = read in AOSP or AndroidX sources by the research and not re-read here; **S0** = to be measured (V-U checks, Appendix C.4).

| Protection | 29 | 30 | 31–32 | 33 | 34 | 35 | 36 | 37 | Never covers |
|---|---|---|---|---|---|---|---|---|---|
| `FLAG_SECURE`: screenshots and recordings by apps, ADB, MediaProjection; insecure displays | yes | yes | yes | yes | yes | yes (ADB `screencap` draws secure layers black, src) | yes | yes | camera, modified client, root (`LSPosed` modules), userdebug builds with `DISABLE_SECURE_WINDOWS` (src) |
| `FLAG_SECURE`: recents thumbnail replaced by the theme placeholder | yes (src) | yes | yes | yes | yes | yes | yes | yes | the placeholder file itself |
| `FLAG_SECURE`: IME window protected when its target is secure | **no** (src) | **no** | yes (src) | yes | yes | yes | yes | yes | — |
| `FLAG_SECURE`: Assist structure, Content Capture off | yes (src) | yes | yes | yes | yes | yes | yes | yes, and the only opt-out (doc) | app overrides of `onProvideAssistData` (banned) |
| `FLAG_SECURE` against accessibility screenshots by system tool services | — | — | — | — | — | — | from 16 QPR2 tools may capture secure layers (src, S0 V-U20) | same | — |
| `setRecentsScreenshotEnabled(false)` | — | — | — | yes (doc: "only affects … Overview"; the system may still screenshot elsewhere) | yes | yes | yes | yes | screenshots in other contexts (doc) |
| `accessibilityDataSensitive` / `isSensitiveData` | ignored | ignored | ignored (tool flag readable from 31, doc) | ignored | **enforced** for non-tool services (doc API 34) | enforced | enforced | enforced; with Advanced Protection, non-tool services are blocked outright (secondary sources) | services that declare `isAccessibilityTool` falsely (self-declared; Play policy only); tools; speech |
| `EXTRA_IS_SENSITIVE` on a clip | ignored | ignored | ignored | preview hidden (doc) | yes | yes | yes | yes | "does not change clipboard behavior" (src); keyboard histories |
| Clipboard read restricted to the focused app or default IME | yes (doc) | yes | yes; a toast when an app reads another app's clip (doc) | yes | yes | yes | yes | yes | the focused app, the IME |
| System clears the clipboard about 1 h after a copy | no | no | no | yes (doc "secure clipboard handling"; DeviceConfig-controlled, src) | yes | yes | yes | yes | — |
| `IME_FLAG_NO_PERSONALIZED_LEARNING` | hint | hint | hint | hint | hint | hint | hint | hint | an IME that ignores it (`EditorInfo` javadoc) |
| `VISIBILITY_SECRET` notification on a secure lock screen | yes | yes | yes | yes | yes | yes; content hidden during screen sharing (doc behaviour changes 15) | yes | yes | notification listeners; wearables; history |
| Untrusted overlay touches blocked | no | no | yes above 0.8 opacity (doc) | yes | yes | yes | yes | yes | — |
| `setUnlockedDeviceRequired` keys | buggy semantics, symmetric ops unrestricted ≤ 30 (doc) | same | bugs in 12–14 (doc) | bugs | bugs | fixed (doc) | yes | yes | not used (§5.1) |

The UI copy never says more than this table. The "Securitate" screen states the protections that apply on the user's own API level, from this table (§6.8).

### 2.4 UI-caused traffic: the closed list (normative; T53)

Everything not in this table causes **no** relay, issuer or mirror traffic and no change of a read schedule, session start or session end. Rendering, scrolling, opening a conversation, `markDisplayed`, `setConversationOnScreen`, previews, verification, safety numbers, blocking, accepting or rejecting a request, adding a contact, lock and unlock in standard mode, notifications and every status read are local.

| User action | Facade call | What becomes visible, and to whom | Declared in |
|---|---|---|---|
| Opening the app (any screen, the lock screen included) | `ProcessLifecycleOwner` ON_START → foreground session | relays see the foreground cadence (app open) | LIM L2.1 point 4; L11-U12 |
| Send, post, react, set a timer, retry, send again, reset a session, reconnect, revoke (P1) | `Messaging.*`, `Channels.*` enqueue | stores at the next pair events (HIGH: delayed U[0, 10 min]) | T19; F9 §11.1 |
| Expedite after a send (STANDARD only) | `SyncController.requestExpedite()` | the work lane wakes for due stores; no read event | `SyncController.kt:10`; F7:1400 |
| Create a channel, invite, accept, remove, leave, set policy, reveal, resync | `Channels.*` | commits, Welcome, join requests at pair events | F10 §7.7 |
| Send media | `sendMedia` | the upload burst | F11 §12.1 |
| Pause media download | Phase 11 switch | `M_0` listing stops (relay-visible) | F11:548, L9-M3 |
| Activate an invite | `Entitlement.activate` → `RedeemInvite` in the foreground | one issuer call (L3) | F8 §8.3; E3 |
| Invoice now, check now (STANDARD only) | `requestInvoiceNow`, `checkNow` | one issuer call each (L3) | F8 §11.2; E3 |
| Buy, claim a payout, create or revoke an invite | `startPurchase`, `claimPayout`, `createInvite`, `revokeInvite` | issuer calls in later quiet runs only | F8 §19.11 |
| Show the payment instructions | `paymentScreenShown` / `Hidden` | relay sessions close and stay held U[20, 60] min | F8 §19.11; E15 |
| Change the privacy mode | `setPrivacyMode` | read pages per event, send delays, slot days | ADR-20 point 3 |
| Check for an update, download it | `Updates.requestCheck`, `requestDownload` | mirror fetches on the `Update` scope | F14 §7.3 |
| Strict lock | process exit | the foreground session ends early | §5.4 |

### 2.5 The property the gate proves

For a device running the release build of the closing commit on a tested API level: (i) every window GHOST opens is secure from its first frame and none is made insecure (T10); (ii) no UI path writes message, post, media or secret text to the clipboard, another app, a drag, or a non-tool accessibility service on API 34+, and every clipboard write GHOST makes is sensitive and cleared within 30 s (T24); (iii) notifications carry a constant text (T11); (iv) only §2.4's actions cause traffic (T53); (v) the UI keeps no sensitive state outside SQLCipher and RAM (T54); (vi) locked means nothing composed (T55); (vii) no unbacked claim ships (T56); (viii) a wipe leaves §5.5's inventory (T57); and (ix) representative users complete the P0 journeys and understand the named disclosures (§12.5). It says nothing about a compromised device, about OEM builds outside the matrix, or about what a user does after understanding a warning.

---

## 3. Architecture (normative; ADR-53)

### 3.1 Module layout

| Module / package | Contents | May depend on |
|---|---|---|
| `:ui` `org.ghost.ui.shell` | `GhostRoot` (the window root: theme, IME interceptor, clipboard override, curtain), `Route`, `BackStack`, the route host, banners, the two-pane layout | Compose (BOM 2026.09.00), `activity-compose` 1.13.0 (`BackHandler`, `PredictiveBackHandler`), `lifecycle-runtime-compose` 2.11.0, `androidx.window` 1.5.0 (size classes), `core-ktx` |
| `:ui` `org.ghost.ui.protect` | `SecureActivity`, `SecureDialog` helpers, `SensitiveText` (value class), `SensitiveTextView` (the one unwrap site), `GhostTextField`, `ImeIncognito`, `SensitiveClipboard`, `PinPad`, `WordKeyboard` | the above |
| `:ui` `org.ghost.ui.design` | colour, type and shape tokens, components (buttons, banners, list items, state panels) | `material3` 1.4.0 |
| `:ui` `org.ghost.ui.qr` | `QrImage` (zxing encoder drawn on a `Canvas`), `QrScanner` (Camera2 preview on a `TextureView`, zxing decoder on `ghost-qr`) | `com.google.zxing:core` 3.5.4; platform `android.hardware.camera2` |
| `:ui` `org.ghost.ui.gateway` | the gateway interfaces, UI models and UI enums (§3.2); nothing else | `kotlinx-coroutines` (already shipped, 1.9.0) |
| `:ui` `org.ghost.ui.feature.*` | `onboarding`, `restore`, `lock`, `access`, `dm`, `channels`, `media`, `settings`, `security`, `update`, `about` | the packages above only |
| `:app` `org.ghost.app` | `GhostApp`, `MainActivity` (extends `SecureActivity`), `SyncWiring`, `MessagingWiring`, `AppDatabase` (existing roles unchanged) | every module |
| `:app` `org.ghost.app.ui` | gateway adapters, the `ghost-ui-io` executor, `ChangeHub`, `AppPresence`, `LockController`, `StrictLock`, `WipeController`, `GhostNotifier`, `SettingsStore`, `CrashCapture`, `KeystorePin` | `:ui` and the engines |

**Rules (gated).** `:ui` declares no `project(…)` dependency and names no `org.ghost.*` package outside `org.ghost.ui` (G-U5); it names no network, storage or file API (G-U5 reuses the lists of `kotlin-clearnet.sh` and G-DM1 and adds SQLite, `File` writes and `openFileOutput`). `:app` reaches a traffic-causing facade method only from the adapter files allowlisted for it (G-U5's half modelled on G-DM2). No new JNI function and no Rust code: Phase 13 is Kotlin only, and the closed native lists (G-R6 for `DmNative`, G-M6 for `MlsNative`, G-D5 for `UpdateNative`) are unchanged; the Kotlin analogue of a closed surface is the gateway list of §3.2, which G-U5 checks against the adapters. `ui-tooling` (previews) is declared only as `:app`'s `debugImplementation`, never in `:ui`: the `gate` build type resolves library modules to their debug variants (`matchingFallbacks`, `app/build.gradle.kts:51-56`), so a `debugImplementation` in `:ui` would put previews into the gate APK that the gate devices install.

### 3.2 Data flow, threads, unavailability

```
Composable ── intent ──▶ ScreenModel (main thread; StateFlow<UiState>)
                           │ suspend gateway call
                           ▼
            gateway interface (:ui)  ◀── implemented by ──  adapter (:app, org.ghost.app.ui)
                                                              │ blocking facade call on ghost-ui-io (2 threads)
                                                              ▼
                     Messaging · Channels · media · Entitlement · SyncController · Updates · IdentityBackup
ChangeHub ◀── content-free hints (MessagingListener, ChannelListener) ; status polls every 2 s while VISIBLE and unlocked
```

- **Gateways** (closed list, each method mapped to exactly one facade method or a local composition): `IdentityGateway` (create the database key, inspect and activate an invite, activation state, restore, mnemonic indices for display, backup challenge), `LockGateway`, `AccessGateway` (entitlement), `DmGateway`, `ChannelGateway`, `MediaGateway`, `UpdateGateway`, `StatusGateway` (sync and entitlement status), `SettingsGateway`, `WipeGateway`. UI models are `data class`es of UI enums, local ids and `SensitiveText`; no engine type crosses into `:ui`.
- **Threads.** Every adapter call runs on `ghost-ui-io` (a fixed pool of 2, wrapped as a coroutine dispatcher) and asserts its thread name (CS-U6); debug builds add StrictMode `penaltyDeath` for disk and network on the main thread (in `src/debug`, never shipped). The DM actor serializes its own calls (`DmActor.kt:199-216`); a long actor pass delays a UI read, never the reverse beyond one turn.
- **Unavailability.** A facade that is `null` (`GhostApp.messaging` before the first database open, `GhostApp.kt:77`) or that throws `IllegalStateException` (a stopped actor, `DmActor.kt:194`) maps to `Unavailable(STARTING)` and is retried at the next hint; `CRYPTO_UNAVAILABLE` and `NATIVE_MISSING` map to the states of §6.9. Adapters never cache a facade instance, because the stack is replaced when the database reopens (`MessagingWiring.kt:229-264`).
- **Hints.** `ChangeHub` is a `MutableSharedFlow<ChangeKind>` with `extraBufferCapacity = 64` and `DROP_OLDEST`, fed by `tryEmit` from the engine's thread (the listener must never block the actor, F9 §13.7); a lost hint is harmless because models re-query. Screen models conflate hints and re-query at most every 250 ms, with at most one read in flight each.
- **Polling.** `SyncController.status()` (it opens a read transaction), `Entitlement.status()` and `Updates.status` are polled every 2 s while the app is VISIBLE and unlocked, never otherwise. The UI's total read rate is bounded (at most about ten facade reads per second in the worst screen), which NI-U1 checks does not move a time-triggered step across a minute boundary (§12.3).

### 3.3 State holders and the unlocked session

- **`UnlockedSession`** is created by `LockController` at unlock (and during onboarding before a lock exists) and closed at lock: its coroutine scope is cancelled, every screen model and its `UiState` dropped, and the content composition replaced by the lock screen. The back stack (routes hold only local ids) survives a standard lock in memory; the strict lock ends the process.
- **Drafts** (the composer's text per conversation) are kept in memory across a standard lock and lost at a strict lock or process death; they are never persisted (F9 §7.3 crash table: "the draft lived in memory").
- **No saved state.** `SecureActivity.onCreate` passes `null` to `super.onCreate`, and `onSaveInstanceState` clears the bundle after `super` (T54; V-U16 checks AndroidX tolerates both). `rememberSaveable`, `SavedStateHandle`, `rememberTextFieldState` (it is saveable) and `@Parcelize` UI models are banned in `:ui` and `org.ghost.app.ui` (G-U6). Text fields use `remember { TextFieldState() }`.
- **`SensitiveText`** is a value class over `String` with `toString() = "SensitiveText(redacted)"`; its unwrap is called only in `SensitiveTextView.kt` (G-U3), which renders it with `isSensitiveData = true`. A reflection test fails if any UI model has a `String` property outside a reviewed allowlist (route and enum names).
- **The mnemonic** is an `IntArray` of 24 word indices, rendered from the constant BIP-39 list (`Bip39Wordlist.kt`), zeroed when its screen leaves; no `String` is built from the root (F-U4 removes the `String` of bits the current encoder builds, `Bip39.kt:29-36`).

### 3.4 Navigation and links

- **Back stack:** a `SnapshotStateList<Route>` in the session; `Route` is a sealed interface of plain objects and data classes (onboarding steps, `Restore`, `Home(tab)`, `Conversation(id)`, `ContactAdd`, `MyCard`, `Requests`, `SafetyNumber(id)`, `KeyChange(id)`, `ContactInfo(id)`, `ChannelList`, `Channel(id)`, `ChannelCreate`, `ChannelInvite(id)`, `ChannelAccept(link)`, `Members(id)`, `Reveal(id, member)`, `Access`, `Purchase(id)`, `PaymentInstructions(id)`, `Invites`, `Payout`, `Settings(section)`, `WhoSeesWhat`, `Accessibility`, `Backup`, `Wipe`, `Update`, `About`, `Licences`, `Crash`, `MediaViewer(id)`, `ViewOnce(id)`). Transitions by `AnimatedContent`; back by `PredictiveBackHandler` on the top route; nothing is written to a bundle.
- **Two panes** from a window width of 600 dp (`androidx.window` size class): conversation and channel lists beside their detail. Android 17 removes the opt-out from orientation and resizability rules on large screens for apps targeting API 37 (developer.android.com, behaviour changes 17), so every screen is resizable and rotatable (V-U24).
- **Links.** The launcher activity has `VIEW` filters for `ghost` with the hosts `invite`, `contact` and `channel` only (no `http` or `https`, no `autoVerify`; G-U11). The link is read once from the intent, bounded (≤ 1 024 characters), held in memory as a `PendingLink`, removed from the intent (`setIntent(Intent())`), and acted on only after unlock through a confirmation screen that shows its kind, version and short checksum (§4.7). Another app may fire any `ghost://` intent at GHOST and may claim the scheme itself (L11-U13); QR in person stays the recommended path (ADR-05).

### 3.5 Lifecycle: presence, lock timing, "displayed", "on screen", payment

- **`AppPresence`** = HIDDEN, VISIBLE (process started: `ProcessLifecycleOwner` ON_START, the signal sync already uses, `GhostApp.kt:154-158`) or INTERACTIVE (VISIBLE, `MainActivity` resumed, unlocked). Sync keeps using ProcessLifecycleOwner alone; the lock screen counts as visible, so the foreground session runs under it (Q31).
- **Lock timing:** `MainActivity.onStop` (not a configuration change) records `hiddenAt = SystemClock.elapsedRealtime()` in memory; `onStart` locks when `elapsedRealtime − hiddenAt ≥ timeout` (0, 60, 300 or 1 800 s; default 60 s, LIM:32) before the next frame, because a Compose state change made in `onStart` is applied before the frame that follows. A new process starts locked when a lock is configured. Round trips to the photo picker, the camera permission dialog or system settings count like any other hide (no grace, Q29).
- **"Displayed"** (`markDisplayed`, the recipient's countdown, F9 §10.3): an incoming message counts as displayed when its item is at least half visible for 500 ms in a conversation screen while INTERACTIVE; calls are batched every 500 ms. A notification, a list summary or a TalkBack read of a list never counts.
- **"On screen"** (`setConversationOnScreen`, F11 §6.5): the contact of the top route while INTERACTIVE; `null` at lock, at hide and on leaving the route.
- **Payment screen:** `paymentScreenShown(id)` at every resume of `PaymentInstructions(id)` while INTERACTIVE, `paymentScreenHidden(id)` at pause or when the route leaves (F8 §19.11; `Entitlement.kt:64-71`). No other screen calls `paymentInstructions`, whose read marks the purchase shown (`EntitlementEngine.kt:230-249`) and so ends `cancel` and `PAYMENT_READY`; G-U5 confines the call to the payment adapter.
- **Privacy mode at process start:** the mode is read from `ui_settings` on the sync runtime thread when the runtime opens the database, before any job or foreground session, with the mechanism `SyncWiring` already uses for the payment hold (`SyncWiring.kt:34-39`), so a job process obeys HIGH too (MC-U9).

### 3.6 Facade additions (normative; each re-runs its phase's gates)

| Module | Addition | Why | Gates and tests re-run |
|---|---|---|---|
| `:messaging` | `setListener(MessagingListener?)` with `fun interface MessagingListener { fun onChanged(kinds: Set<ChangeKind>) }`, `ChangeKind ∈ {CONTACTS, MESSAGES, REQUESTS, TRUST, OUTCOMES, STATUS}`, emitted after commits on the actor thread | live screens; designed in F9 §13.2, never built (`Messaging.kt:20-22`) | G-DM1 … G-DM7, `NotificationPortContractTest` pattern for the listener (enums only), the privacy worlds at PR scale |
| `:messaging` | `addContact(card, source, name: String?)`, `rename(contact, name: String?)`, `ContactView.name` | aliases; `dm_contact.name_env` exists (`Schema.kt:936`); F9 §13.2's signature | same |
| `:messaging` | `conversationSummaries(): List<ConversationSummary>` (contact id, live unread count, newest live message minute; **no text**) | lists and badges; pure queries over stored content, no new column (T33) | `DmSchemaIntrospectionTest`, `DmExpiredRowLint` (the expiry filter applies) |
| `:messaging` | `conversationTimer(contact): Timer?`; `MessageView.timer`, `MessageView.expireAtMinute`, `MessageView.myReaction`, `MessageView.peerReaction` | L7-D28's own-timer display; countdowns; reactions (FR-4.3) | same |
| `:entitlement` | `inspectInvite(text): InvitePreview` (version, expiry day, refusal reason; local, no state) | a confirmation before `activate` commits a trial | `TrialStepsTest`, T16 vectors |
| `:entitlement` | `openPurchases(): List<PurchaseView>` (id, pay-with, state; no amount, address or time) and `invites(): List<InviteView>` (index, expiry day, state) | resume a purchase after process death; list and revoke invites | the entitlement harness, `EntitlementSchemaConstraintsTest` |
| `:entitlement` | `activateGenesis(acknowledged: Boolean): ActivationResult`, refusing unless the build's genesis policy is on | FR-1.5's genesis path has no facade (`IdentityManager.kt:19`) | E6 stays declared; Q21 |
| `:identity` | `RootEntropy.toMnemonicIndices(): IntArray`, `IdentityManager.verifyBackupIndices(…)`, and the encoder and decoder rewritten over zeroed bit arrays (F-U4) | no `String` of the root in the heap | the Trezor vectors, `KeyDerivationTest` |
| `:app` | `GhostApp.createDatabaseKey()` (`DatabaseKeyProvider.getOrCreate()`, zero the returned array, then `onDatabaseKeyCreated()`); `restorePrivacyModeFrom(…)` beside `restorePaymentHoldFrom`; `DatabaseAccess.AUTH_BOUND` (a compile-time constant today, `AppDatabase.kt:16`) becomes the value read at process start from which envelope set exists, and the DM key wrappers receive the same value | the missing creator (`GhostApp.kt:161`); D18; strict mode (§5.3) | `MessagingWiringTest`, the `:app` JVM tests |
| `:sync` | `AndroidSyncController.restorePrivacyModeFrom(read: () -> PrivacyMode?)`, run on the runtime thread before any session, like `restorePaymentHoldFrom` | D18 | `:sync` suite, T19 tests |
| Phase 10 (coordination) | `ChannelView.unread`, per-post timer and expiry, a content-free `ChannelListener` (F10 §10.3 lists it) | the same needs as DMs | Phase 10's gates |
| Phase 11, Phase 14 | none: their facades (F11 §6.5, F14 §9.5) are consumed as designed | — | — |

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
- URLs, numbers and addresses in messages are plain text: no `Linkify`, `LinkAnnotation`, `LocalUriHandler`, `autoLink` or preview (G-U2; ADR-08). A user who needs a URL retypes it (L11-U15).
- No drag source (`dragAndDropSource`, `View.startDragAndDrop`) and no share (`ACTION_SEND`, `ACTION_SEND_MULTIPLE`, `ShareCompat`, `createChooser`) anywhere (G-U2; Phase 11's proposed G-M1 bans them as well, `faza11-media.md:1197`).
- **The composer** is a normal field (ADR-27 point 3): the user may paste into it; its copy and cut go through `SensitiveClipboard` because `GhostRoot` provides `LocalClipboard` (and the deprecated `LocalClipboardManager`) backed by it (X-U2; V-U5 confirms that Compose 1.12.1's text fields use the provided clipboard).

### 4.3 Accessibility sensitivity

- **Window level:** decor `ACCESSIBILITY_DATA_SENSITIVE_YES` on API 34+ for the activity and for every dialog and popup window (`SecureDialog`). Non-tool services then see no GHOST node at all; tools (TalkBack, Switch Access, Voice Access) see everything (`View.setAccessibilityDataSensitive`, API 34, "only allow interactions from AccessibilityServices with the isAccessibilityTool property set to true", developer.android.com via Microsoft Learn).
- **Leaf level:** `isSensitiveData = true` (Compose UI ≥ 1.9; "hiding this node and its generated AccessibilityEvents from other Accessibility Services that are not declared as accessibility tools", AndroidX `SemanticsProperties.kt`) on every message, post, caption, alias, pseudonym, safety digit, fingerprint, word, passphrase, PIN dot row, payment field and the composer. The leaf marking is what the JVM tests can see (the platform enforces only on 34+).
- **Announcements:** a new message is announced politely as "Mesaj nou" (a constant), never its text; no `liveRegion` on content (PM-U11).
- **Actions:** every long-press menu also exists as `customActions`; every icon has a content description; headings are marked; traversal order is set where the visual order differs.
- **Below API 34**, and on any level where an enabled service is not a declared tool: the screen "Cine poate citi ecranul" (§6.8) lists the enabled services (label, package, system or installed, declared tool from API 31) and offers **"Ascunde conținutul de toate serviciile de accesibilitate"**, which replaces content semantics with constant descriptions (`hideFromAccessibility` on content leaves). It is off by default and its copy says that a screen reader will then not read messages (Q8).

### 4.4 Clipboard (`SensitiveClipboard.kt`, the only writer)

| Item | Rule |
|---|---|
| What may be copied | an invite link, the own contact link, a channel invite link, a payment subaddress, the app's signer fingerprint; nothing else (a `CopyKind` enum) |
| Never | message, post or caption text, aliases, pseudonyms, the 24 words, a passphrase, safety digits, the PIN |
| Each write | `ClipData.newPlainText(label, text)` with `label` = 16 random hex characters (the ownership token) and `extras` = `{"android.content.extra.IS_SENSITIVE": true}` (the string key also works below API 33, developer.android.com, copy and paste) |
| Clear | after 30 s (`elapsedRealtime`), at lock and at wipe: with focus, `getPrimaryClipDescription()` (no paste toast, developer.android.com behaviour changes 12) and clear only if the label is ours; without focus, `clearPrimaryClip()` unconditionally (X-U3, Q10) |
| Process death inside the 30 s | the clip stays until Android 13+'s own clear (about 1 h) or, on API 29–32, until replaced (L11-U4) |
| Paste | only into the composer, the contact-link and invite fields; never into the PIN, word or passphrase keypads |

### 4.5 Keyboards and autofill

- **`ImeIncognito`:** `GhostRoot` wraps every window's content in `InterceptPlatformTextInput` (public in `PlatformTextInputModifierNode.kt`, AndroidX), whose interceptor wraps the `PlatformTextInputMethodRequest` and ORs `EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING` into `imeOptions` in `createInputConnection`. Composition locals reach dialog content, so one interceptor per window covers it (V-U4 confirms on AOSP's keyboard and Gboard). Compose's own `KeyboardOptions` has no field for the flag (`EditorInfo.android.kt` sets only action, ASCII, no-enter and no-fullscreen flags).
- **Keypads:** `PinPad` (10 digits, delete, confirm; no IME, no paste, no autofill; digits held in a `CharArray` zeroed after the check) and `WordKeyboard` (26 letters, delete, and suggestion chips from the BIP-39 list once the prefix is unique or after 3 letters; the chosen word is the list's constant; used for restore, backup verification and the channel passphrase). Both are ordinary Compose buttons, readable by TalkBack and usable by Switch Access.
- **Keyboard warning:** at the end of onboarding and in Settings, if the default input method (`Settings.Secure.DEFAULT_INPUT_METHOD`) belongs to a non-system package (V-U14), a one-time warning names it and says what it can see.
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
| Never notified | `PAYMENT_READY` (F8 §19.11), `ENTITLEMENT_NEEDED`, update offers, alarms: in-app only |
| Permission | `POST_NOTIFICATIONS` (API 33+, in T15) requested at the end of onboarding after a screen showing exactly what the notification will say; refusal is respected and shown in Settings |

### 4.7 QR codes and the camera

- **Encoding:** zxing `QRCodeWriter` (byte mode, margin 4) drawn module by module on a Compose `Canvas` (no `Bitmap`); error correction L for invite links (876 characters → version 21, F8:1769), M for channel links (552 characters → version 18, F10 §19.29.3), L for the 131-byte contact card and the 65-byte safety-number form (F9 §12.1, §8.4). While a code is shown the window's brightness is raised (`screenBrightness = 1f`, own window only).
- **Scanning:** in-app, on the `QrScanner` screen only, with `CAMERA` (in T15) requested at first use; Camera2 preview on a `TextureView` inside the secure window; YUV frames from an `ImageReader` decoded on `ghost-qr` by zxing `QRCodeReader` (`TRY_HARDER`); frames are never stored; the camera closes at leave, hide and lock. Each screen states which payload it expects (an invite, a card or link, a channel link, a safety-number code) and refuses others.
- **FR-7.7 display:** every link confirmation shows the kind, the format version and an 8-hex-digit check code `SHA-256(link)[0..4]`, which the two people can read to each other; a damaged code or an unknown version fails with a typed message and nothing is stored.
- **Fallbacks:** paste into the link field; a device without a camera (`android.hardware.camera` declared not required) uses paste only.

---

## 5. Lock, wipe, backup, restore (normative; ADR-55)

### 5.1 Two strengths of lock

| | Standard (default) | Strict (opt-in, Settings > Securitate) |
|---|---|---|
| Unlock with | the app PIN (6–16 digits on `PinPad`), or biometric (`BIOMETRIC_STRONG`) as a convenience | device authentication through the platform `BiometricPrompt` (`BIOMETRIC_STRONG \| DEVICE_CREDENTIAL` on API 30+, `setDeviceCredentialAllowed(true)` on API 29); requires a secure lock screen |
| At lock | the curtain; the unlocked session closes; the DM context, the database and sync keep running | `GhostApp.onLock()` (the DM context closes, `MessagingWiring.kt:347-350`), then `finishAndRemoveTask()` and process exit within 1 s |
| Keys at rest | Keystore-wrapped, usable without the user (ADR-20 Q6, `AppDatabase.kt:16`) | database, identity, DM content and state keys wrapped by authentication-bound Keystore keys (30 s validity after authentication, the existing wrapper's policy, `AndroidKeystoreWrapper.kt:52-62`) |
| Background | receipt, sweeps, owner steps, notifications continue (the job process and the UI process share the DM layer) | nothing: a job cannot open the database (`DatabaseAccess.mayOpen`, `AppDatabase.kt:22-23`), so no receipt, no notification, no physical deletion until unlock (expired messages are never shown, because every read filters expiry, F9 §10.7 point 4, but they stay on disk until the next unlocked sweep: L11-U9) |
| Protects against | someone holding the unlocked phone (C1) | also an attacker with the phone and no device credential, and memory of a dead process; not root on an unlocked device |
| Cost | none | no background messages; removing the device's screen lock **irreversibly invalidates** the keys ("The key is irreversibly invalidated if the secure lock screen is disabled or forcibly reset", Keystore javadoc via Microsoft Learn) → only a restore from the words, with every contact and message lost |

`setUnlockedDeviceRequired` is not used: symmetric operations were unrestricted up to API 30 and the javadoc lists bugs on Android 12–14 fixed only in 15 (Microsoft Learn mirror, 2026-10-03).

**State machine** (`LockController`, every legal and illegal transition a JVM test, CS-U2): `UNCONFIGURED` (onboarding before a PIN) → `UNLOCKED` (PIN set); `UNLOCKED` → `LOCKED` (timeout at `onStart`, timeout 0 at `onStop`, "Blochează acum", process start with a lock configured); `LOCKED` → `CHECKING` (PIN or biometric submitted) → `UNLOCKED` (match) or `LOCKED` with `failures + 1` and, from the fifth failure, `BACKOFF(retry_minute)` (30 s, then doubling to at most 1 h, persisted and rounded up to the minute, T33's rule); strict: `UNLOCKED` → `EXITING` → (process gone). The session (§3.3) exists exactly in `UNLOCKED` and `UNCONFIGURED`.

### 5.2 The PIN verifier (byte level)

```
K_pin   = Keystore HMAC-SHA256 key, alias "ghost.v1.pin-mac", non-exportable, StrongBox when present,
          no user-authentication requirement, created at the first PIN set
salt    = 16 bytes from SecureRandom, new at every set or change
input   = "ghost/v1/app-pin" ‖ 0x00 ‖ salt ‖ ASCII digits of the PIN
tag     = HMAC-SHA256(K_pin, input)                                  (32 bytes)
stored  = ui_lock(salt, tag, failures, retry_minute)                 (§10)
check   = MessageDigest.isEqual(HMAC-SHA256(K_pin, input'), tag); the digit array is zeroed after the call
```

Without the device's Keystore a copied database gives no PIN (each guess needs `K_pin`); with root on the device, guesses run at Keystore speed (V-U10 measures it; a 6-digit PIN is then a matter of minutes to hours) — declared (L11-U8), consistent with L1's non-goal. No automatic wipe after failures (duress is P2); the failure counter is a forensic artefact, reset at a successful unlock (L11-U8).

### 5.3 Strict mode: switching without losing data (crash-safe)

| Step | Action | A crash here leaves |
|---|---|---|
| R0 | require `KeyguardManager.isDeviceSecure()`; authenticate; show the cost (§5.1) and confirm | nothing changed |
| R1 | create the strict aliases (`*.strict`) with authentication required; write the file envelopes `db-key.v1.strict` and `root-entropy.v1.strict` beside the old ones | both envelope sets; the old ones still open the database |
| R2 | one SQLCipher transaction: re-wrap the DM content and state keys in `dm_self` (and every other device-key envelope another phase stores under "the database-key policy") under the strict aliases, and set `ui_settings.lock_mode = 1` | either all rows old and `lock_mode = 0`, or all new and `lock_mode = 1` |
| R3 | delete the old file envelopes, then the old aliases | strict envelopes only, or both |
| R4 | process exit | strict |

**At process start:** only old envelopes → standard; only strict → strict; **both** → open the database with the old envelope (still valid until R3) and read `lock_mode`: 1 → finish R3; 0 → delete the strict envelopes and aliases (roll back). Leaving strict mode is the same procedure in reverse, after device authentication. The enumeration test injects a crash at every step and statement over a software Keystore (CS-U3, MC-U5).

### 5.4 Strict mode at run time

- **Cold start:** strict is recognised by the strict envelope's presence (the database cannot be read before authentication); the lock screen shows the device-authentication prompt; on success, within the 30 s window, `GhostApp` opens the database for the foreground, unwraps the identity for the DM context and builds the stack; if the window lapses first, the prompt returns.
- **Lock:** as §5.1. Removing the task from recents leaves no placeholder thumbnail either.
- **Notifications:** none can be posted (nothing is decrypted in the background); the onboarding and settings copy says so before the switch.

### 5.5 Local wipe (crypto-shred first)

| Step | Action |
|---|---|
| W1 | the user reads what a wipe does and does not do (contacts' copies, relay copies until TTL, tokens and credits lost, identity recoverable only with the 24 words), re-enters the PIN (or authenticates in strict mode) and holds the button 3 s |
| W2 | on the `ghost-wipe` thread: `GhostApp.onWipe()` (the DM stack stops after the pass in flight, the alarm is cancelled; the sync controller cancels the periodic job and drops the stores; `GhostApp.kt:185-188`, never on the main thread) |
| W3 | delete the database-key and identity envelopes (`DatabaseKeyProvider.destroy()`, `IdentityManager.wipe()`, and their `.strict` twins): from here the database file is ciphertext nobody can open |
| W4 | delete every GHOST Keystore alias (`ghost.v1.secret-wrap`, the DM content and state key aliases, `ghost.v1.pin-mac`, the crash-report key, strict twins) |
| W5 | delete files: `databases/ghost.db` with `-wal`, `-shm` and `-journal` (the file is in `databases/`, not `no_backup/`, F9 §22.32 point 5); all of `noBackupFilesDir` (Arti state `tor/`, Phase 11's `m/`, Phase 14's `update/`, `crash/`); the contents of `filesDir` and `cacheDir` |
| W6 | cancel every notification; clear the clipboard unconditionally |
| W7 | `finishAndRemoveTask()`, process exit; the next launch is a fresh onboarding |

**Resumption (CS-U1):** in `GhostApp.onCreate`, before any wiring, if no database-key envelope exists but `ghost.db`, its WAL or any GHOST file beyond a fresh install's baseline (V-U18) exists, W4–W6 run silently first. A crash before W3 leaves an intact app; any crash after W3 is completed at the next start. **What remains** (T57, L11-U11): an empty app sandbox apart from the system's `code_cache`, the notification channel record, the OS's job and alarm histories (`dumpsys` "removal history", LIM:68), notification history if the user enabled it, relay copies until their TTL, and flash blocks below the file system.

### 5.6 Seed backup

- **When:** after `activationState() == ACTIVE` (a failed trial wipes the identity, F8 §8.3 step 4), never before. The 24 words are numbered in two columns, large type, `isSensitiveData`, under `FLAG_SECURE`, rendered from `toMnemonicIndices()`; no copy, no export, no QR, no file.
- **Verification (FR-1.4):** four positions from `IdentityManager.backupChallenge(4)` (`IdentityManager.kt:80`), entered on `WordKeyboard`; a wrong answer draws a new subset; there is no skip; onboarding stays incomplete (`ui_settings.backup_verified = 0`) and the main screens stay closed until it passes.
- **Later:** Settings > "Cuvintele de recuperare" shows them again after re-authentication, and offers the check again.
- **Copy** (§8.3): write on paper, keep offline, never photograph, never type them into another app or site; GHOST asks for them only at restore and in this check.

### 5.7 Restore

1. Welcome → "Restaurez din 24 de cuvinte" → **"Ce se întoarce și ce nu"** before any typing: back come the identity, the contact card and the safety numbers (ADR-33′); not back come contacts, conversations, sessions, access tokens and unused credits (E11), credits sent to invites above index 7 (only drops 0–7 are listened to for 5 weeks, LIM E11), channel memberships (each needs a new invite, and in a password channel the password, F10 Q48 (a)), media.
2. The database key is created (`createDatabaseKey`), then the 24 words are typed on `WordKeyboard` (each slot accepts only list words) → `Entitlement.restore(words)` (local, `Entitlement.kt:51`): `RESTORED`, `REFUSED_MNEMONIC` ("un cuvânt sau ordinea nu se potrivesc"), `ALREADY_ACTIVE`, `UNAVAILABLE`.
3. PIN, mode and notification steps as in onboarding (§6.2 steps 8–10).
4. **"Pașii următori"**: buy access (no token survived; until a pack's tokens are usable, hours to days, nothing can be sent), add contacts again by scanning their cards, then "Reconectează" (staggered over 48 h, F9 §8.6; progress shows counts only), ask channel owners for new invites.
5. **NFR-10 clock:** from the first key on the word screen to the home screen after the PIN is set (spec p.12: entry, validation and first local unlock).

---

## 6. Journeys and screens (normative)

### 6.1 Information architecture

- **Three destinations:** **Conversații** (DM list, requests, new contact), **Canale** (channel list, create, join), **Setări** (sections: Acces; Confidențialitate; Securitate; Despre; Ajutor; Șterge datele). Two panes from 600 dp.
- **Status chip** in the top bar: hidden when the transport is `READY`, otherwise the connection state (§6.9).
- **Banners**, one at a time by priority: (1) security alarms (`SCHEDULE_CONFLICT`, `ISSUER_MISMATCH`, `REFUSED_BY_RELAY`, update `CONFLICT`, update `UNSUPPORTED`); (2) a pending key change of any contact; (3) access (`ENTITLEMENT_NEEDED`, `PAYMENT_READY`, `PAYMENT_EXPIRED`, `PAYMENT_LOST`, `UPDATE_REQUIRED`); (4) connectivity (`UNAVAILABLE` after 30 s, `NATIVE_MISSING`, `NO_REPLICAS`); (5) information (an update is available).
- **Every list and detail screen has the same seven states:** empty, loading, ready, offline (transport not `READY`: content stays readable, sends queue), degraded (fewer than two operators, or a relay flag), locked (curtain), unavailable (`CRYPTO_UNAVAILABLE`, facade not yet open); "wiped" is not a state of a screen but a fresh onboarding.

### 6.2 J1: invite → identity (onboarding)

| # | Screen | Gateway calls (engine) | Traffic | States and copy |
|---|---|---|---|---|
| 1 | **Bun venit** | none | none | the build stage label ("Previzualizare pentru dezvoltatori", later "Alfa privată"; spec §3.1) and three limits: a compromised phone defeats GHOST (LIM:41); your provider sees that you use Tor (LIM L4); "rezistență, nu imunitate" (LIM:87). Choices: "Am o invitație", "Restaurez din cuvinte" (§5.7); "Bootstrap (genesis)" only where the build's genesis policy is on (Q21) |
| 2 | Pregătire | `createDatabaseKey()` → `onDatabaseKeyCreated()`; wait for the database to open (migrations) | none (the periodic job is scheduled at key creation, ADR-20 point 1) | loading; a Keystore or storage failure shows a typed error and a retry; nothing else is created before the key envelope exists |
| 3 | Invitația | scan (`QrScanner`), paste, or a pending `ghost://invite/` link | none | link via another app: "Linkul a trecut prin acea aplicație; ea îl poate vedea sau înlocui. Preferă codul QR, în persoană" (ADR-05, plan:191) |
| 4 | Confirmă invitația | `inspectInvite(text)` (local) | none | kind, version, expiry day, check code (§4.7); "se poate folosi o singură dată"; each `REFUSED_*` with its copy (§6.9) |
| 5 | Activare | `activate(text)` → `PENDING`; `RedeemInvite` in the foreground through `runUserIssuerCall`; `activationState()` polled | one issuer call over Tor (L3, E3) | "Conectare prin Tor, poate dura până la 3 minute" (bootstrap bound 180 s, RPC 60 s, ADR-19); transient failure: retried at each foreground (at most 40, LIM E3) and by a button (each try is an L3 sample, said in the button's help); `FAILED`: "Invitația a fost refuzată: folosită deja sau revocată. Identitatea creată a fost ștearsă." (F8 §8.3 step 4) |
| 6 | Cuvintele tale | `toMnemonicIndices()` | none | §5.6 |
| 7 | Verificare | `backupChallenge(4)`, `verifyBackupIndices` | none | §5.6; no skip |
| 8 | Blocarea aplicației | `LockGateway.setPin`, optional biometric | none | PIN typed twice; why it exists and what it does not do (L11-U8) |
| 9 | Mod de confidențialitate | `SettingsGateway.setPrivacyMode` → `setPrivacyMode` | changes pacing (§2.4) | STANDARD preselected; HIGH's consequences in plain words (§7.1) |
| 10 | Notificări | `POST_NOTIFICATIONS` request (API 33+) | none | a picture of the exact notification; "fără expeditor, fără text"; refusal is fine |
| 11 | Înainte să începi | `SettingsGateway.ackDisclosures(version)` | none | three cards (§8.3 DC-1 … DC-3); the keyboard warning if needed (§4.5); then home |

### 6.3 J2: payment (access)

| # | Screen | Gateway calls | Traffic | States and copy |
|---|---|---|---|---|
| 1 | **Acces** (Setări) | `status()` every 2 s while visible; `openPurchases()`; `invites()` | none | "Acces până la sfârșitul săptămânii …" (from `coverageEndWeek`), fresh credits, invites left; flags as banners (§6.9) |
| 2 | Cumpără | `startPurchase(XMR \| CREDITS)` | none now; `RequestInvoice` in a later quiet run | `null` → "Programul de prețuri al aplicației se termină curând: actualizează" (`UPDATE_REQUIRED`) or "Creditele nu ajung"; else "Factura vine automat în câteva ore"; STANDARD only: **"Cere factura acum"** (`requestInvoiceNow`) with "un apel imediat către serviciul de plată e un semnal de timp" (E3) |
| 3 | Factura e gata | the `PAYMENT_READY` flag (surfaced by the engine ≥ U[1 h, 6 h] after receipt, never a notification) | none | — |
| 4 | Înainte de plată | `requiredDisclosures(id)`; `acknowledge(id, all five)` | none | the five disclosures, each a short paragraph with its own tick (§8.3 DC-6 … DC-10); the button stays disabled until all five |
| 5 | **Instrucțiuni de plată** | `paymentInstructions(id)` (only here); `paymentScreenShown(id)` at every resume, `paymentScreenHidden(id)` at pause | relay sessions close now and stay held U[20, 60] min after the screen hides (F8 §19.11) | exact amount (XMR), subaddress (grouped, `isSensitiveData`), deadline (receipt + 24 h, local time), QR of the `monero:` URI; buttons **"Deschide în portofel"** (`ACTION_VIEW` on the URI; no wallet → explained), **"Copiază adresa"** (sensitive clip); "Plătește de pe alt dispozitiv sau mai târziu, fără GHOST deschis" (E15); "Sincronizarea e oprită cât e deschis acest ecran și 20–60 de minute după" |
| 6 | După plată | `openPurchases()`, `status()`; STANDARD only: **"Verifică acum"** (`checkNow`, never signs) | `checkNow`: one issuer call | "Plata se confirmă în cel mult 72 de ore; accesul devine folosibil de la o oră de activare, la câteva ore după" (F8 §19.11, E1); `UNDERPAID`: the outstanding amount and a top-up URI; `PAYMENT_EXPIRED`: whether the payment was seen, and "o plată întârziată nu se poate potrivi; fără rambursare" (E25); `PAYMENT_LOST`: what happened and that nothing can be recovered (E8) |
| 7 | Anulare | `cancel(id)` | none | offered only while no instructions were ever shown (`Entitlement.kt:32-36`) |
| 8 | Credite și plată referral | `claimPayout(address)`; `setAutoRenewWithCredits` | the claim in a later quiet run | "o subadresă nouă din portofelul tău, niciodată a unui exchange"; "o revendicare refuzată pierde creditele" (E21); E23 |
| 9 | Invitații | `createInvite(expiryDay)`, `invites()`, `revokeInvite(index)` | redemption in a later quiet run | the link shown once as QR and text, copyable (sensitive clip), with ADR-05's warning; revoke explains it burns the token |

### 6.4 J3: direct messages

| Screen | Gateway calls | Traffic | States and copy |
|---|---|---|---|
| **Conversații** | `contacts()`, `conversationSummaries()`; hints | none | alias (`SensitiveText`), trust badge, unread count, newest minute; **no message preview** (Q14); "Cereri (n)" entry; empty state explains cards and QR |
| Contact nou | scan (`QrScanner`, source `QR_IN_PERSON` → starts verified) or paste a `ghost://contact/` link (source `LINK` → unverified); `addContact(card, source, name)` | none (R-E1: adding is local) | `LINK`: "Aplicația prin care a venit linkul îl poate vedea sau înlocui; verifică numărul de siguranță"; each `AddContactResult` (§6.9) |
| Cardul meu | `myCard()` | none | QR in person first; "Copiază linkul" (sensitive clip) with: "cine are cardul tău îți poate scrie, pentru totdeauna" (L7-D25) |
| **Conversație** | `conversation(id, 50, before)`, `markDisplayed` (§3.5), `setConversationOnScreen` | none | bubbles: text, minute timestamp ("ora la minut e vizibilă corespondentului", ADR-08), state for outgoing (§6.9), the message's own timer when it differs from the conversation's (L7-D28), quote, reactions; a banner while `CHANGED` |
| Compunere | `send(id, text, quote)`; then `requestExpedite()` in STANDARD | stores at pair events | byte counter near 61 440 B; the first send to a `LINK` or request contact shows once: "Primul mesaj îi dă cardul tău complet" (L7-D25); `KEY_CHANGED` opens the key-change screen |
| Mesaj — acțiuni | `retry(id)` (FAILED, before the deadline); "Trimite din nou ca mesaj nou" for INDETERMINATE (F9:1079); `react(id, target, g)` | stores | "Trimis" means stored on relays, not read (F9 D10); no copy, share or forward |
| Timer | `conversationTimer(id)`, `setTimer(id, t)` | one TIMER_SET store | values off, 5 min, 1 h, 1 d, 7 d (default), 30 d; §7.2 copy |
| **Schimbare de cheie** | `pendingSafetyNumber`, `verifyKeyChange(id, scanned)`, `acknowledgeKeyChange(id)` | none | "Mesajele tale nu pleacă și ale lui sunt ținute până decizi (cel mult 30 de zile)"; paths: scan in person, read the 60 digits by voice, or accept without checking (a separate, explicit confirmation stating that nothing was verified); undecided past the bound loses held messages (L7-D17) |
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
| Invită | `createInvite(id, expiryDays ≤ 7, password?)` | stores at passes | in a password channel only committers may invite (F10 Q46 (b)); the sponsor **retypes the passphrase** on `WordKeyboard` at each issue (Q50 (a)); the link appears **once** (QR and copyable text) and is not kept on the phone; a later void (a committer change or a password change) is told to the sponsor: "Spune-i celui invitat să nu folosească linkul vechi" (F10 §19.29.2 (3)) |
| Intră | `acceptInvite(link, password?)` | join request at passes | preview first; `PASSWORD_REQUIRED` → `WordKeyboard`, then a progress indicator while Argon2id runs (seconds on a low-end phone, F10 Q44); `WRONG_PASSWORD`; then "Așteaptă aprobarea unui moderator; poate dura ore" (`PENDING`); "Apari sub același pseudonim ca în orice canal anterior cu acest identificator" (F10:599); channel rules (LIM:141) |
| După intrare | `fingerprint(id)` | none | "Compară acest cod cu cel care te-a invitat, pe alt canal" (F10 §19.29.2 (3)); a mismatch: "Ești probabil într-o copie falsă a canalului. Părăsește-o și cere o invitație nouă" (F10 Q49 (a)) |
| Membri | `members(id)`, `remove`, `setPolicy` | commits | pseudonym fingerprints, roles, sponsor; owner actions (moderators, funders, transfer of rank 0, timer, name, who may invite — members or committers only, forced to committers in a password channel (F10 Q46 (b)) — password set, change or removal); after a removal: "Cel scos știe parola; schimb-o?" (F10:1965) |
| Părăsește | `leave(id)` | commit | a committer must resign or transfer first (F10 §6.6); the only committer with members names a successor (F10:691) |
| **Dezvăluie identitatea** | `reveal(id, member)` | a post | before the button: "Persoana aleasă va putea dovedi oricui (unui operator, unei instanțe, altor membri) că pseudonimul tău din acest canal ești tu. Ceilalți membri văd că ai făcut o dezvăluire, nu către cine." (F10 Q14, Q35, L8-C8); confirm with a hold |
| Resincronizare | `resync(id)` | a rejoin request | offered on `resync_needed` only, as a user action |

**6.5.1 The channel password (F10 §19.28, §19.29.3; Q42–Q50 approved).** At create or at "set password" the app draws 5 words uniformly from the 2 048-word BIP-39 English list already embedded (`Bip39Wordlist.kt`, hash-checked), ≈ 55 bits (Q44 (a)); the owner cannot choose a weaker one. Canonical form: the five lowercase words joined by one U+0020, NFKD, UTF-8 — the bytes Phase 10's facade receives (`CharArray` zeroed after the call, `faza10-forum.md:965`). The words are shown once with "Scrie-o pe hârtie și comunic-o membrilor în persoană; nu o copia"; there is no copy. Changing it voids old invites and moves the channel to a new address (+3 tokens, Q45 (a)). Restoring a device needs it (Q48 (a)). Because the same word list serves the seed, the passphrase screens use a distinct frame and title, and the app never asks for seed words after onboarding except in the backup check behind re-authentication (§5.6).

### 6.6 J5: media (on Phase 11's facade, `faza11-media.md:516-531`)

| Screen | Calls | Traffic | States and copy |
|---|---|---|---|
| Atașează | `PickVisualMedia` (system picker; on API 29 `ACTION_OPEN_DOCUMENT`), `sendMedia(id, source, caption, viewOnce)` | the upload burst | caption ≤ 1 024 B; `TOO_LARGE`, `TOO_LARGE_FOR_TIMER` (video ≤ 160 s, ≤ 85 s in 5-min and 1-h conversations), `UNSUPPORTED_SOURCE`, `UNDECODABLE`; "Fotografia e re-codată; metadatele (locație, model) sunt eliminate; originalul rămâne în galeria ta" (F11 §8, L9-M9) |
| Progres | `mediaState(id)` | — | fragments held of F; `failed` → `retryMedia` (≤ 3, before the deadline); "Trimiterea continuă în fundal și poate dura ore" (no upload service, D26) |
| Primire | `mediaState`, `mediaPreview` (only while on screen) | automatic download on `M`'s schedule (F11 D10) | awaiting, fetching (progress), complete, verified, `corrupt`, `incomplete` ("poate fi incomplet"), `undecodable`, `NOT_KEPT` (from a request: never opens) |
| Vizualizare | `openMedia(id)` → `MediaHandle` closed on leave | none | full screen, secure, Compose player (`media3-ui-compose`, `TextureView`); no save, share or copy |
| Vezi o dată (P1) | `openViewOnce(id)` | none | before opening: "Se poate vedea o singură dată pe acest telefon. Captura de ecran e blocată, dar oricine poate fotografia ecranul cu alt telefon." (F11 §11.2) |
| Pauză descărcări | Phase 11's switch | `M_0` listing stops | "Releele văd că ai oprit descărcările" (L9-M3) |

### 6.7 J6: update (on Phase 14's `Updates`, F14 §9.5, proposed)

| Screen | Calls | Traffic | States and copy |
|---|---|---|---|
| **Versiune și actualizări** | `Updates.status` | none | the installed version; `UpToDate`, `Available(name, code)`, `Downloading(received, total)`, `Ready`, `Installing`, `Installed`, `Stale(day)`, `Unsupported(floor)`, `Conflict`, `NoChannel`, `Failed(code)` |
| Verifică acum | `requestCheck()` | mirror fetches on the `Update` scope (F14 §7.3) | foreground only; "Verificarea trece prin Tor" |
| Descarcă | `requestDownload()` | APK ranges | progress; resumable |
| Instalează | `canRequestPackageInstalls()`; if false, `Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES` for GHOST; then `install()` → `PackageInstaller` session, the system's confirmation | none | "Android îți va cere să confirmi; GHOST nu instalează nimic fără tine" (F14 Q16) |
| Alarme | — | — | `Conflict` (red, persistent): "Am primit două versiuni diferite ale aceluiași manifest de actualizare: posibilă încercare de atac. Nu instala GHOST din alte surse; raportează."; `Stale` after 7 days; `Unsupported`: "Această versiune nu mai e acceptată; actualizează"; `NoChannel` after 14 days |
| Verifică aplicația | `signerCertificateSha256()` | none | the fingerprint grouped for reading aloud, copyable; "Compară-l cu amprenta publicată de verificatorul public" (F14 D21) |

Only after Phase 14's gate closes may the copy of F14 §2.6 appear, beside its residue; before that, the screen states only versions and states (§8).

### 6.8 Settings, security, about

- **Confidențialitate:** privacy mode (§7.1); notifications (on/off, count, lock-screen display); media download pause (§6.6).
- **Securitate:** app lock (change PIN, biometric, timeout 0/1/5/30 min), strict mode (§5.3); **"Cine poate citi ecranul"** (enabled accessibility services, §4.3, and the protections that apply on this Android version, from §2.3); the keyboard (§4.5); "Cuvintele de recuperare" (§5.6); "Verifică aplicația" (§6.7); "Diagnostic" (counts only: `MessagingStatus`, sync flags, never ids or times).
- **Despre:** version; **"Cine vede ce"** (§8.2); "Limite" (plan §7, LIM summaries); **Licențe** (renders `assets/THIRD_PARTY_NOTICES.txt` with the MPL-2.0 source offer, ADR-37 points 2–3); security contact (FR-8.6; the owner provides it, OA-6); the ADR-38 residue sentence ("Nu puteți verifica singuri codul sursă; vă bazați pe auditorii numiți și pe jurnalul public") once any claim is allowed.
- **Ajutor:** "Tor și țara ta" (LIM:159; text under legal review, OA-5; no location lookup); "Înainte să schimbi telefonul" (what a restore loses, §5.7); "Raportează o problemă" (local crash reports: review, delete; sending waits for Q20).
- **Șterge datele** (§5.5).

### 6.9 States catalogue (normative; every constant has Romanian and English copy and an action, CS-U4)

| Engine value | UI state and action |
|---|---|
| `TransportStatus.STARTING` | chip "Se conectează prin Tor"; after 30 s "poate dura până la 3 minute" (no percentage exists, `TransportPort.kt:7`) |
| `UNAVAILABLE` | banner after 30 s: "Nu ne putem conecta prin Tor. Verifică rețeaua și ora telefonului; în unele rețele Tor e blocat." → "Tor și țara ta" (the cause is not distinguishable, so both hints) |
| `BRIDGE_CONFIG`, `TRANSPORT_FAILED` | "Configurația de conectare nu e validă" / "Conexiunea a eșuat; reîncercăm automat" |
| `NATIVE_MISSING` | a full screen: "Instalarea e incompletă. Reinstalează GHOST din sursa oficială." No retry loop |
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
| Sends | leave when due (≤ 32 per pass); the UI expedites after a user send | each operation delayed once by U[0, 10 min]; stores only at the pair's events (≤ 8 per event) (ADR-20 point 3) |
| Reads | ≤ 4 pages per event | exactly 1 page per event (ADR-20 point 4) |
| New access tokens | usable from the activation slot | plus Geometric(1/2) extra days (LIM E1) |
| "Cere factura acum", "Verifică acum" | shown | hidden (`Entitlement.kt:26-30`) |
| Receipts, typing, delivery reports | none exist (F9 D10) | none |
| Volume | follows activity in both modes (no cover traffic; LIM L2.1 point 3) | same |

Copy (Romanian, DC-22): "În modul de confidențialitate ridicată, trimiterile pleacă cu o întârziere aleatoare de până la 10 minute, aplicația citește mai puțin la fiecare verificare, iar un acces nou devine folosibil cu câteva zile mai târziu. Volumul traficului rămâne vizibil: GHOST nu trimite trafic de acoperire." The per-namespace send-delay override is not exposed (DM and channel namespaces cannot turn it off, F9:1758). The mode persists in `ui_settings.privacy_mode` and reaches every process before its first session (§3.5, MC-U9).

### 7.2 Disappearing messages: what the UI says, and only that (ADR-27 points 7–11, ADR-32, F9 §10)

- The conversation's timer is a chip in the header (default 7 days); a change is a message both sides see ("Ai setat ca mesajele să dispară după 1 zi").
- A message whose own timer differs from the conversation's shows it (L7-D28).
- The countdown starts for the sender at sending and for the recipient at first display (§3.5's definition); a read message shows a coarse "dispare în ~3 h".
- Unread messages disappear at the latest when their relay copy expires; short timers lose messages for a recipient who stays offline (ADR-27 consequences, F9 R-15).
- DC-15, verbatim intent: "Mesajul dispare de pe acest telefon și de pe telefonul celuilalt dacă folosește aplicația oficială. Nu dispare din capturi făcute cu alt dispozitiv sau din copii păstrate de o aplicație modificată. Releele cinstite șterg copia criptată când îi expiră termenul."
- "Un timer diferit de 7 zile face conversația mai ușor de recunoscut de relee" (L7-D4; F9 Q39).
- In strict mode, deletion from disk waits for the next unlock; nothing expired is ever shown (L11-U9).

### 7.3 Media: ephemeral and view-once (F11 §11)

The copy of §6.6 and nothing stronger: view-once means at most one display **on this device**; screenshots are blocked; a camera, a second device, a modified client or a rooted phone are not; relay copies live until their TTL; the sender's original stays where it was picked from; decrypted pixels may linger in memory GHOST does not own (L9-M7).

### 7.4 Receipts and typing

None are built (F9 D10; Q18). "Trimis" always means "stored on relays", never "delivered" or "read"; DC-16 says the minute of each message is visible to the correspondent (ADR-08).

---

## 8. Disclosures and the claims register (normative; ADR-56)

### 8.1 Three layers

1. **Onboarding** (step 11 of J1, short and mandatory): DC-1 … DC-3.
2. **Just in time**, at the action that carries the risk: payment (DC-6 … DC-10, DC-23), sharing a link (DC-11), the first send to a link contact (DC-12), block (DC-13), key change (DC-14), timers (DC-15), reveal (DC-17), view-once (DC-18), notifications (DC-19), strict mode (DC-26).
3. **Reference:** "Cine vede ce" (plan §4 as a table), "Limite" (plan §7 and LIM summaries), "Cine poate citi ecranul" (§2.3 for the user's own API level).

### 8.2 "Cine vede ce"

One row per actor of plan §4 (relay, entitlement issuer, network or ISP, channel members, DM correspondent, the operator, the Monero network, an attacker with the unlocked phone) plus "cine are cardul tău" (L7) and "moderatorii unui canal" (F10). Three columns: **Vede** (always shown; a `LIMIT`, written as "vede cel puțin", never "doar"), **Nu ar trebui să vadă** (a `GOAL`, always printed with its status, today "obiectiv de design — neverificat încă"), **Dovada** (the evidence IDs and their status from the register). When an evidence ID enters the green list, the row's status changes; the sentence becomes a `CLAIM` only through the register (§8.5).

### 8.3 Mandatory disclosures (each a `LIMIT` in the register)

| ID | Disclosure | Source | Where |
|---|---|---|---|
| DC-1 | A compromised phone defeats GHOST; what reduces the damage | LIM:41 | J1 step 11; Securitate |
| DC-2 | A dedicated device (for example GrapheneOS) for high-risk profiles, and why | LIM:33 | J1 step 11 |
| DC-3 | Your provider sees that you use Tor; "rezistență, nu imunitate"; the regional guide | LIM:87, :159; plan §7 | J1 step 11; Ajutor |
| DC-4 | The 24 words: the only way back; never typed elsewhere; what a restore loses | FR-1.4; E11; F9 §8.6 | §5.6, §5.7 |
| DC-5 | What a wipe does and does not do | FR-4.7 by analogy | §5.5 |
| DC-6 | Paying from an exchange with KYC links you to an invoice; the Monero network sees the broadcast moment and the wallet's fingerprint; prefer your own wallet over Tor, at a random moment | FR-6.9; TM S13; E7 | J2 step 4 |
| DC-7 … DC-10 | No refund; the exact amount (a shortfall can be topped up in the window); no lock time; 24 h to pay, up to 72 h to confirm, pay from another device or later | `Disclosure.kt`; F8 §7.4; E15, E25 | J2 step 4 |
| DC-11 | A link sent through another app is seen, and can be replaced, by that app; prefer QR in person | ADR-05; plan:191; F9 §12.1 | every link screen |
| DC-12 | Your card means "may message me", for good; the first message gives the full card | L7-D25 | my card; first send |
| DC-13 | Block does not stop deposits, does not tell the contact, does not delete their copies | F9 §12.4; FR-4.7 | contact screen |
| DC-14 | What a key change and a safety number mean; held messages and their bound | FR-4.6; TM S12; L7-D17 | key change, safety number |
| DC-15 | Timers (§7.2) | ADR-27; L7-D4, L7-D28 | timer sheet |
| DC-16 | The minute of each message is visible to the other side | ADR-08 | conversation info |
| DC-17 | Channel pseudonyms; the reveal's transferable proof; the same pseudonym on a re-invite; classical cryptography in channels; the fingerprint check; every member, and every removed member, knows the password; funders are recognisable to relays | ADR-04; F10 Q14, Q35, Q49, Q7; F10:365, :599; §19.28.2 | channel screens |
| DC-18 | Media re-encoding and what survives; view-once limits; the pause is visible | F11 §8.5, §11.2; L9-M3 | media screens |
| DC-19 | What a notification shows; that listener apps and watches see it | §4.6; L11-U6 | J1 step 10 |
| DC-20 | Which accessibility services can read the screen on this Android version | §2.3 | Securitate |
| DC-21 | A third-party keyboard sees what you type in the composer | ADR-08 | keyboard warning |
| DC-22 | HIGH mode's effects; no cover traffic | ADR-20; LIM L2.1 | §7.1 |
| DC-23 | Sync stops while the payment screen is open and 20–60 min after | F8 §19.11 | J2 step 5 |
| DC-24 | Updates: no claim before Phase 14's gate; first installs and store updates are outside the updater's checks | F14 §2.6 | §6.7 |
| DC-25 | "Nu puteți verifica singuri codul sursă; vă bazați pe auditorii numiți și pe jurnalul public" beside any allowed claim | ADR-38 point 11 | with every `CLAIM` |
| DC-26 | Strict mode: no background messages; removing the screen lock destroys the keys | §5.1 | Securitate |
| DC-27 | The build stage ("previzualizare", "alfa privată", …) and that no privacy property is verified yet | spec §3.1; STATUS:26 | Bun venit; Despre |

### 8.4 Forbidden wording and the PQ rule

- **Never** (either language, any screen, store text or document): "100%" next to private, anonymous or safe; "complet anonim", "total privat", "nimeni nu poate", "imposibil de urmărit / citit / spart", "anonimat garantat", "untraceable", "unbreakable", "military-grade"; "open source", "sursă deschisă", "verificabil de oricine", "auditat" without a named report (ADR-38 point 11); "quantum-proof", "rezistent cuantic", "criptare end-to-end post-cuantică", "ratchet PQ", "protocolul Signal", "verificat formal" (ADR-36 point 6); for updates "sigur", "imposibil de falsificat", "martori independenți", "reproductibil" without a named attestation (F14 §2.6).
- **Post-quantum:** no post-quantum statement at all until ADR-36's model (M-1 … M-7) has run and the external review is published; then only ADR-36's sentence, for DMs. Channels carry DC-17's limitation sentence **without** a comparison with DMs (X-U11): "Mesajele din canale folosesc criptografie clasică; nu sunt protejate împotriva unui viitor calculator cuantic."
- **End-to-end encryption** and every "X cannot see Y" sentence are `CLAIM`s, blocked until their evidence is green (Phase 9 and 10 gates, the Phase 15 audit); today the UI does not say them.
- A negated phrase ("GHOST nu este 100% privat") is allowed only through the reviewed allowlist of G-U8.

### 8.5 The register (format) and its gate (G-U8)

`ghost/android/ui/claims/claims.tsv`, one row per sentence, columns: `id` (the string resource id), `kind` (`LIMIT`, `FEATURE`, `GOAL`, `CLAIM`), `evidence` (comma-separated invariant, gate or report IDs, or `-`), `residue` (the id of the sentence that must accompany it, or `-`), `source` (document and line), and for `CLAIM` rows the Romanian and English text. The green list is `ghost/test-harness/privacy/claims-evidence.txt` (one evidence ID per line, each with the run that made it green; empty today). G-U8 fails when: a `limit_`, `goal_` or `claim_` resource has no row of that kind, or a row lacks either language; a `CLAIM` whose evidence is not entirely green appears in any `res/values*/strings.xml` of a release source set; a `goal_` string is rendered other than through `GoalText` (which prints the status); a forbidden phrase matches outside the allowlist `claims-allow.tsv` (id and reason). Before a distributed release the register carries the signed claim checklist of FR-8.7 (a release check, §14.3).

### 8.6 Copy rules

Romanian first, informal "tu" (LIM:41's voice); sentences of at most about 20 words; a term explained at first use (releu, Tor, card, număr de siguranță); "ș" and "ț" with comma below (U+0219, U+021B); numbers with units; local dates and times; no claim adjectives ("sigur", "anonim") about GHOST; a native editor reviews every string, and counsel reviews the payment, privacy and Tor-guide texts (OA-5).

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

### 9.3 Accessibility versus leakage (the trade-off, Q8)

A screen reader must read the text to the user, so any protection that hides text from every service also excludes blind users. The only mechanism that separates "assists a user" from "reads the screen" is the self-declared `isAccessibilityTool` flag, enforced by the platform from API 34 and backed only by store policy (Play rejects false declarations and Play Protect blocks them where it runs, developer.android.com blog 2025-12-11; on a device without Google Play services a sideloaded app can lie) and, on Android 17 with Advanced Protection, by blocking non-tool services (secondary sources, Appendix D).

| Option | What it does | Cost |
|---|---|---|
| A (default) | decor and leaf sensitivity: non-tool services see nothing on API 34+; tools see everything | none for users; nothing below API 34; a lying service still reads |
| B | hide content from all services, always | blind users cannot use GHOST; contrary to ADR-27 |
| C (default, opt-in) | A, plus the "Cine poate citi ecranul" screen and an opt-in that hides content from all services, offered when a non-tool or unknown service is enabled | a user who turns it on loses screen-reader reading of content |
| D | announce new content aloud (live regions) | bystanders hear messages; rejected; only "Mesaj nou" is announced |

Disclosed limits (DC-20): nothing is enforced on API 29–33; services that lie about being tools; system tools (from Android 16 QPR2, per AOSP sources read by the research, able to capture secure windows; V-U20); a screen reader's own cloud features (TalkBack 16.0 can send a screenshot of the screen to Gemini for description at the user's request, support.google.com, 2026-10-03); speech heard by others.

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
  lock_mode        INTEGER NOT NULL CHECK (lock_mode IN (0, 1)),                 -- 0 standard, 1 strict (§5.3 R2)
  lock_timeout_s   INTEGER NOT NULL CHECK (lock_timeout_s IN (0, 60, 300, 1800)),
  biometric        INTEGER NOT NULL CHECK (biometric IN (0, 1)),
  notif_mode       INTEGER NOT NULL CHECK (notif_mode IN (0, 1, 2)),             -- off, constant, constant with count
  notif_lockscreen INTEGER NOT NULL CHECK (notif_lockscreen IN (0, 1)),          -- 0 hidden (VISIBILITY_SECRET)
  theme            INTEGER NOT NULL CHECK (theme IN (0, 1, 2)),                  -- system, light, dark
  dynamic_color    INTEGER NOT NULL CHECK (dynamic_color IN (0, 1)),
  a11y_hide        INTEGER NOT NULL CHECK (a11y_hide IN (0, 1)),
  onboarding_step  INTEGER NOT NULL CHECK (onboarding_step BETWEEN 0 AND 11),
  backup_verified  INTEGER NOT NULL CHECK (backup_verified IN (0, 1)),
  ime_warned       INTEGER NOT NULL CHECK (ime_warned IN (0, 1)),
  disclosures_v    INTEGER NOT NULL CHECK (typeof(disclosures_v) = 'integer' AND disclosures_v >= 0)
);
INSERT INTO ui_settings VALUES (1, 0, 0, 60, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0);

CREATE TABLE ui_lock (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  salt         BLOB NOT NULL CHECK (length(salt) = 16),
  tag          BLOB NOT NULL CHECK (length(tag) = 32),
  failures     INTEGER NOT NULL CHECK (typeof(failures) = 'integer' AND failures BETWEEN 0 AND 1000000),
  retry_minute INTEGER CHECK (retry_minute IS NULL OR (typeof(retry_minute) = 'integer' AND retry_minute % 60 = 0))
);

CREATE TABLE ui_crash (
  crash_id   BLOB    PRIMARY KEY NOT NULL CHECK (length(crash_id) = 16),
  day        INTEGER NOT NULL CHECK (typeof(day) = 'integer' AND day >= 0),           -- a day index, nothing finer
  version    INTEGER NOT NULL CHECK (typeof(version) = 'integer' AND version > 0),     -- the versionCode
  report_env BLOB    NOT NULL CHECK (length(report_env) BETWEEN 29 AND 8220)            -- content-key envelope, ≤ 8 KiB of report
) WITHOUT ROWID;
-- Triggers: no DELETE on ui_settings; at most one ui_lock row; at most 8 ui_crash rows (the importer deletes the oldest first);
-- the REPLACE guards of F9 §13.6.
```

**The crash report** (FR-8.11's local half): the uncaught-exception handler writes, synchronously and at most 8 KiB, the exception chain as class names and frames (`class.method:line`) with no message, thread name, path or argument, into `noBackupFilesDir/crash/pending.bin` as `0x01 ‖ nonce(12) ‖ AES-256-GCM(K_crash, report, AAD = "ghost/v1/crash")`, `K_crash` a non-exportable Keystore key; the next start imports it into `ui_crash` under the content key and deletes the file. It is the UI's only file outside SQLCipher (declared in T54 and L11-U14); the T3 canary test covers it. Sending waits for Q20.

Nothing else of the UI is persisted: drafts, back stacks, scroll positions and screen states live in memory (T54).

---

## 11. Invariants (new T53–T57; changes to T3, T4, T6, T10, T11, T20, T24, T25)

### 11.1 New invariants (Romanian rows for INVARIANTS.md in Appendix B.2)

| ID | Invariant | Verification | Executable from |
|---|---|---|---|
| T53 | **UI-caused traffic.** Only §2.4's closed list of user actions causes relay, issuer or mirror traffic; no other UI event or state (opening a screen, scrolling, display, standard lock, notifications, status reads) changes a read schedule, a session's start or end, or what is sent | G-U5; the recording-gateway suite (every intent of every screen model against recording facades: the traffic-causing calls equal §2.4's row for that intent); twin worlds NI-U1 (the Phase 9 privacy world with a UI driver reading every facade method at the bounded maximum rate vs none: identical relay views, registrations in the same minute), NI-U2 (a conversation opened and displayed vs not), NI-U3 (payment instructions read vs not, apart from the declared hold) | Phase 13 (JVM) |
| T54 | **UI persistence.** The UI keeps nothing sensitive outside SQLCipher and RAM: the saved-state bundle is empty; no preference, DataStore or file except the declared transient crash file (encrypted); no sensitive value in a `toString` | G-U6; JVM bundle canary scan per screen; the `toString` reflection test; emulator sandbox inventory with canaries (Phase 11's scan extended) | Phase 13 (JVM, emulator) |
| T55 | **Lock.** While locked no content screen is composed; the lock decision precedes the first frame after a return; a new process starts locked when a lock is configured; in strict mode no GHOST process survives the lock | JVM state-machine and frame tests on a virtual clock; emulator (`uiautomator dump` shows only the lock screen; `pidof` after a strict lock) | Phase 13 |
| T56 | **Claims.** No `CLAIM` string reaches a release without its evidence in the green list; every `GOAL` is printed with its status; no forbidden phrase in either language | G-U8 with fixtures; a JVM test that parses every resource and the register | Phase 13 |
| T57 | **Wipe.** After a wipe: no key envelope, no GHOST Keystore alias, no database or WAL, no file under `no_backup`, `files` or `cache`, no scheduled job or alarm, no notification; an interrupted wipe completes at the next start | JVM crash enumeration over W2–W7 (every step and file operation); emulator `run-as` inventory and `dumpsys jobscheduler`, `alarm`, `notification`; device | Phase 13 |

### 11.2 Changes to existing invariants

| ID | Change |
|---|---|
| T10 | Made exact: every window the package opens (activity, Compose dialog, popup, menu, sheet, player) is secure from its first frame; G-U1's bans; API 33+ recents opt-out; on the emulator `dumpsys window` shows `SECURE` on every window of every scripted screen, ADB capture is refused (API ≤ 34) or black (API ≥ 35), and the recents snapshot is a placeholder (not "absent": it is written with `isRealSnapshot=false`, research src), each with a non-secure control; Phase 11's media-window rule (X-M11) is folded in |
| T11 | "Locked or not" (F9 Q19); one constant text and an optional count; hidden on the lock screen by default; no badge; `dumpsys notification --noredact` canary scan and the notification-history step on a device |
| T24 | The approved unit is `SensitiveClipboard.kt` plus the root that provides it as Compose's clipboard (X-U2); the clear is checked-if-ours with focus and unconditional without (X-U3); window-level and leaf-level sensitivity; the secrets have no system-IME field (X-U4); emulator dumps through a non-tool client (zero canaries) and a tool client (canaries present) on API 34+ |
| T3 | The canaries add aliases, message and post text, passphrase and seed words, the PIN, payment addresses; the scan adds logcat during every emulator suite, crash reports and bundles |
| T4 | Executed on the emulator in S10 (`bmgr` with the local transport; the archive scanned for canaries and for SQLCipher, envelope and Arti files) |
| T6 | The dynamic half runs in S10: the emulator with `-tcpdump`, Tor unreachable, every journey script exercised: zero non-Tor packets and zero DNS queries from the app |
| T20 | The device inventory runs on the emulator in S10 after a session and after a wipe; the UI's declared file (the crash file) is listed |
| T25 | The UI's "displayed" definition (§3.5) starts the recipient's countdown; in strict mode physical deletion waits for the next unlock (declared, L11-U9); unchanged otherwise |

---

## 12. Testing and the exit-gate argument

### 12.1 Tiers

| Tier | Runs | Proves | Cannot prove |
|---|---|---|---|
| JVM | every push, in the `android` job (Robolectric 4.17, SDK 35 by default, SDK 29, 33 and 34 for version-gated cases; JDK 17) | window flags at creation, toolbars, semantics, clipboard on a virtual clock, bundles, lock frames, state machines, recording gateways, twins, crash enumerations, the state catalogue, semantic snapshots | what the platform does with a flag (capture, enforcement, recents), real keyboards, real Keystore |
| Emulator | nightly and on dispatch (`ui-emulator.yml`), AOSP x86_64 images API 29, 33, 35, 36 and `google_apis` 37.0 (no AOSP 37 image exists, `sys-img2-3.xml`, 2026-10-03) | §12.3: platform behaviour of every protection, ATF checks, journeys on the loopback transport, T4, T6, T20, T57 | OEM builds, hardware Keystore, real Tor latency, humans |
| Devices | two phones at the phase's close (OA-2), signed checklist (§12.6) | hardware keys, OEM screen features, TalkBack walkthroughs, real QR scanning | — |
| People | two moderated rounds (§12.5) | completion, critical errors, comprehension, NFR-10 | long-term behaviour |

Robolectric's `android-all-instrumented` jars are resolved through Gradle and pinned in `verification-metadata.xml` and run offline (`robolectric.offline`, `robolectric.dependency.dir`; robolectric.org configuring page), never downloaded at test time; SDK 36 and 37 under Robolectric need JDK 21 (Robolectric 4.16 notes), which CI does not use (ADR-34), so API 36 and 37 are covered on the emulator only.

### 12.2 JVM suites (in `:ui` and `:app` test sources)

- **Protection suite:** window flags of the activity and of every dialog, popup, menu and sheet at creation (PM-U1 … PM-U3); a spy `TextToolbar` that must see no `showMenu` on a long press over content (PM-U4); a semantics walk that finds no `CopyText`, `CutText` or `SetSelection` action and finds `isSensitiveData` on every node that carries a canary (PM-U5, PM-U8, PM-U9, PM-U22, PM-U25); a clipboard spy on a virtual clock (sensitive extra on every write, clear at 30 s and at lock, no write for secrets; PM-U6, PM-U7); `EditorInfo` captured from every editor, flag set (PM-U23); the saved bundle of every screen scanned for canaries after `onSaveInstanceState` (PM-U14, PM-U15); notifications through the notification-manager shadow (PM-U12, PM-U13); lock frames on the virtual `mainClock` (PM-U19, PM-U20); live regions carry constants only (PM-U11).
- **Recording gateways (T53):** every intent of every screen model runs against recording facades; the set of traffic-causing calls per intent must equal §2.4 (PM-U16, PM-U17); a display-semantics test checks what counts as "displayed" (§3.5; PM-U18).
- **Twins:** NI-U1 … NI-U3 on the Phase 9 privacy world (`dmworld`, production triggers, §22.36 of F9) at PR scale, with the UI driver as an extra participant.
- **Semantic snapshots:** for each screen × {ro, en} × {light, dark} × font scale {1.0, 2.0}, the unmerged semantics tree serialised (role, resource text, flags, actions, size class; sensitive text replaced by a token) and compared with committed goldens; text diffs are reviewed like code.
- **Pixel goldens** (informative, Linux CI only, fonts differ by OS): Robolectric native graphics `captureToImage` for about 30 key screens, compared with a small tolerance by a comparator in test code (no new dependency).
- **Accessibility arithmetic:** every clickable node ≥ 48 dp; every token pair meets its contrast ratio; no visual text overflow at font scale 2.0.
- **Crash enumerations:** the wipe (W2–W7) and the strict rewrap (R1–R4) over an in-memory file system and a software Keystore port (CS-U1, CS-U3; MC-U3 … MC-U5).
- **Catalogue and limits:** reflection over every mapped enum (CS-U4, MC-U7); every limit refused before a call (CS-U5, MC-U10); adapters on `ghost-ui-io` only (CS-U6, PM-U26).

### 12.3 Emulator suites (`ui-emulator.yml`, judged by `ui-emulator-check.sh`: exact test counts, zero skipped, every report line present; not run is red)

| Suite | Method |
|---|---|
| T10 | for each scripted screen (and its dialogs, sheets, menus): `dumpsys window windows` → every window of the package has `fl=… SECURE`; `screencap` refused on API ≤ 34 and black inside the app's bounds on ≥ 35 (a JDK program checks uniformity); the recents snapshot (`adb root`, `/data/system_ce/0/snapshots`) not real or uniform; each check repeated on a control activity without the flag in the test APK, which must capture (V-U1) |
| T24 | accessibility dumps through a non-tool `UiAutomation` (API 34+; or, if V-U3 finds that unusable, a test-only service declaring `isAccessibilityTool=false`): zero canary nodes; through the default (tool) client: canaries present; clipboard on the real clock with the app in the background: cleared within 30–35 s; IME flags read from `dumpsys input_method` |
| T11 | a scripted DM receipt through Phase 9's loopback transport seam → the real `GhostNotifier` → `dumpsys notification --noredact` scanned for every canary; visibility and badge fields |
| T55, T57 | background past the timeout (0 and 60 s), return, dump; strict lock then `pidof`; wipe then `run-as` inventory and `dumpsys jobscheduler`, `alarm`, `notification` |
| ATF | `enableAccessibilityChecks()` (Compose ≥ 1.8, `ui-test-junit4-accessibility`) over every screen on API 35: zero errors |
| Journeys | J1–J6 scripted end to end over the loopback transport and the model peers of the Phase 8 and 9 harnesses (model issuer, model relays); J6 against Phase 14's model mirror once it exists |
| Process death and Doze (FR-7.3) | `am kill` at every step of every journey script, then relaunch: the app is locked when a lock exists and resumes from engine state alone (the onboarding step in `ui_settings`, `openPurchases`, the activation state), drafts lost as declared; `dumpsys deviceidle force-idle` during a pending send: nothing is lost, the notification arrives after the maintenance window |
| Earlier phases' debts | G-DM5 and the release smoke test on the R8 graph that now has callers (Phase 9 review A-4); T4 (`bmgr`); T6 dynamic (`-tcpdump`, Tor unreachable); T20 inventory |

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
| PM-U16 | `requestExpedite()` on opening a conversation | G-U5; recording gateways; NI-U2 |
| PM-U17 | a status screen reads `paymentInstructions` | G-U5; recording gateways (the shown flag); NI-U3 |
| PM-U18 | `markDisplayed` for every fetched message | display-semantics test; the T25 countdown case |
| PM-U19 | content composed for one frame at `onStart` | frame test |
| PM-U20 | a new process starts unlocked | process-restart test; emulator |
| PM-U21 | the strict lock does not exit | emulator `pidof` |
| PM-U22 | `Linkify` on message URLs | G-U2; semantics walk (no link actions) |
| PM-U23 | the IME interceptor removed | `EditorInfo` test; G-U4 |
| PM-U24 | a blocked `CLAIM` string shipped | G-U8 |
| PM-U25 | message previews in the conversation list | semantics canary walk |
| PM-U26 | a facade call on the main thread | adapter thread assertion |
| MC-U1 | PIN failures not persisted | state-machine restart test |
| MC-U2 | no back-off | state-machine test |
| MC-U3 | files deleted before the key envelope | wipe crash enumeration |
| MC-U4 | leftovers not finished at start | wipe resumption test; emulator |
| MC-U5 | a crash between R2 and R3 leaves both wrappings live | rewrap crash enumeration |
| MC-U6 | onboarding completes without a verified backup | onboarding model test |
| MC-U7 | a state constant without copy | catalogue reflection |
| MC-U8 | the back stack resurrects a deleted contact's route | navigation test |
| MC-U9 | the privacy mode not applied in a job process | process-start test (HIGH before the first session) |
| MC-U10 | an over-limit body reaches the facade | limits test |

Thirty-six mutants. Reports carry `ui mutants: N run, N detected`, pinned by a report check as `dm-report-check.sh` does, so a report cannot claim more than it ran.

### 12.5 Usability protocol (the owner can run it with 5–10 people; the rest is automated)

| Item | Rule |
|---|---|
| Rounds | **formative**: 5 participants after S4 (J1–J3 and restore), to find problems; **summative**: ≥ 8 participants on the release candidate, all journeys, to decide the gate (Nielsen: 5 users find most problems; quantitative claims need about 20, nngroup.com) |
| Participants | adults who read Romanian, recruited outside the team: mostly non-technical people who care about privacy; at least one older adult using large text; at least one person with a higher-risk profile (journalist, activist, lawyer); a screen-reader user if one can be recruited, otherwise an expert TalkBack walkthrough recorded as such |
| Setting | provided phones (a mid-range one and a low-end one, OA-2) with the RC build on stagenet; staging relays and issuer if deployed (OA-3), else the loopback build used by the automated journeys, recorded in the report; a stagenet wallet supplied for the payment task |
| Tasks | J1 activate an invite and back up the words; restore on a second phone (timed, NFR-10); J2 buy access up to "plata trimisă" and explain what happens next (token arrival takes hours: verified separately by the scripts); J3 add a contact by QR, send, change the timer, verify the safety number, handle a scripted key change; J4 join a password channel with a passphrase given on paper, compare the fingerprint, post; J5 send a photo, view a view-once item; J6 find the version and install an offered update |
| Measures | unassisted completion per task; critical errors; time on the restore task; comprehension questions after J1, J2, J3 and J4 (for example "Cine îți vede adresa IP?", "Ce se întâmplă dacă pierzi telefonul?", "Ce înseamnă «Trimis»?", "Ce poate face cel căruia i-ai dezvăluit identitatea?"); SUS (informative; 68 is the usual mean, measuringu.com) |
| Critical errors | finishing onboarding with words that do not restore; believing a KYC exchange is safe after the warning; accepting a key change believing nothing changed; believing "Trimis" means read; revealing an identity without knowing the proof is transferable; pasting a link received from a stranger as a QR-verified contact |
| Pass (gate) | per journey, ≥ 80 % unassisted completion (≥ 7 of 8); a critical error in at most one participant per journey; each comprehension item right for ≥ 75 %; NFR-10 median < 3 min; a failure means a fix and a re-test with ≥ 5 new participants on that journey |
| NFR-10 p95 | reported only with ≥ 20 timed restores (the spec's rule, p.12), otherwise "unverified" and completed in the private alpha (Q23) |
| Recording | no screen recording (`FLAG_SECURE` makes it black, and it would capture participants' input): a facilitator's notes, audio with consent, optionally a camera on the hands and phone with consent; recordings deleted 30 days after the report; a consent form reviewed by counsel (GDPR; OA-4) |
| Report | per task: completion, errors, quotes, problems by severity; signed by the facilitator; kept in `docs/usability/` without names |

### 12.6 Device checklist (two phones: one on API 34+ with a hardware Keystore, one low-end; signed)

1. **T10:** hardware screenshot, the system screen recorder, casting, Recents, the assistant and any "circle to search" or OEM screen-AI feature over every P0 screen, a dialog and the media viewer: black or blocked.
2. **T24:** TalkBack reads a message, the 24 words and a safety number; a test service that is not a tool reads nothing (API 34+); copying an invite link: the keyboard preview is hidden (API 33+) and the clipboard is empty after 30 s, also with the app in the background; the third-party keyboard warning.
3. **T11:** the lock screen with a new message (nothing shown by default), the shade (constant text), notification history.
4. **Lock:** timeouts, biometric, back-off; strict mode on, lock, background a day (no notification, as disclosed), unlock; strict mode with the screen lock then removed (the disclosed loss, on a throwaway install).
5. **QR:** an 876-character invite printed and on another screen, at 20–40 cm, on the low-end phone; a damaged code fails safely.
6. **Restore:** the NFR-10 timing.
7. **Wipe:** the inventory after wipe.
8. **Update:** the "Install unknown apps" prompt and the platform confirmation (with Phase 14's staging mirror).
9. **Phase 9 steps 6 and 7** (app lock, restore UI) now runnable.

### 12.7 Exit-gate evidence and argument

| Gate item | JVM | Emulator | Devices and people |
|---|---|---|---|
| T10 | flags at creation for every window kind; G-U1 | `dumpsys` on every window; capture refused or black; recents placeholder; controls | §12.6 step 1 |
| T24 | toolbar, semantics, clipboard, `EditorInfo`; G-U2 … G-U4 | non-tool and tool dumps; real-clock clear; IME flags | §12.6 step 2 |
| Usability | journey models, catalogue | journey scripts J1–J6 | §12.5 summative round; NFR-10 |

The argument: the static gates make the forbidden constructions absent from the shipped sources; the JVM suites prove the shipped components set every flag and route every write as specified; the emulator suites prove the platform honours those flags on the tested API levels, each check paired with a control that fails without the flag; the device checklist covers what an emulator cannot (OEM features, hardware keys, real keyboards); the mutants prove each check can fail. The usability round is a human judgement with stated thresholds. Nothing here covers untested OEM builds or a compromised device, and the report says so.

---

## 13. Gates, CI, dependencies

### 13.1 Gates (each reads production source sets — `src/main`, `src/release`, and `src/gate` where it says so — through `source-text.pl`, fails on an empty scan, and has a negative fixture with an exact `self-test.sh` hit count and near-miss positives)

| Gate | Invariant | Rules |
|---|---|---|
| G-U1 `ui-secure-window.sh` | T10 | `FLAG_SECURE` set only in `SecureActivity.kt`, before any content call; every `Activity` subclass extends `SecureActivity`; banned: `clearFlags(`, other writes of window flags, `SecureFlagPolicy.SecureOff`, `Toast`, `PopupWindow`, `ListPopupWindow`, `android.app.Dialog`, `AlertDialog`, `DialogFragment`, `Presentation`, `WindowManager` `addView`, `Spinner`, `AutoCompleteTextView`, `PopupMenu`, `PlayerView`, `WebView`, `SurfaceView` without `setSecure(true)`, overrides of `onProvideAssist*`; merged release manifest: exactly one activity |
| G-U2 `ui-text-protection.sh` | T24 | banned everywhere: `SelectionContainer`, `textIsSelectable`, `setTextIsSelectable`, `ACTION_SEND`, `ACTION_SEND_MULTIPLE`, `ShareCompat`, `createChooser`, `dragAndDropSource`, `startDragAndDrop`, `Linkify`, `LinkAnnotation`, `LocalUriHandler`, `autoLink`; `ClipData`, `setPrimaryClip`, `ClipboardManager`, `LocalClipboard`, `LocalClipboardManager` only in `SensitiveClipboard.kt` and `GhostRoot.kt`; `SensitiveClipboard.kt` must contain the sensitive key, `clearPrimaryClip` and the 30 000 ms constant; the backup, restore, passphrase and safety-number packages never import the clipboard package. Shares one exemption file with Phase 11's G-M1 |
| G-U3 `ui-sensitive-text.sh` | T24, T3 | the unwrap of `SensitiveText` only in `SensitiveTextView.kt`; plus the JVM reflection test over UI models |
| G-U4 `ui-input.sh` | T24, ADR-08 | `BasicTextField`, `TextField`, `OutlinedTextField`, `BasicSecureTextField` only in `GhostTextField.kt`; `InterceptPlatformTextInput` present in `GhostRoot.kt` |
| G-U5 `ui-isolation.sh` | T53 | `ui/build.gradle.kts` has no `project(` dependency; `android/ui` names no `org.ghost.` package outside `org.ghost.ui`, no network, SQLite or file-writing API; in `:app`, the facade methods that cause traffic or must follow a user action (`requestExpedite`, `runUserIssuerCall`, `requestInvoiceNow`, `checkNow`, `paymentInstructions`, `paymentScreenShown`, `paymentScreenHidden`, `setPrivacyMode`, `reconnect`, `resync`, `requestCheck`, `requestDownload`, `install`) only from the files in `ui-traffic-callers.allow`, each with a reason (G-DM2's pattern) |
| G-U6 `ui-no-persist.sh` | T54 | in `android/ui` and `org.ghost.app.ui`: no `rememberSaveable`, `SavedStateHandle`, `rememberTextFieldState`, `Parcelize`, `getSharedPreferences`, `PreferenceManager`, `DataStore`, `openFileOutput`, `FileOutputStream`, and no `onSaveInstanceState` override other than `SecureActivity`'s |
| G-U7 `ui-deps.sh` | T7, ADR-06 | an artifact-level denylist (`androidx.browser`, `androidx.webkit`, `androidx.credentials`, `androidx.ads`, `androidx.compose.ui:ui-text-google-fonts`, `com.google.mlkit`, `com.google.android.gms`); test-only groups absent from `releaseRuntimeComponents`; the `androidx.startup` initializer set unchanged (the existing rule of `merged-manifest-lint.sh`) |
| G-U8 `ui-claims.sh` | T56 | §8.5 |
| G-U9 (`messaging-no-network.sh` widened) | ADR-20, X-U8 | the `kotlinx.coroutines`, `kotlin.coroutines` and `suspend` ban extended to `:sync`, `:storage`, `:identity`, `:entitlement`, `:network`, `:media` and `:app`'s `org.ghost.app` top package (all comply today) |
| G-U10 `ui-notifications.sh` | T11 | notification builders only in `GhostNotifier.kt`; banned styles, `RemoteInput`, `setNumber`, `Person`, shortcuts, bubbles, `VISIBILITY_PUBLIC`; title and text only from the allowlisted resource ids |
| G-U11 (`merged-manifest-lint.sh` extended) | T15m, T16 | exactly one exported component (the launcher) with `VIEW` filters for scheme `ghost` and hosts `invite`, `contact`, `channel`; no `http(s)` data, no `autoVerify`; permissions within T15 (Phase 14's `REQUEST_INSTALL_PACKAGES` when ADR-51 lands); `android.hardware.camera` not required |
| G-U12 `ui-l10n.sh` | R13-1 | every string in `values` and `values-ro` with the same placeholders; Romanian plurals with `one`, `few`, `other`; no literal user-visible string in composables |

`anti-placeholder.sh` bans the words "placeholder" and "hardcoded" in production sources, so GHOST's text fields use `label` and supporting text, never Compose's `placeholder` parameter (better for accessibility as well). `no-logging.sh` and `kotlin-clearnet.sh` already cover `android/ui`.

### 13.2 CI jobs

| Job | Trigger | Runs |
|---|---|---|
| `static-gates` (ci.yml) | every push | G-U1 … G-U12 and `self-test.sh` (fix first: the `dm-golden-lock` case fails on a shallow clone, F-U2) |
| `android` (ci.yml) | every push | `:ui` and `:app` JVM suites (Robolectric), semantic snapshots, the mutant report, T53 twins at PR scale |
| `ui-screenshots` (in `android`) | every push, Linux | pixel goldens (informative) |
| `ui-emulator.yml` (new) | nightly, dispatch, PRs touching `android/ui` or `android/app` | §12.3 on API 29, 33, 35, 36, 37 (google_apis); concurrency group; no other heavy job at the same time (F9 §22.32 item 11) |
| `dm-emulator.yml` | as today | the release smoke test on the graph with callers |

The emulator jobs need KVM: the runner user is not in the `kvm` group today (read-only check in the `ghost-runner` distribution, 2026-10-03; OA-1).

### 13.3 Dependencies and licences (closed source: only permissive licences in anything shipped)

| Coordinate | Licence | Shipped | Why | Gate changes |
|---|---|---|---|---|
| `com.google.zxing:core:3.5.4` (2025-11-11, no runtime dependency) | Apache-2.0 | yes | QR encode and decode (D23) | allowlist line `com.google.zxing` (ADR-57); verification metadata; G-L2 licence line |
| `androidx.media3:media3-ui-compose:1.11.0` (matching the pinned Media3) | Apache-2.0 | yes, with media | the player surface (D24) | Phase 11's G-M2 list gains `-ui-compose` |
| `org.robolectric:robolectric:4.17` and its `android-all-instrumented` jars | MIT (POM) | test only | JVM Compose tests | allowlist line marked test-only (the `org.xerial` precedent); G-U7 |
| `androidx.compose.ui:ui-test-junit4`, `ui-test-manifest`, `ui-test-junit4-accessibility` (BOM) | Apache-2.0 | test only | Compose tests; ATF checks | G-U7 |
| `androidx.test:core`, `runner`, `rules`, `androidx.test.ext:junit` | Apache-2.0 | test only | emulator suites (Phase 9 avoided them with a plain `DeviceRunner`; ATF needs them, Q25) | G-U7 |
| `com.google.android.apps.common.testing.accessibility.framework:accessibility-test-framework:4.1.1` | Apache-2.0 (S0 confirms) | test only | ATF | allowlist line, test-only |

**Not added:** Navigation 3 and Navigation Compose (D6), `lifecycle-viewmodel-compose`, `material3-adaptive`, `androidx.biometric` (the platform `BiometricPrompt` suffices; the AndroidX one needs a `FragmentActivity`), `androidx.appcompat` (D22), CameraX (D23), Hilt, Dagger or Koin (manual composition root, as `GhostApp` already is), icon artifacts, DataStore, Coil or Glide. Every coordinate added gets verification-metadata entries, and every shipped one a G-L2 line and a notice.

---

## 14. Slices, effort, exit-gate checklist

### 14.1 Slices (each ends green in CI; the Q defaults apply unless the owner objects)

| Slice | Content | Depends on | Exit condition |
|---|---|---|---|
| **S0a** evidence | V-U1 … V-U24 (Appendix C.4) on the API 29, 33, 35, 36 and 37 emulators and the two phones | OA-2 (phones); emulators run locally before OA-1 | every V-U result recorded in Appendix C with its consequence; any design change made in this document first |
| **S0b** gates and test infrastructure | the `:ui` module skeleton (`SecureActivity`, `GhostRoot`, one demo screen) so that the gates scan real sources; G-U1 … G-U12 with fixtures and exact `self-test.sh` counts; Robolectric pinned and offline; `ui-emulator.yml` and `ui-emulator-check.sh`; F-U2 fixed | — | `static-gates` green with the new gates; each gate fails on its fixture and on an empty tree |
| **S1** foundation | design system; `SensitiveText(View)`, `GhostTextField` with `ImeIncognito`, `SensitiveClipboard`, `PinPad`, `WordKeyboard`, `SecureDialog`; `QrImage`, `QrScanner`; shell (curtain, back stack, two panes); gateways, adapters, `ghost-ui-io`, `ChangeHub`, `AppPresence`; `SettingsStore` and migration UX; `LockController` (standard); `createDatabaseKey`, `restorePrivacyModeFrom` | S0b | the JVM protection suite green; the emulator T10 and T24 suites green on the demo screens on API 29 and 35 |
| **S2** identity and lock | J1 screens and restore; the `:identity` index API and F-U4; `inspectInvite`, `activateGenesis`; backup and verification; lock wiring (`GhostApp` callers); `WipeController`; the notification-permission step; DC-1 … DC-5 | S1 | J1 and restore scripts green on the emulator (loopback transport, model issuer); T55 and T57 green; an NFR-10 dry run |
| **S3** access and payment | J2 screens; `openPurchases`, `invites` | S2 | the J2 script green; the recording gateways prove the payment rules; NI-U3 |
| **S4** direct messages | the `:messaging` additions of §3.6; every J3 screen; `GhostNotifier`; `markDisplayed`; key change, safety number, requests, block, reconnect; G-DM5 and the release smoke test re-run | S2 | the J3 script green; T11 on the emulator; NI-U1, NI-U2; Phase 9's device steps 6–7 runnable. **The formative round follows** |
| **S5** channels | J4 screens on Phase 10's facade and its coordination items; the password flow; the fingerprint check | Phase 10's facade on `main` | the J4 script green with a password channel and a fingerprint mismatch |
| **S6** media | J5 screens on Phase 11's facade | Phase 11 approved and its facade on `main` | the J5 script green; media windows in the T10 suite |
| **S7** update, settings, disclosures | J6 on Phase 14's facade; Settings, Securitate, Despre, Ajutor; "Cine vede ce"; the claims register and G-U8 live; licences; local crash reports | S4; Phase 14's facade for J6 | G-U8 green over the real register; the licences screen renders the packaged asset; the J6 script green (or the recorded fake, Q39) |
| **S8** strict mode | rewrap R0–R4, device authentication, process exit | S2 | the rewrap crash enumeration green; the emulator strict suite; device step 4 |
| **S9** accessibility, localisation, layout | ATF, font scale 2.0, Romanian and English complete (G-U12), TalkBack walkthrough, two panes, edge to edge | S4, continuing | ATF zero errors on API 35; the semantic snapshots for both languages committed |
| **S10** evidence | three consecutive green nightlies on every API level; mutants N of N; T4, T6 dynamic, T20; the device checklist | S4 … S9 | §14.3 items 1–12 |
| **S11** summative round | §12.5 on the release candidate, fixes, re-tests | S10, OA-3 … OA-5 | §12.5 thresholds met |
| **S12** documents | Appendix B applied: INVARIANTS rows, LIMITE L11, THREAT_MODEL, plan errata, STATUS, ADR files and index, notes in F9, F10, F11, F14 | S11 | committed with the closing commit |

### 14.2 Effort (honest, for the plan's team of 5–6)

| Slice | Person-weeks |
|---|---|
| S0a, S0b | 3 + 3 |
| S1 | 6 |
| S2 | 6 |
| S3 | 3 |
| S4 | 7 |
| S5 | 6 |
| S6 | 3 |
| S7 | 4 |
| S8 | 2.5 |
| S9 | 4 |
| S10 | 4 |
| S11 (two rounds, analysis, fixes) | 5 |
| S12 | 1 |
| **Total** | **≈ 57.5 (range 50–62)** |

Staffing as plan §6.4 (a lead, two Android engineers, a Rust engineer and a half, QA, part-time SRE): about 4.5 people can work on this phase at once (the Android engineers and QA full time, the lead and one Rust engineer half time on facade additions, gates and CI). **10–13 calendar weeks**, of which the waits for Phases 10, 11 and 14's facades and the human study are not compressible; the plan's 4–6 weeks did not count five facades, about 55 screens with seven states each, twelve gates, the emulator matrix and two moderated rounds (X-U6, Q26). A copywriter-designer is not in the plan's team; the estimate assumes the Android engineers write the first copy and OA-5's editor reviews it (R-U11). **Calibration:** Phase 9's implementation slices landed in nine days against a 10–12-week estimate when built by agents, while its exit gate stayed open on owner actions and CI capacity (F11 D24 and §17.2; STATUS). UI implementation may compress the same way; the device checklist, the usability rounds, recruiting, legal review and the facades of other phases will not, and they date the gate. No date is promised.

### 14.3 Exit-gate checklist (all on the closing commit)

1. G-U1 … G-U12 green, `self-test.sh` green with every new case.
2. JVM suites green with 0 skipped: protection, recording gateways, twins NI-U1 … NI-U3, snapshots, crash enumerations, catalogue, limits.
3. `ui-emulator.yml` green on three consecutive nights on API 29, 33, 35, 36 and 37 (`google_apis`), 0 skipped.
4. T10 evidence in all three tiers (§12.7).
5. T24 evidence in all three tiers.
6. T53, T54, T55, T56, T57 executable and green (Q36).
7. `ui mutants: 36 run, 36 detected` (or the registered count), checked by the report gate.
8. The device checklist (§12.6) signed for both phones.
9. The summative usability report meets §12.5's thresholds; NFR-10's median recorded (and p95 if ≥ 20 restores).
10. G-DM5 and the release smoke test green on the R8 graph that ships with the UI.
11. T4, T6 dynamic and T20 executed on the emulator, results recorded in INVARIANTS.
12. ATF zero errors on API 35; the TalkBack walkthrough recorded.
13. The claims register reviewed (OA-5) and the licences screen present (ADR-37 point 3).
14. Documents of §14.1 S12 applied.
15. `static-gates` and `android` green on the closing commit (F-U2 fixed).

---

## 15. Risks

| ID | Risk | Likelihood / impact | Mitigation | Residue |
|---|---|---|---|---|
| R-U1 | Phase 10, 11 or 14 facades arrive late or change | high / high | gateways and fakes decouple the screens; S5–S7 wait (Q37, Q39) | the gate date follows theirs |
| R-U2 | The summative round fails on the seed or the payment | medium / high | the formative round after S4; copy iterations; re-test rule | schedule |
| R-U3 | Decor-level sensitivity does not reach Compose nodes or dialogs on some version | medium / medium | V-U3 in S0a; leaf marking stays as the second layer | declared per version |
| R-U4 | OEM capture features ignore `FLAG_SECURE` | low / high | device checklist; disclosure | L11-U1 |
| R-U5 | Strict-mode users lose data by removing the screen lock | medium / high | DC-26 before the switch; a hold-to-confirm; restore remains | declared |
| R-U6 | The mandatory PIN annoys users into uninstalling | medium / medium | biometric convenience; timeout choices (Q5) | — |
| R-U7 | Robolectric on JDK 17 stops at SDK 35 | certain / low | API 36–37 on the emulator and devices | — |
| R-U8 | Emulator CI on the owner's laptop runners is slow or flaky | high / medium | nightly only, concurrency group, no parallel heavy jobs, retries forbidden (a flaky check does not count until three greens) | gate waits |
| R-U9 | Tor bootstrap time spoils onboarding | medium / medium | honest progress copy; measured in S0a; Phase 12 tuning | — |
| R-U10 | Payment takes hours, so J2 cannot finish in a session | certain / medium | the session ends at "plata trimisă" plus comprehension; token arrival verified by scripts | declared in the report |
| R-U11 | Copy quality without a dedicated writer | medium / medium | OA-5 editor; the register forces review of every security sentence | — |
| R-U12 | Facade calls on the single DM actor make the UI stutter | medium / low | off-main, bounded reads, stale-while-loading; V-U17 measures | — |
| R-U13 | "No copy" frustrates users (URLs, addresses) | high / low | stated in DS copy; usability feedback | L11-U15 |
| R-U14 | Behaviour differs across API 29–37 (clipboard, notifications, accessibility) | high / medium | the version matrix of §2.3 drives tests and copy | per version |
| R-U15 | Hand-rolled navigation bugs | medium / low | navigation tests; Navigation 3 stays the fallback (D6) | — |
| R-U16 | A screen reader vendor's cloud feature captures screens | medium / medium | DC-20; V-U20 measures | declared |

---

## 16. Owner questions (the proposed default applies unless the owner objects)

| # | Question | Proposed default | Pe scurt (RO) |
|---|---|---|---|
| Q1 | Approve ADR-53 … ADR-57 (Appendix A) as "propus, aplicat"? | **yes** | Aprobarea ADR-53 … ADR-57 |
| Q2 | A `:ui` module with no engine dependency, `:app` as composition root, amending plan Appendix B? | **yes** | Interfața într-un modul separat, fără acces direct la motoare |
| Q3 | Own navigation instead of Navigation 3 (D6)? | **yes** | Navigare proprie, fără bibliotecă nouă |
| Q4 | Standard lock as a curtain with the DM context kept open (amends F9 §2.5, §13.7), strict lock opt-in with bound keys and process exit? | **yes** | Blocarea standard ascunde ecranul; cea strictă închide cheile și procesul |
| Q5 | App lock mandatory (no "off"); timeout 1 min by default; choices 0, 1, 5, 30 min? | **yes** | PIN obligatoriu; blocare după 1 minut |
| Q6 | Build strict mode in Phase 13 (S8), outside the usability journeys? | **yes** | Modul strict se construiește acum, opțional |
| Q7 | Notifications on by default, constant text, no count, hidden on the lock screen, no badge; count, lock-screen display and off as options? | **yes** | Notificare fixă, fără număr, ascunsă pe ecranul de blocare |
| Q8 | Accessibility options A and C of §9.3 (sensitive nodes; services screen; opt-in hiding from all services)? | **yes** | Ascundem conținutul de serviciile care nu sunt de accesibilitate; cititoarele de ecran merg |
| Q9 | Romanian and English at launch, Romanian written first, English fallback, informal "tu"? | **yes** | Română și engleză; „tu” |
| Q10 | Clearing the clipboard without focus: unconditional (may erase another app's newer clip) or skipped (GHOST's clip stays until Android 13+ clears it after about an hour, never on Android 10–12)? | **unconditional** | Golim clipboard-ul și în fundal, fără verificare |
| Q11 | No share sheet for invite links; QR and sensitive copy only? | **yes** | Fără „Partajează”; doar QR și copiere |
| Q12 | QR through zxing core 3.5.4 and Camera2, no CameraX? | **yes** | QR cu zxing și camera platformei |
| Q13 | URLs in messages as plain text, not tappable, no previews? | **yes** | Linkurile din mesaje nu se pot apăsa |
| Q14 | No message previews in the conversation list? | **yes** | Lista de conversații fără text din mesaje |
| Q15 | The PIN, the 24 words and channel passphrases only on in-app keypads, with no paste? | **yes** | Secretele se tastează doar pe tastatura aplicației |
| Q16 | No prompt-mode foreground service in Phase 13 (a later ADR with battery measurements)? | **defer** | Fără serviciu permanent acum |
| Q17 | No upload foreground service (F11 Q30); uploads continue in background jobs? | **none** | Încărcările continuă în fundal, fără serviciu |
| Q18 | Read receipts (F9 Q8) not built? | **not built** | Fără confirmări de citire |
| Q19 | Card rotation with contact backup, Invite v3, the reduced reply card, the governance engine, the deniable reveal and sponsor-confirmed admission: separate designs before Phase 15, in that order of priority (card rotation first, it closes L7 rows; governance before GA)? | **yes** | Funcțiile de protocol trimise „în Faza 13” primesc designuri separate |
| Q20 | Crash reports captured and reviewed locally now; the sending path designed with an operator endpoint later (FR-8.11 partly open)? | **yes** | Rapoarte de crash locale acum; trimiterea mai târziu |
| Q21 | Genesis onboarding only in builds whose policy enables it (stagenet, the owner's one-off bootstrap build), never in distributed mainnet builds? | **yes** | Bootstrap-ul fără invitație doar în build-uri speciale |
| Q22 | PIN digits only, 6–16; back-off from the fifth failure up to 1 h; no automatic wipe? | **yes** | PIN de 6–16 cifre; fără ștergere automată |
| Q23 | NFR-10: the gate reports the median; p95 only with ≥ 20 restores, else completed in the alpha? | **yes** | Timpul de restaurare: mediana acum, p95 în alfa |
| Q24 | Semantic snapshots as the regression gate, pixel goldens on Linux as information, no Roborazzi or Paparazzi? | **yes** | Teste de „captură” pe arborele semantic, fără biblioteci noi |
| Q25 | Test-only dependencies: Robolectric 4.17, AndroidX Test, ATF 4.1.1? | **yes** | Dependențe noi doar pentru teste |
| Q26 | Amend plan row 13 to 10–13 weeks for a team of 5–6? | **yes** | Faza 13 durează realist 10–13 săptămâni |
| Q27 | Wipe local only; revocation a separate P1 screen? | **yes** | Ștergerea e locală; revocarea e separată |
| Q28 | Dynamic colour on API 31+ by default, fixed safety colours? | **yes** | Culori Material You; culorile de avertizare fixe |
| Q29 | No lock grace for picker or settings round trips? | **yes** | Fără excepții de la blocare |
| Q30 | The third-party keyboard warning by default-IME detection, once and in Settings? | **yes** | Avertisment o dată pentru tastaturile terțe |
| Q31 | Sync keeps running under the lock screen (the lock screen counts as visible)? | **yes** | Sincronizarea merge și sub ecranul de blocare |
| Q32 | The restore cliff declared with a "before changing phone" checklist; no token or contact backup in Phase 13? | **yes** | La restaurare se pierd contactele și accesul; o spunem clar |
| Q33 | Onboarding disclosures as three short mandatory cards plus reference pages? | **yes** | Trei carduri scurte la început; restul în setări |
| Q34 | Drafts kept in memory across a standard lock, lost at a strict lock or process death, never persisted? | **yes** | Ciornele rămân doar în memorie |
| Q35 | The channel passphrase drawn from the embedded BIP-39 English list, framed distinctly from the seed? | **yes** | Parola canalului: 5 cuvinte din aceeași listă, prezentate diferit |
| Q36 | Close Phase 13 only with T53–T57 green as well as the plan's T10 and T24? | **yes** | Închidem faza și cu invarianții noi verzi |
| Q37 | The media leg of the gate waits for Phase 11's approval and facade (no cut)? | **wait** | Partea de media așteaptă Faza 11 |
| Q38 | STANDARD by default; HIGH offered at the end of onboarding and in Settings? | **yes** | Modul standard implicit; cel ridicat la alegere |
| Q39 | The update leg on staging with Phase 14's updater if it has landed, otherwise a scripted fake in a non-distributed test build, recorded as such? | **yes** | Actualizarea se testează cu Faza 14 dacă e gata, altfel cu o simulare declarată |
| Q40 | The schema migration number by merge order (UX = the next free version)? | **yes** | Numărul migrației la merge |

---

## 17. Owner actions (not code)

| ID | Action | Before |
|---|---|---|
| OA-1 | Add the runner user to the `kvm` group (`usermod -aG kvm runner`) and restart the four runner services; allow the emulator images in the runner SDK cache | S0b's emulator job |
| OA-2 | Two test phones: one on API 34+ with a hardware Keystore (StrongBox if possible), one low-end; optionally an API 29–30 device | S0a |
| OA-3 | Staging deployment (issuer, three relays, two mirrors), open since Phases 8, 9 and 14 | S11 |
| OA-4 | Recruit 5 + ≥ 8 participants, incentives, a facilitator, a consent form reviewed by counsel (GDPR) | the formative round |
| OA-5 | A native Romanian editor and counsel for the payment, privacy and Tor-guide texts and the claims register | S11 |
| OA-6 | The security contact for the About screen (FR-8.6) | S7 |
| OA-7 | Decide the Phase 11 and Phase 14 designs (the media and update legs depend on them) | S6, S7 |
| OA-8 | The CI red of F-U2 (`fetch-depth: 0` for the `static-gates` checkout) | S0b |
| OA-9 | Phase 9's A-2 (the alarm under Doze) with the device check | any time |

---

## 18. Findings outside Phase 13 (proposed as separate tasks)

- **F-U1.** FR numbering errata: the plan's FR-1.5 and FR-1.6 (plan:259-260) are the spec's FR-1.6 and FR-1.7; LIMITE's FR-1.7 (LIM:31) is FR-1.8 and its FR-1.9 is right; the plan's FR-6.8 (plan:270) and `Disclosure.kt`'s comment are the spec's FR-6.9 (spec p.8, p.10, read with `pdftotext -table`). Appendix B.1.
- **F-U2.** `static-gates` is red on one of 707 self-test cases (`dm-golden-lock`, "unreadable base" on a shallow clone; needs `fetch-depth: 0`), verified on run 36434212692 at `197b2b4` (706 cases ok, this one failing; `gh run view`, 2026-10-03) and reported by the research for run 36403499762: fix before Phase 13 adds gates, or a new red hides.
- **F-U3.** The runner user is not in the `kvm` group (`/dev/kvm` exists with `kvm_intel nested=Y`), so `dm-emulator.yml` fails on permission, not on missing virtualization (checked read-only in the `ghost-runner` distribution, 2026-10-03): OA-1.
- **F-U4.** `Bip39.encode` and `decode` build the entropy as a `String` of '0' and '1' (`Bip39.kt:29-56`): an unzeroizable copy of the root in the heap (the A-1 family of the Phase 9 review). Fixed in S2 because Phase 13 touches the code.
- **F-U5.** Phase 10 §4.5's channel sentence compares channels with DMs, a PQ claim before ADR-36's evidence (X-U11): an erratum to F10.
- **F-U6.** T7's allowlist admits every `androidx.` artifact, including GMS-bound ones, and the denylist lacks Annex D's `androidx.ads` and `androidx.credentials` (plan:464): G-U7 adds an artifact-level list; the plan should name it.
- **F-U7.** LIMITE rows that name "rotația cardului (Faza 13)" and F11 Q15's "CameraX in Phase 13" need errata once Q19 is decided.
- **F-U8.** Phase 10 coordination: per-channel unread counts, per-post timer and expiry, and a content-free `ChannelListener` in the facade's first slice.

---

## Appendix A: ADR drafts (Romanian)

### ADR-53 — Stratul de interfață: modulul `:ui`, porți de acces, flux unidirecțional, coroutines doar în interfață, navigare proprie

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13, `docs/design/faza13-ux.md`) |
| Sursă | plan §6.2 rândul 13; spec §6.1 (modulul `ui`), FR-7.1 |
| Modifică | plan Anexa B (`app/ # Compose UI, DI, navigare`); ADR-20 punctul 1 („fără coroutines”), doar pentru interfață; designul Fazei 9 §16.3; ADR-06 („+ un foreground service opțional «mod prompt»”), amânat |

**Context.** Fazele 3–11 au livrat motoare fără interfață, în spatele unor fațade blocante: actorul DM rulează pe un singur fir și așteaptă rezultatul fiecărui apel, iar apelurile JNI blochează. Interfața trebuie să le folosească fără să blocheze firul principal, fără să ocolească motoarele și fără să producă trafic pe care releele să-l poată lega de ce face utilizatorul pe ecran.

**Decizie.**
1. Un modul nou `:ui` (bibliotecă Android, Compose) conține ecranele, sistemul de design, componentele de protecție, deținătorii de stare, modelele de interfață și interfețele porților de acces. `:ui` nu depinde de niciun modul `org.ghost.*` (poarta G-U5). `:app` rămâne rădăcina de compoziție și adaugă adaptoarele porților, notificatorul, controlerele de blocare și de ștergere și depozitul de setări.
2. Flux unidirecțional: compozabil → intenție → model de ecran → poartă (`suspend`) → adaptor în `:app`, care apelează fațada blocantă pe executorul `ghost-ui-io` (două fire), niciodată pe firul principal → stare imutabilă într-un `StateFlow`. Schimbările ajung ca indicii fără conținut prin `ChangeHub`; starea motoarelor se citește la 2 s doar cât aplicația e vizibilă și deblocată.
3. Coroutines sunt permise doar în `:ui` și în `org.ghost.app.ui`; în toate modulele de motor rămân interzise (G-U9 extinde G-DM1 la `:sync`, `:storage`, `:identity`, `:entitlement`, `:network`, `:media` și la pachetul de bază din `:app`).
4. Starea interfeței trăiește cât sesiunea deblocată. Nicio valoare sensibilă nu intră în `rememberSaveable`, `SavedStateHandle`, `rememberTextFieldState` sau în pachetul de stare salvată al activității, care se golește (T54).
5. Navigare proprie: o stivă tipizată în memorie, niciodată persistată; fără Navigation 3.
6. O singură activitate, singura componentă exportată; legăturile `ghost://invite`, `ghost://contact`, `ghost://channel` sunt intrări neîncrezute, acționate doar după deblocare și confirmare.
7. Doar acțiunile din lista închisă a designului (§2.4) produc trafic către relee, issuer sau mirror-uri; nimic altceva din interfață nu produce trafic și nu schimbă programul de citire (T53).
8. Fără serviciu în prim-plan în Faza 13 (nici „mod prompt”, nici pentru încărcări): un ADR separat, cu măsurători de baterie.
9. Funcțiile de protocol trimise „în Faza 13” de documentele anterioare (rotația cardului cu copia contactelor, Invitația v3, cardul redus de răspuns, motorul de guvernanță al ADR-13, dezvăluirea negabilă, confirmarea intrării de către sponsor) primesc designuri separate, înaintea Fazei 15.

**Consecințe.** (+) Izolarea interfeței e impusă de Gradle, nu de un text; (+) ecranele se testează pe JVM fără biblioteca nativă; (+) motoarele nu se schimbă, cu excepția adaosurilor la fațade enumerate în design §3.6, fiecare cu porțile fazei ei rulate din nou. (−) Cod de mapare între tipurile motoarelor și cele ale interfeței; (−) o excepție declarată de la „fără coroutines”; (−) funcțiile amânate lasă deschise reziduurile L7 care le numesc, până la designurile lor.

**Alternative respinse.** Totul în `:app` (fără perete la compilare); module per funcționalitate (prea multe pentru o singură activitate); Navigation 3 1.2.0 (persistă cheile și starea pe intrare, dependențe noi); ViewModel cu `SavedStateHandle` (pachetul pleacă din proces); Hilt, Dagger sau Koin (în afara allowlist-ului; rădăcina de compoziție manuală există deja).

**Teste.** G-U5, G-U6, G-U9; suita porților înregistratoare; gemenii NI-U1 … NI-U3; T53, T54.

### ADR-54 — Protecția ecranului și a textului, implementată (precizează ADR-27 punctele 1–6)

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13) |
| Completează | ADR-27 punctele 1–6, ADR-08, FR-7.8, FR-7.14 |
| Modifică | T24 („un singur modul aprobat” devine un singur fișier aprobat); ADR-27 punctul 5 (verificarea „mai conține datele GHOST” doar cu focus); ADR-27 punctul 6 (secretele nu mai au câmp cu tastatura sistemului); T11 („cu dispozitiv blocat” devine „blocat sau nu”); X-M11 al Fazei 11 (suprafețele video) |

**Context.** ADR-27 a fixat regulile; implementarea lor pe Android are limite care diferă de la o versiune la alta (designul Fazei 13, §2.3). UI-ul nu are voie să promită mai mult decât face platforma.

**Decizie.**
1. **Ferestre.** O clasă `SecureActivity` pune FLAG_SECURE înaintea oricărui conținut, apelează `setRecentsScreenshotEnabled(false)` pe API 33+, marchează decorul ca sensibil pentru accesibilitate pe API 34+, exclude autofill-ul și golește pachetul de stare salvată. Dialogurile, meniurile, ferestrele pop-up și foile se fac doar prin Compose, care moștenesc FLAG_SECURE. Sunt interzise `Toast`, `PopupWindow`, `android.app.Dialog`, `Spinner`, `AutoCompleteTextView`, `PopupMenu`, `PlayerView` și `WebView`. Video și previzualizarea camerei rulează pe `TextureView`.
2. **Text.** Fără selecție nicăieri; fără copiere, partajare, „Trimite către” sau tragere pentru mesaje, postări, media și pseudonime; URL-urile din mesaje sunt text simplu, fără legături și fără previzualizări. Câmpul de compunere rămâne normal, iar copierea și tăierea din el trec prin clipboard-ul sensibil.
3. **Accesibilitate.** Decorul fiecărei ferestre e marcat sensibil (API 34+) și fiecare element de conținut poartă `isSensitiveData`; toate semanticile rămân pentru instrumentele de accesibilitate (TalkBack, Switch Access, Voice Access); anunțurile sunt fără conținut („Mesaj nou”); acțiuni personalizate înlocuiesc meniurile la apăsare lungă. Ecranul „Cine poate citi ecranul” arată serviciile active și oferă, opțional, ascunderea conținutului de toate serviciile.
4. **Clipboard.** Un singur fișier (`SensitiveClipboard.kt`) scrie în clipboard, doar date cerute de utilizator care nu sunt conținut: linkuri de invitație, de contact și de canal, subadresa de plată, amprenta aplicației. Fiecare scriere are `EXTRA_IS_SENSITIVE`. Ștergerea are loc la 30 s și la blocare: cu focus, doar dacă datele sunt încă ale GHOST; fără focus, necondiționat, pentru că Android nu permite citirea clipboard-ului în fundal. Cuvintele seed-ului, parolele de canal, cifrele de siguranță și PIN-ul nu se copiază niciodată.
5. **Tastatură.** `IME_FLAG_NO_PERSONALIZED_LEARNING` pe fiecare câmp cu tastatura sistemului, printr-un interceptor la rădăcina fiecărei ferestre. PIN-ul, cele 24 de cuvinte și parola de canal se tastează doar pe tastaturile aplicației, fără lipire și fără autofill. O tastatură implicită care nu e de sistem primește un avertisment, o dată și în setări.
6. **Notificări.** Un singur canal; un text constant („Ai mesaje noi”), opțional cu număr; fără expeditor, conversație sau conținut, cu telefonul blocat sau nu; ascunse implicit pe ecranul de blocare; fără insignă; fără `MessagingStyle`, răspuns direct, scurtături sau bule. Plata, accesul și actualizările nu sunt niciodată notificări.

**Consecințe.** (+) Ce garantează fiecare versiune de Android e scris, iar UI-ul nu spune mai mult. (−) Pe API 29–30 tastatura poate apărea în capturi; pe API 29–33 orice serviciu de accesibilitate citește textul; pe API 34+ un serviciu care pretinde fals că e instrument citește și el; ștergerea necondiționată poate șterge un text copiat de altă aplicație după GHOST; utilizatorul retastează URL-urile.

**Alternative respinse.** Ascunderea conținutului de toate serviciile, implicit (exclude utilizatorii nevăzători); foaia de partajare pentru linkuri; clipboard-ul implicit al Compose; tastatura sistemului pentru secrete; notificări cu expeditor sau text.

**Teste.** T10, T11, T24 (rândurile din INVARIANTS), G-U1 … G-U4, G-U10; mutanții PM-U1 … PM-U13, PM-U22, PM-U23; pașii 1–3 ai listei de dispozitive.

### ADR-55 — Blocarea aplicației, modul strict, ștergerea locală, copia și restaurarea cuvintelor

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13) |
| Completează | ADR-08 (auto-lock și PIN de aplicație), ADR-14 (PIN-ul de constrângere rămâne P2), FR-1.4, FR-1.8, FR-7.13 |
| Modifică | designul Fazei 9 §2.5 și §13.7 (blocarea standard nu închide contextul DM); LIMITE L7-D19; ADR-20 Q6 rămâne valoarea implicită, iar modul strict e opțiunea |

**Context.** Cu chei care nu cer autentificare (ADR-20 Q6), contextul DM se redeschide din Keystore la orice pornire de proces; închiderea lui la fiecare blocare ar opri primirea și notificările în procesul pe care îl împarte cu jobul de fundal, fără să protejeze de cineva care poate folosi Keystore-ul. FR-1.8 cere o politică biometrică sau PIN configurabilă, iar LIMITE L1 numește „autentificare per deblocare”.

**Decizie.**
1. Blocarea e obligatorie: un PIN de 6–16 cifre pe tastatura aplicației, biometrie opțională; implicit, blocare după 1 minut în fundal (alegeri: imediat, 1, 5, 30 de minute).
2. **Blocarea standard**: o perdea înaintea primului cadru și închiderea sesiunii deblocate; contextul DM, baza de date și sincronizarea rămân pornite, deci primirea, ștergerea mesajelor expirate și notificările continuă.
3. **Modul strict** (opțional): cheile bazei, ale identității și cheile de conținut și de stare DM sunt învelite de chei Keystore legate de autentificarea dispozitivului; la blocare contextul DM se închide și procesul se termină; nimic nu se sincronizează în fundal. Trecerea în ambele sensuri e sigură la crash (pașii R0–R4 ai designului). Dezactivarea blocării ecranului telefonului distruge definitiv cheile (reziduu declarat, spus înainte de activare).
4. Verificatorul PIN e HMAC-SHA256 cu o cheie Keystore neexportabilă peste o etichetă, o sare de 16 octeți și cifre; de la al cincilea eșec, amânare exponențială până la o oră; fără ștergere automată.
5. **Ștergerea locală**: oprirea DM și a sincronizării, apoi plicurile cheilor (punctul de distrugere criptografică), apoi aliasurile Keystore, apoi fișierele, apoi ieșirea din proces; o ștergere întreruptă se termină la pornirea următoare. Revocarea identității e un ecran separat (P1).
6. Cele 24 de cuvinte apar doar după ce activarea e `ACTIVE`; se verifică 4 poziții aleatoare, fără posibilitatea de a sări; onboarding-ul nu se încheie fără verificare; cuvintele se pot reafișa după reautentificare; nu se copiază și nu se exportă. Restaurarea trece doar prin `Entitlement.restore`, după ecranul „ce se întoarce și ce nu”.

**Consecințe.** (+) FR-1.8 e îndeplinit (politică configurabilă); (+) rândul L1 „autentificare per deblocare” există ca opțiune. (−) În modul standard cheile DM stau în memoria nativă cât trăiește procesul (L7-D19 actualizat); (−) modul strict nu are notificări și nu șterge de pe disc mesajele expirate până la deblocare; (−) PIN-ul nu rezistă unui atacator cu root pe telefon.

**Alternative respinse.** Închiderea contextului DM la fiecare blocare standard; o blocare doar de interfață, fără opțiunea strictă; un verificator Argon2id fără Keystore; PIN-ul dispozitivului ca PIN al aplicației; revocare și ștergere într-un singur pas; cuvintele arătate în timpul activării.

**Teste.** T55, T57, CS-U2, CS-U3; mutanții MC-U1 … MC-U6, PM-U19 … PM-U21; pașii 4, 6 și 7 ai listei de dispozitive.

### ADR-56 — Afirmații și disclosure-uri în interfață (CP-10)

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13) |
| Completează | CP-10, FR-8.7, C-10, ADR-36 punctul 6, ADR-38 punctul 11, designul Fazei 14 §2.6 |
| Modifică | designul Fazei 10 §4.5 (fraza pentru canale apare fără comparația cu mesajele directe până la dovezile ADR-36) |

**Context.** `docs/STATUS.md` spune „Afirmații permise în marketing/UI: niciuna”. O interfață are totuși nevoie să spună ce nu protejează GHOST, cum se comportă o setare și care sunt obiectivele de design, fără să afirme ce nu e dovedit.

**Decizie.**
1. Registrul `ghost/android/ui/claims/claims.tsv` conține fiecare frază de confidențialitate sau securitate, cu tipul ei (`LIMIT` — o limită; `FEATURE` — cum funcționează o setare; `GOAL` — un obiectiv de design; `CLAIM` — o afirmație despre ce nu poate face un adversar), dovezile, reziduul care o însoțește și sursa.
2. Un `CLAIM` intră într-un release doar dacă toate dovezile lui sunt în lista verde `ghost/test-harness/privacy/claims-evidence.txt` (azi goală). Un `GOAL` se afișează mereu cu starea lui („obiectiv de design — neverificat încă”).
3. Formulările interzise, în română și engleză, sunt cele din design §8.4. Nicio afirmație post-cuantică până când modelul ADR-36 a rulat și revizia externă e publicată; apoi doar fraza ADR-36, pentru mesajele directe. Canalele poartă limitarea „criptografie clasică” fără comparație.
4. Trei straturi de disclosure: onboarding (trei carduri scurte), la momentul acțiunii riscante, pagini de referință („Cine vede ce” după tabelul din plan §4, „Limite”, „Cine poate citi ecranul”).
5. Disclosure-urile DC-1 … DC-27 ale designului sunt obligatorii; un redactor nativ și un jurist revizuiesc textele de plată, de confidențialitate și ghidul Tor; lista de afirmații semnată (FR-8.7) e condiție de release.

**Consecințe.** (+) CP-10 devine o regulă verificată la build. (−) Azi interfața nu spune nici măcar „criptat end-to-end”: dovezile (porțile Fazelor 9 și 10, auditul Fazei 15) nu există încă.

**Alternative respinse.** Textele revizuite „din ochi”, fără registru.

**Teste.** T56, G-U8, mutantul PM-U24.

### ADR-57 — Componente și permisiuni noi: notificări, camera pentru QR, zxing, legături `ghost://`

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-10-03 (designul Fazei 13) |
| Completează | ADR-06, ADR-05, ADR-10 (setul de permisiuni T15), T15m, T16 |
| Modifică | designul Fazei 11 Q15 („CameraX în Faza 13”); nota din `MessagingPorts.kt` despre ADR-ul permisiunii de notificare |

**Context.** Interfața are nevoie de notificări, de scanarea codurilor QR (invitații, carduri, numere de siguranță, canale) și de legături `ghost://`, fără SDK-uri terțe, fără biblioteci native noi și fără componente exportate noi.

**Decizie.**
1. `POST_NOTIFICATIONS` (deja în lista T15) se declară și se cere la sfârșitul onboarding-ului (API 33+), după ce utilizatorul vede exact textul notificării.
2. `CAMERA` (în lista T15) se declară, cu `android.hardware.camera` neobligatoriu, doar pentru scanarea codurilor QR în fereastra securizată, prin Camera2 al platformei; fără CameraX, fără aplicația de cameră a sistemului, fără ML Kit.
3. `com.google.zxing:core` 3.5.4 (Apache-2.0, fără dependențe la rulare) intră în allowlist (grupul `com.google.zxing`), cu notificare și sume în `verification-metadata.xml`.
4. Activitatea de lansare primește filtre `VIEW` pentru schema `ghost` cu gazdele `invite`, `contact` și `channel`; fără `http` sau `https`, fără `autoVerify`; legăturile sunt intrări neîncrezute.
5. `USE_BIOMETRIC` (în lista T15) pentru deblocare, prin `BiometricPrompt` al platformei; fără `androidx.biometric`.
6. Dependențe doar pentru teste: Robolectric 4.17 (MIT), AndroidX Test, Accessibility Test Framework 4.1.1; absente din graful release (G-U7).

**Consecințe.** (+) Nicio bibliotecă nativă nouă și nicio componentă exportată nouă. (−) Cod propriu pentru previzualizarea camerei; (−) o altă aplicație poate revendica schema `ghost://` și intercepta un link deschis din afara GHOST (reziduu L11-U13; QR-ul în persoană rămâne calea recomandată).

**Alternative respinse.** CameraX (bibliotecă nativă nouă), ML Kit (Google Play services), zxing-cpp (nativ), intentul camerei sistemului (o aplicație terță vede imaginea); foaia de partajare; `androidx.biometric` (cere `FragmentActivity`).

**Teste.** G-U7, G-U10, G-U11, T15m, T16; verificarea V-U8.

---

## Appendix B: Text changes in other documents (applied in S12)

### B.1 Master plan and LIMITE errata (Romanian)

- **Plan §6.2, rândul 13:** durata „4–6 s” devine „10–13 s (echipă de 5–6; ≈ 50–62 de persoane-săptămână; design `docs/design/faza13-ux.md` §14.2)”; la „Depinde de” se adaugă „(în fapt și fațadele Fazei 8 și ale Fazei 14 pentru actualizare)”; poarta rămâne, cu nota „T53–T57 verzi (Q36)”.
- **Plan §6.6 (Anexa B revizuită):** se adaugă `ui/ # Compose: ecrane, sistem de design, componente de protecție (Faza 13, ADR-53)`; `app/` devine `# rădăcina de compoziție, DI, adaptoare, navigarea e în ui/`.
- **Plan §5:** notă: „Numerotarea FR din acest tabel e decalată față de spec: FR-1.5 (payload-ul invitației) e FR-1.6 în spec, FR-1.6 (eligibilitatea) e FR-1.7, FR-6.8 (avertismentul KYC) e FR-6.9 (spec p.8, p.10; design Faza 13 F-U1).”
- **LIMITE L1, rândul „Prevenire” cu Keystore:** „(FR-1.7)” devine „(FR-1.8)”; se adaugă „autentificarea per deblocare e modul strict opțional (ADR-55); implicit cheile nu cer autentificare (ADR-20 Q6)”.
- **LIMITE L7-D19:** „blocarea și wipe-ul nu au încă apelant” devine „în blocarea standard cheile rămân în memoria nativă cât trăiește procesul; modul strict închide contextul și termină procesul la blocare; wipe-ul le șterge (ADR-55)”.
- **LIMITE, rândurile care numesc „rotația cardului (Faza 13)”:** devin „rotația cardului (design separat, Faza 13 Q19)”.

### B.2 `ghost/test-harness/privacy/INVARIANTS.md` (rânduri noi și modificate)

| ID | Invariant | Verificare | Executabil din | Cod |
|---|---|---|---|---|
| T53 | Doar acțiunile utilizatorului din lista închisă (design Faza 13 §2.4) produc trafic către relee, issuer sau mirror-uri; nicio altă acțiune sau stare a interfeței (deschiderea unui ecran, derularea, afișarea, blocarea standard, notificările, citirile de stare) nu schimbă programul de citire, momentele sesiunilor sau ce se trimite | G-U5; suita porților înregistratoare (fiecare intenție a fiecărui model de ecran, contra fațadelor înregistratoare); gemenii NI-U1 (lumea de confidențialitate DM cu un șofer de interfață care citește fiecare metodă de fațadă la rata maximă permisă, față de niciuna: vederi de relay identice, înregistrări în același minut), NI-U2 (o conversație deschisă și afișată față de nu), NI-U3 (instrucțiunile de plată citite față de nu, în afara reținerii declarate) | Faza 13 (JVM) | `android/ui`, `android/app` (`org.ghost.app.ui`), lumea DM |
| T54 | Interfața nu păstrează nimic sensibil în afara SQLCipher și a memoriei: pachetul de stare salvată e gol; nicio preferință, DataStore sau fișier, în afara fișierului tranzitoriu de crash (criptat, declarat); nicio valoare sensibilă într-un `toString` | G-U6; scanarea canarilor în pachetul fiecărui ecran; testul de reflecție pe `toString`; inventarul sandbox-ului pe emulator | Faza 13 | `android/ui`, `android/app` |
| T55 | Cât aplicația e blocată nu se compune niciun ecran cu conținut; decizia de blocare precede primul cadru după revenire; un proces nou pornește blocat; în modul strict niciun proces GHOST nu supraviețuiește blocării | testele JVM ale mașinii de stări și ale cadrelor, pe ceas virtual; emulator (`uiautomator dump`, `pidof`) | Faza 13 | `android/ui`, `android/app` |
| T56 | Nicio afirmație (`CLAIM`) nu ajunge într-un release fără toate dovezile în lista verde; fiecare obiectiv (`GOAL`) apare cu starea lui; nicio formulare interzisă, în română sau engleză | G-U8 cu fixture-uri; testul JVM care citește toate resursele și registrul | Faza 13 | `android/ui/claims/`, `scripts/gates/ui-claims.sh` |
| T57 | După ștergere: niciun plic de cheie, niciun alias Keystore GHOST, nicio bază de date sau WAL, niciun fișier în `no_backup`, `files` sau `cache`, niciun job sau alarmă programată, nicio notificare; o ștergere întreruptă se termină la pornirea următoare | enumerarea crash-urilor peste pașii W2–W7 (JVM); inventarul `run-as` și `dumpsys jobscheduler`, `alarm`, `notification` pe emulator; dispozitiv | Faza 13 | `android/app` |

Rânduri modificate (text adăugat la coloana „Verificare”):
- **T10:** „Faza 13 (ADR-54): fiecare fereastră a pachetului (activitate, dialog, meniu, foaie, player Compose) e securizată de la primul cadru (G-U1); pe emulator, API 29, 33, 35, 36 și 37: `dumpsys window` arată `SECURE` pe fiecare fereastră a fiecărui ecran scriptat; captura ADB e refuzată (API ≤ 34) sau neagră (API ≥ 35); instantaneul din recents e un înlocuitor (nu „absent”), fiecare cu un control nesecurizat; pașii de dispozitiv. Regula ferestrelor media a Fazei 11 (X-M11) e inclusă.”
- **T11:** „blocat sau nu (Faza 9 Q19); un text constant și, opțional, numărul; ascunsă implicit pe ecranul de blocare; fără insignă; scanarea canarilor în `dumpsys notification --noredact` și pasul istoricului notificărilor pe dispozitiv.”
- **T24:** „Fișierul aprobat e `SensitiveClipboard.kt`, plus rădăcina care îl folosește drept clipboard-ul Compose; ștergerea verifică proprietatea cu focus și e necondiționată fără focus; marcarea de accesibilitate pe decor și pe frunze; secretele nu au câmp cu tastatura sistemului; pe emulator, API 34+: zero canari printr-un client care nu e instrument, canari prezenți prin unul care e.”
- **T3:** canarii includ aliasurile, textul mesajelor și al postărilor, cuvintele și parolele, PIN-ul, adresele de plată; scanarea include logcat-ul fiecărei suite de emulator, rapoartele de crash și pachetele de stare.
- **T4, T6 (dinamic), T20 (inventarul):** „executat pe emulator în Faza 13 (felia S10)”, cu rezultatul.
- **T25:** „definiția «afișat» din design Faza 13 §3.5 pornește numărătoarea destinatarului; în modul strict ștergerea fizică așteaptă deblocarea (L11-U9).”

### B.3 `docs/THREAT_MODEL_v2.1.md` (română)

- **§7, scenariu nou S14. Aplicații de pe telefon care citesc ecranul, tastatura, clipboard-ul sau notificările.** Obține: ce afișează GHOST, dacă protecțiile nu se aplică. Mitigări: FLAG_SECURE pe fiecare fereastră, marcarea de accesibilitate (API 34+), clipboard sensibil cu ștergere la 30 s, secrete doar pe tastaturile aplicației, notificări cu text constant (ADR-27, ADR-54). **Rezidual:** API 29–33 pentru accesibilitate, API 29–30 pentru tastatură în capturi, serviciile care mint că sunt instrumente, instrumentele de sistem, cameră sau alt dispozitiv, root. **Test:** T10, T11, T24.
- **§6, rând nou „Interfața (Faza 13)”:** releele văd prezența (aplicația deschisă, inclusiv la ecranul de blocare) și acțiunile din lista închisă; nimic din navigare, afișare, blocarea standard sau notificări; un atacator cu baza deschisă (AD-8) vede setările (modul ridicat, modul strict, contorul de eșecuri ale PIN-ului).

### B.4 `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`: secțiunea nouă L11 (reziduurile interfeței, Faza 13)

| ID | Reziduu | De ce rămâne | Atenuare |
|---|---|---|---|
| L11-U1 | Ecranul poate fi fotografiat cu alt dispozitiv; un client modificat sau un telefon cu root anulează FLAG_SECURE; funcțiile de captură ale unor producători nu sunt testate | aplicația rulează pe sistemul utilizatorului | lista de dispozitive testate; timere scurte |
| L11-U2 | Pe Android 10–11 (API 29–30) tastatura poate apărea în capturi | platforma nu securizează fereastra IME înainte de API 31 | secretele pe tastaturile aplicației |
| L11-U3 | Pe API 29–33 orice serviciu de accesibilitate citește textul; pe 34+ un serviciu care pretinde fals că e instrument; instrumentele de sistem (din Android 16 QPR2, după sursele AOSP) pot captura ferestre securizate; funcții ale cititoarelor de ecran care trimit capturi în cloud la cererea utilizatorului | `isAccessibilityTool` e declarat de serviciu | ecranul „Cine poate citi ecranul”; opțiunea de ascundere |
| L11-U4 | Clipboard-ul: 30 s de expunere; istoricul de clipboard al tastaturilor; ștergerea necondiționată în fundal poate șterge textul altei aplicații; dacă procesul moare înainte, clipul rămâne până la ștergerea sistemului (~1 h pe Android 13+, niciodată pe 10–12) | Android nu permite citirea în fundal | doar date care nu sunt conținut; secretele nu se copiază |
| L11-U5 | O tastatură terță vede tot ce scrii în câmpul de compunere | câmpul de compunere folosește tastatura sistemului (ADR-27 punctul 3) | flagul fără învățare (doar o recomandare); avertisment |
| L11-U6 | Aplicațiile care ascultă notificările (ceasuri, automatizări) văd textul constant și momentul lui, care e momentul decriptării unui mesaj; istoricul notificărilor (24 h, dacă e activ) | notificarea există | text constant; ascunsă pe ecranul de blocare; opțiunea „fără notificări” |
| L11-U7 | Textul decriptat din ecrane (șiruri JVM) nu se poate șterge; după blocare devine eligibil pentru GC | limbajul | sesiunea se închide la blocare |
| L11-U8 | PIN-ul aplicației oprește pe cineva care ține telefonul deblocat, nu un atacator cu root (încearcă PIN-uri cu cheia Keystore de pe telefon); contorul de eșecuri e un artefact | HMAC-ul cu Keystore e un oracol pe dispozitiv | modul strict; PIN de până la 16 cifre |
| L11-U9 | Modul strict: fără sincronizare și notificări în fundal; mesajele expirate rămân pe disc (neafișate) până la deblocare; dezactivarea blocării ecranului distruge cheile | cheile cer autentificarea | disclosure DC-26; restaurarea din cuvinte |
| L11-U10 | Setările (modul ridicat, modul strict, durata blocării) sunt vizibile unui atacator cu baza deschisă | trebuie citite de procesele de fundal | — |
| L11-U11 | După ștergere rămân: istoricul de joburi și alarme al sistemului, istoricul notificărilor (dacă e activ), înregistrarea canalului de notificare, blocuri de flash sub sistemul de fișiere, copiile de pe relee până la TTL, copiile contactelor | în afara aplicației | ștergerea criptografică înaintea fișierelor |
| L11-U12 | Deschiderea aplicației, inclusiv la ecranul de blocare, pornește sesiunea de prim-plan, deci releele văd că aplicația e deschisă | sincronizarea urmează procesul vizibil | — (LIMITE L2.1 punctul 4) |
| L11-U13 | O altă aplicație poate revendica schema `ghost://` și intercepta un link deschis din afara GHOST | schemele nu se pot verifica | QR în persoană; codul de verificare citit cu voce tare |
| L11-U14 | Raportul de crash stă criptat într-un fișier tranzitoriu până la pornirea următoare | handler-ul nu poate scrie sigur în baza de date | fără mesaje, fire sau căi în raport |
| L11-U15 | Fără copiere din mesaje, utilizatorul retastează URL-urile și adresele (risc de greșeală) | ADR-27 punctul 3 | — |
| L11-U16 | Selectorul de fotografii al sistemului și DocumentsUI pot păstra istoricul selecțiilor | scris de sistem | Faza 11 L9-M15 |

### B.5 Other designs (English forward notes)

- **F9 §2.5, §13.7:** "Phase 13 (ADR-55, X-U1): the standard lock is a curtain; `ctxClose` runs at a strict lock (followed by process exit) and at wipe."
- **F10 §4.5:** the channel sentence loses its comparison clause until ADR-36's evidence (X-U11). **F10 §10.3:** coordination items F-U8.
- **F11 Q15, Q30, G-M2:** the camera serves QR only through Camera2 (no CameraX); no upload service in Phase 13; G-M2 admits `media3-ui-compose`.
- **F14 §0.4, F-D8:** consumed by §6.7; Q16 (no silent updates) unchanged.

### B.6 STATUS and the ADR index

- **`docs/STATUS.md`, rândul „Faza 13”:** „design propus 2026-10-03 (`docs/design/faza13-ux.md`: modul `:ui`, protecția ecranului și a textului, blocare standard și strictă, ștergere, copie și restaurare, registrul de afirmații; ADR-53 … ADR-57; estimare 10–13 săptămâni; 40 de întrebări cu valori implicite). Niciun cod.”
- **`docs/adr/README.md`:** secțiunea „Propuse (Faza 13)” cu ADR-53 … ADR-57.

---

## Appendix C: Evidence, verified vs assumed

### C.1 Verified in the repository (at `197b2b4`, read 2026-10-03)

| Fact | Where |
|---|---|
| Plan row 13, its gate, effort and dependencies | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md:317` |
| The only `FLAG_SECURE` today; no other window code | `ghost/android/app/src/main/kotlin/org/ghost/app/MainActivity.kt:31` |
| No production caller of `onLock`, `onUnlock`, `onWipe`, `onDatabaseKeyCreated`, `setNotificationPort`, `markDisplayed`, `requestExpedite` (only tests and comments) | grep over `android/*/src/main` and `app/src` |
| `AUTH_BOUND = false`; background opening refused for bound keys | `AppDatabase.kt:16,22-23` |
| The Keystore wrapper's authentication parameters (30 s, biometric or device credential) | `AndroidKeystoreWrapper.kt:50-62` |
| The backup challenge and its check | `IdentityManager.kt:80,88` |
| The BIP-39 encoder builds a `String` of bits | `Bip39.kt:29-36,43-56` |
| `getOrCreate` writes the key envelope | `DatabaseKeyProvider.kt:19-24` |
| The DM facade lacks `setListener` and names; `MessageView` fields | `Messaging.kt:11-27,78,375-398` |
| `NotificationPort` carries only an `Int` | `MessagingPorts.kt:35-38` |
| `locked` starts false; `onLock` posts the close; `onWipe` waits for the pass | `MessagingWiring.kt:162-163,347-374` |
| Facade calls wait on a future without a timeout; `IllegalStateException` after retire | `DmActor.kt:194-216` |
| `paymentInstructions` marks the purchase shown | `EntitlementEngine.kt:230-249` |
| Transport states, status flags; controller methods; the privacy-mode default | `SyncStatus.kt:4-28`; `SyncController.kt:10,12,44,50,56,68`; `sync/api/Types.kt:103-104`; `SyncRuntime.kt:191` |
| The payment-hold read at process start | `SyncWiring.kt:34-39` |
| Schema version 5; `name_env` | `Schema.kt:120,936` |
| T15's permissions; anti-placeholder's words; the dependency lists; G-DM1's coroutine ban | `scripts/gates/common.sh:15`; `anti-placeholder.sh:6-20`; `dependency-allowlist.txt`, `dependency-denylist.txt`; `messaging-no-network.sh:21-24` |
| Toolchain pins | `libs.versions.toml:4-12` |
| The release APK already ships coroutines 1.9.0, `navigationevent` 1.0.0, `savedstate-compose` 1.4.0, `runtime-retain` 1.12.1, `autofill` 1.0.0, `window` 1.5.0; not `lifecycle-viewmodel-compose`, any navigation library or `material3-adaptive` | `ghost/licenses/THIRD_PARTY_NOTICES-android.txt` |
| The manifest's permissions, launcher and the removed emoji2 initializer | `app/src/main/AndroidManifest.xml:6-10,23-30,61-70` |
| Phase 10's facade, password decisions, Q4, Q7, Q14, Q15, Q35, Q42–Q50 | `docs/design/faza10-forum.md:975-1000,1391-1456,1900-2021` |
| Phase 11's facade, view-once and media rules, Q15, Q30 | `docs/design/faza11-media.md:470-531,723-744,1339,1354` |
| Phase 14's update runs, `Updates`, claims rule, F-D8 (branch `p14-design`, `58117c0`) | `git show p14-design:docs/design/faza14-distribution.md` §2.6, §7.3–§7.7, §9.5, §17 |
| `static-gates` red on `197b2b4`: 706 "self-test ok", 1 failure (`dm-golden-lock` on an unreadable base) | `gh run view 36434212692` (2026-10-03) |
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
| Keys requiring authentication are invalidated when the secure lock screen is disabled; `setUnlockedDeviceRequired` bugs on 12–14 | Microsoft Learn (KeyGenParameterSpec.Builder) |
| `DEVICE_CREDENTIAL` combinations unsupported on API ≤ 29; no `CryptoObject` with a credential fallback | developer.android.com biometric authentication |
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

### C.3 Corrected digest claims

1. `isAccessibilityTool()` is readable from API 31, not 34 (Microsoft Learn `ApiSince=31`); enforcement of data sensitivity starts at 34.
2. The randomized-subset backup rule is FR-1.4 and the configurable biometric/PIN policy FR-1.8 (spec p.8, table extraction), not FR-1.9 and FR-1.7.
3. The payment disclosure is spec FR-6.9; "FR-6.8" is the plan's and the code's numbering.
4. "`REQUEST_INSTALL_PACKAGES` is outside the T15 set" is true today but not for good: Phase 14's ADR-51 (proposed) adds it, and Phase 13 relies on that for J6.
5. (Not a digest error, a source note.) Robolectric 4.17's date is 2026-09-10 (Maven metadata); a fetched page summary that read 2024 was a summariser artefact.

### C.4 Assumed, checked in S0a (each with the fallback if it fails)

| ID | Assumption | Fallback |
|---|---|---|
| V-U1 | `dumpsys window` shows `SECURE` per window on API 29–37; `screencap` refused (≤ 34) or black (≥ 35); the recents snapshot is a placeholder; `screenrecord` frames black | rely on `dumpsys` and the device checklist; declare the gap |
| V-U2 | A `TextureView` inside a secure window is covered; a `SurfaceView` needs `setSecure(true)` | ban `SurfaceView` (already the design) |
| V-U3 | Decor-level `setAccessibilityDataSensitive` hides Compose nodes and dialog content from a non-tool client on API 34–37; the hidden non-tool `UiAutomation` flag works | a test-only spy service declaring `isAccessibilityTool=false`; leaf marking only |
| V-U4 | The interceptor's flag reaches the AOSP keyboard and Gboard (`dumpsys input_method`) | a View-based `EditText` bridge for the composer only |
| V-U5 | Compose 1.12.1's text fields use the provided `LocalClipboard`; background `clearPrimaryClip` works; `getPrimaryClipDescription` with focus reads the label without a toast | disable copy and cut in the composer's toolbar instead |
| V-U6 | Decor-level autofill exclusion stops every autofill request on Compose 1.12.1 | per-field `contentType` with no autofill semantics |
| V-U7 | Robolectric 4.17 with Compose tests on JDK 17 at SDK 35, offline jars, `captureToImage` under native graphics | emulator-only pixel goldens |
| V-U8 | zxing decodes an 876-character invite (version 21, level L) from Camera2 YUV on the low-end phone at 20–40 cm in under 2 s | a larger on-screen code; paste |
| V-U9 | The platform `BiometricPrompt` with a device-credential fallback works on API 29 and 30+ without `androidx.biometric` | add `androidx.biometric` with a `FragmentActivity` (ADR amendment) |
| V-U10 | Keystore HMAC keys work on API 29–37, StrongBox where present; the time per check | a TEE key; declare the speed |
| V-U11 | Strict mode: unwraps inside the 30 s window after authentication; invalidation on screen-lock removal; the job does nothing; process exit and restart | a longer validity window |
| V-U12 | `captureToImage` in instrumentation on a test activity without the flag | JVM goldens only |
| V-U13 | `getEnabledAccessibilityServiceList` gives labels and packages under package visibility on API 30+ | show packages only |
| V-U14 | The default IME's package and system flag are readable under package visibility | warn for every non-AOSP keyboard |
| V-U15 | `VISIBILITY_SECRET` hides the notification on a secure lock screen on 29–37; the channel's lock-screen and badge settings take effect | per-notification settings only |
| V-U16 | Clearing the saved bundle and passing `null` to `super.onCreate` cause no AndroidX failure across configuration changes and process death | clear selected keys only |
| V-U17 | DM actor latency of UI reads during passes (p50, p99) on the emulator and the low-end phone | lower the poll rate; stale-while-loading |
| V-U18 | The files a fresh install creates (profile installer, code cache) | extend the wipe baseline |
| V-U19 | Predictive back with `PredictiveBackHandler` on API 33–37 at target 37 | plain `BackHandler` |
| V-U20 | Whether an accessibility tool (TalkBack's describe-screen) can capture a secure window on API 36 QPR2+ and 37 | declare (it is declared either way) |
| V-U21 | `LocaleManager` and `generateLocaleConfig` with AGP 9.4 | system language only |
| V-U22 | `media3-ui-compose` 1.11.0 renders on a `TextureView` inside a secure window with no View popup | own `TextureView` player surface |
| V-U23 | Two apps claiming `ghost://`: the platform's chooser behaviour | declare; QR only |
| V-U24 | Edge-to-edge, IME insets and two panes at target 37 on a 600-dp emulator | single pane on large screens |

---

## Appendix D: Sources (accessed 2026-10-03 unless stated)

**Repository** (at `197b2b4`): `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`; `output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf`; `docs/adr/ADR-01` … `ADR-39`; `docs/THREAT_MODEL_v2.1.md`; `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`; `docs/STATUS.md`; `docs/ci-self-hosted.md`; `docs/design/faza7-sync-engine.md`, `faza8-issuer.md`, `faza9-dm.md`, `faza10-forum.md`, `faza11-media.md`; `docs/design/faza14-distribution.md` on branch `p14-design` (`58117c0`); `docs/reviews/2026-09-25-faza9-review.md`; `ghost/test-harness/privacy/INVARIANTS.md`; the Kotlin sources and gates cited in Appendix C.1.

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
- https://developer.android.com/blog/posts/enhancing-android-security-stop-malware-from-snooping-on-your-app-data (2025-12-11)
- https://learn.microsoft.com/en-us/dotnet/api/android.views.view.setaccessibilitydatasensitive
- https://learn.microsoft.com/en-us/dotnet/api/android.accessibilityservices.accessibilityserviceinfo.isaccessibilitytool
- https://learn.microsoft.com/en-us/dotnet/api/android.app.activity.setrecentsscreenshotenabled
- https://learn.microsoft.com/en-us/dotnet/api/android.security.keystore.keygenparameterspec.builder.setuserauthenticationrequired
- https://learn.microsoft.com/en-us/dotnet/api/android.security.keystore.keygenparameterspec.builder.setunlockeddevicerequired
- https://dl.google.com/android/repository/sys-img/android/sys-img2-3.xml and `…/google_apis/sys-img2-3.xml`

**Jetpack, libraries, tools**
- https://developer.android.com/jetpack/androidx/releases/navigation3; https://dl.google.com/android/maven2/androidx/navigation3/ (POMs 1.2.0)
- https://developer.android.com/develop/ui/compose/bom/bom-mapping
- https://developer.android.com/develop/ui/compose/accessibility/testing
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

**AOSP and AndroidX sources read by the research digests** (not re-read for this draft; each fact marked "src" in §2.3 and checked by a V-U item): `frameworks/base` (`ActivityRecord.java`, `AbsAppSnapshotController.java`, `AssistStructure.java`, `DisplayContent.java`, `WindowState.java`, `ClipboardService.java`, `ClipDescription.java`, `AbstractAccessibilityServiceConnection.java`, `AccessibilityManagerService.java`, `View.java`), `frameworks/native` (`screencap.cpp`, `LayerFE.cpp`), `frameworks/support` (`AndroidDialog.android.kt`, `AndroidPopup.android.kt`, `ModalBottomSheet.android.kt`, `AndroidComposeView.android.kt`, `AndroidComposeViewAccessibilityDelegateCompat.android.kt`, `AndroidClipboardManager.android.kt`, `ComposeUiTestExt.android.kt`).
