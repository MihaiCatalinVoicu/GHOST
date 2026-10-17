plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.messaging"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
        // `DeviceGateSuite` (Phase 9 design §15.9; slice S12) through the plain-Instrumentation
        // runner of `:crypto-bridge`'s `src/deviceRunner` (§16.3 adds no Gradle coordinate).
        testInstrumentationRunner = "org.ghost.messaging.device.MessagingDeviceRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // JVM test infrastructure shared with :storage and :sync (JdbcSqlExecutor), Phase 7 design
    // §1.5: a plain source directory, so no experimental test-fixtures support is needed. The
    // owner-side steps of S6 are proved against a real migrated v5 database, not against a mock:
    // every guard this slice relies on (the `dm_self_monotonic` trigger, the partial unique index
    // of `olm_prekey_gen`, the REPLACE guards) lives in the schema.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
            // The entitlement world of §15.1 variant (b) (`entworld/`): the Phase 7 sync harness
            // (World, Client, the driver, the relay port, ModelRelay, the invariants and the Runner)
            // and the Phase 8 `EntHarness` (EntWorld, EntClient, the ModelIssuer, the
            // ModelRedeemRelays, the harness native layer) as plain source directories, exactly the
            // pattern `:entitlement` uses for the sync harness. Their own tests do not run here (the
            // filter below); only the classes are reused, so a DM world drives the **real**
            // entitlement engine, redeem lane and registration lane instead of a redeem fairy.
            kotlin.srcDir("../sync/src/test/kotlin")
            kotlin.srcDir("../entitlement/src/test/kotlin")
            // `DmEquivalence`'s declarations (design §22.37): the crash worlds switch MC-20's mutant
            // and KC5b's replayed binding on one DM context with `bindingHooks`, a test-vectors
            // entry point of the host library. A test source set, never a release one (G-DM5).
            kotlin.srcDir("../crypto-bridge/src/equivalence/kotlin")
        }
        getByName("androidTest") {
            kotlin.srcDir("../crypto-bridge/src/deviceRunner/kotlin")
            // §15.9 item 3: the device suite runs the **shipped** library, `libghost_client_net.so`
            // with the DM symbols, which `:network` packages into the app. A library module's test
            // APK does not inherit it, so the suite packages the same directory the CI jobs fill
            // from `scripts/build-native.sh` (`dm-emulator.yml` does it before assembling). Empty
            // locally: the suite then fails at `System.loadLibrary`, it does not skip.
            jniLibs.srcDir(file("../network/src/main/jniLibs"))
        }
    }
}

dependencies {
    // Phase 9 design §13.1: `:messaging` depends on `:crypto-bridge`, the `:sync` API and
    // `:identity`. It has **no** dependency on `:entitlement`: the K20 activation hook points the
    // other way (`:entitlement` calls into this module through a port that `:app` wires, §13.4),
    // and the ES slot table reaches the owner steps through `EsSlots`, for the same reason.
    api(project(":sync"))
    implementation(project(":crypto-bridge"))
    // Phase 11 design §13.1 (slice S5): the sender pipeline lives in `:media`; the MEDIA-* steps
    // and the facade's media half drive its stores and ports (G-DM1's text rule still bans a
    // network name in either module).
    implementation(project(":media"))
    // `ZBase32`: the `ghost://contact/` link of §3.3 is the same encoding as the `ghost1…` string
    // and the invite payload, and a second copy of an alphabet is a second place to get it wrong.
    implementation(project(":identity"))
    testImplementation(libs.junit)
    testImplementation(libs.sqlite.jdbc)
    // `DmSessionStates` (design §22.38 items 11 and 12) opens every stored session state on the JVM,
    // independently of the native code that wrapped it: ChaCha20-Poly1305 from Bouncy Castle, the
    // coordinate the project already ships (`:identity`, `:network`) and tests with (§16.3). Those
    // modules declare it `implementation`, so it is on this source set's runtime classpath but not
    // on its compile classpath: without this line the unit tests do not compile under AGP.
    testImplementation(libs.bouncycastle.bcprov)
    // **Test only**, and only for the entitlement world of §15.1 variant (b): its clients carry the
    // real entitlement engine (the Phase 8 `EntHarness` compiled in above), so the unit-test
    // classpath needs `:entitlement` and the `:network` JNI surface it names. The production graph
    // keeps §13.1's direction — nothing in `src/main` can see either.
    testImplementation(project(":entitlement"))
    testImplementation(project(":network"))
    // The emulator suite (§15.9): JUnit 4 through `DeviceRunner`, and SQLCipher opened the way
    // `:storage` opens it. Every coordinate is one the project already ships or tests with (§16.3).
    androidTestImplementation(libs.junit)
    // The S5 device smoke's `VideoSource.mediaItem()` (media3's type crosses the test boundary).
    androidTestImplementation(libs.androidx.media3.common)
    // S9's media privacy world drives `prepareVideo` on the JVM (the same crossing as the S5 smoke).
    testImplementation(libs.androidx.media3.common)
    // Slice S7's playback device test drives the player (GhostPlayer returns ExoPlayer).
    androidTestImplementation(libs.androidx.media3.exoplayer)
    androidTestImplementation(libs.sqlcipher.android)
    androidTestImplementation(libs.androidx.sqlite)
    // `DeviceWorld.onion` computes the v3 checksum with the SHA3 `:network`'s `OnionAddress` checks
    // it with (Bouncy Castle, already shipped): Android has no "SHA3-256" `MessageDigest`.
    androidTestImplementation(libs.bouncycastle.bcprov)
}

// The entitlement world (§15.1 variant (b)): the sync and entitlement harness sources compiled into
// this module's unit tests use `:sync` and `:entitlement` internals (SyncEngine, Session, Steps; the
// entitlement engine's steps and stores), so the unit-test compilation is a friend of both library
// jars — the same arrangement `:entitlement` has with `:sync`. Their own test classes are excluded:
// `:sync` and `:entitlement` run them, and running them twice would only double the build.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    if (name.startsWith("compile") && name.endsWith("UnitTestKotlin")) {
        val variant = name.removePrefix("compile").removeSuffix("UnitTestKotlin")
        val jars = listOf(":sync", ":entitlement").map { friend ->
            project(friend).layout.buildDirectory.file(
                "intermediates/compile_library_classes_jar/${variant.lowercase()}/bundleLibCompileToJar$variant/classes.jar",
            )
        }
        jars.forEach { friendPaths.from(it) }
        // The path is the Android Gradle plugin's intermediate layout, not an API: when a plugin
        // update moves it, say so instead of failing on every `internal` the harness sources use.
        val files = jars.map { it.get().asFile }
        doFirst {
            val missing = files.filter { !it.exists() }
            check(missing.isEmpty()) { "the friend jars of the entitlement world are not where the Android Gradle plugin put them before: $missing" }
        }
    }
}

// The exclusion below is by package, so a test of this module's own under either package would be
// dropped without a word: refused here instead.
listOf("org/ghost/sync", "org/ghost/entitlement").flatMap { p -> listOf(file("src/test/kotlin/$p"), file("src/test/java/$p")) }
    .filter { it.exists() }
    .let { shadowed -> check(shadowed.isEmpty()) { "a :messaging test under a package the unit-test filter excludes would never run: $shadowed" } }

tasks.withType<Test>().configureEach {
    filter {
        excludeTestsMatching("org.ghost.sync.*")
        excludeTestsMatching("org.ghost.entitlement.*")
    }
    // `TestKeys` reads the committed test keys by a path relative to the module directory (the same
    // depth from here as from `:entitlement`): declared as an input, as `:entitlement` declares it,
    // so a change to the keys re-runs the entitlement-world tests.
    inputs.file(rootProject.file("../issuer/crates/entitlement/tests/fixtures/test_keys.txt"))
        .withPropertyName("entitlementTestKeys")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

// The send-and-receive worlds run the **real** DM cryptography through the host build
// `ghost-dm-host` (Phase 9 design §2.7, §15.1): the seal, the ratchet and the KEM decide whether
// the other device can open what this one sealed, and a fake of them would prove its own
// arithmetic. The `android` CI job builds the library with
// `cargo build -p ghost-dm-host --release --locked --features provenance` (S11: every seal then
// asserts T35's key kinds) and passes `-Dghost.dm.native=<path>`;
// without it `DmWorld.nativeAvailable()` is false and those worlds report themselves skipped,
// while the owner-side worlds of S6 — which fake the derivations deliberately — still run.
//
// Declared as a test input so a rebuilt library re-runs the tests instead of reusing a cached
// result (build caching is on), exactly as `:crypto-bridge` declares it.
val hostLibrary = providers.systemProperty("ghost.dm.native")
    .orElse(providers.gradleProperty("ghost.dm.native"))

// The S10 exit-gate harness's own knobs (Phase 9 design §15.1 "harness `-D` properties declared as
// test inputs"; §15.3's gate scale, §15.4's seed count). Without the forwarding they reach the
// Gradle JVM and not the test JVM, so `-Dghost.dm.crash=full` would silently run the PR scale and
// the gate would report a number it did not measure — which is the one failure mode a report-checked
// gate must not have.
val harnessProperties = listOf(
    "ghost.dm.crash",
    "ghost.dm.sample",
    "ghost.dm.seeds",
    "ghost.dm.threads",
    "ghost.dm.report",
    // S11's privacy worlds (§15.6): the scale (`gate` for N = 600 over 42 days, `off` to skip
    // them), one seed pair by index or the first n (`all` for the ten pinned ones), and the report
    // `dm-report-check.sh privacy-*` reads.
    "ghost.dm.privacy",
    "ghost.dm.privacy.seed",
    "ghost.dm.privacy.seeds",
    "ghost.dm.privacy.report",
    // S10/S11's channel harness knobs, the same forwarding (without it they reach the Gradle JVM
    // and not the test JVM): the SCN-M20 seed selection (§12.5) and the channel privacy world's
    // seed selection and day count (§12.7; `ghost.channel.privacy.days` is the gate-scale knob).
    "ghost.channel.seed",
    "ghost.channel.seeds",
    "ghost.channel.report",
    "ghost.channel.report.lenient",
    "ghost.channel.privacy.seed",
    "ghost.channel.privacy.seeds",
    "ghost.channel.privacy.days",
    // S9's media harness knobs (Phase 11 design §15.1): the media privacy world's scale
    // (`ghost.media.privacy=gate` for N = 300 over 28 days), the crash-enumeration shard
    // selection of `media-exit-gate.sh`, and the media report `media-report-check.sh` reads.
    "ghost.media.privacy",
    "ghost.media.shard",
    "ghost.media.shards",
    "ghost.media.report",
)

tasks.withType<Test>().configureEach {
    // Phase 9 review GATES-7: the DM reports (`build/reports/dm/report.txt`, `privacy.txt`) are
    // written by the tests as a side effect, not declared outputs, so a test task restored
    // FROM-CACHE wrote none and the `android` job's report checks failed on a missing file. The
    // gate workflows pass `--rerun` for this reason; `./gradlew build` does not. A task whose
    // evidence is a side effect is never taken from the cache.
    outputs.cacheIf("the DM reports are a side effect of the run, not a cached output") { false }
    inputs.property("ghost.dm.native", hostLibrary.orElse(""))
    hostLibrary.orNull?.let { path ->
        systemProperty("ghost.dm.native", path)
        inputs.file(path)
            .withPropertyName("dmHostLibrary")
            .withPathSensitivity(PathSensitivity.NAME_ONLY)
    }
    for (name in harnessProperties) {
        val value = providers.systemProperty(name).orElse(providers.gradleProperty(name))
        inputs.property(name, value.orElse(""))
        value.orNull?.let { systemProperty(name, it) }
    }
    // The test JVM's heap (Phase 9 design §22.33). Without it Gradle's default of 512 MB applies, and
    // the privacy world at the gate scale (N = 600 over 42 days) outgrows it: its first nightly run
    // (2026-09-25) failed on all ten seed pairs with a bare `java.sql.SQLException` out of
    // `world.run()`, and the local reproduction spent its time in full collections with the old
    // generation 99 % full — the relay's retained blobs and the recorded view are held for the joins
    // at the end. 2 GB is what `:sync` and `:entitlement` give their harnesses and covers every world
    // at the PR scale; `dm-privacy-gate.yml` raises it with `-Dghost.dm.heap` for the gate scale.
    maxHeapSize = providers.systemProperty("ghost.dm.heap")
        .orElse(providers.gradleProperty("ghost.dm.heap"))
        .orElse("2g")
        .get()
}
