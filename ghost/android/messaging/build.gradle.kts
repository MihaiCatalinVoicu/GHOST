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
    // `ZBase32`: the `ghost://contact/` link of §3.3 is the same encoding as the `ghost1…` string
    // and the invite payload, and a second copy of an alphabet is a second place to get it wrong.
    implementation(project(":identity"))
    testImplementation(libs.junit)
    testImplementation(libs.sqlite.jdbc)
    // **Test only**, and only for the entitlement world of §15.1 variant (b): its clients carry the
    // real entitlement engine (the Phase 8 `EntHarness` compiled in above), so the unit-test
    // classpath needs `:entitlement` and the `:network` JNI surface it names. The production graph
    // keeps §13.1's direction — nothing in `src/main` can see either.
    testImplementation(project(":entitlement"))
    testImplementation(project(":network"))
    // The emulator suite (§15.9): JUnit 4 through `DeviceRunner`, and SQLCipher opened the way
    // `:storage` opens it. Every coordinate is one the project already ships or tests with (§16.3).
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.sqlcipher.android)
    androidTestImplementation(libs.androidx.sqlite)
}

// The entitlement world (§15.1 variant (b)): the sync and entitlement harness sources compiled into
// this module's unit tests use `:sync` and `:entitlement` internals (SyncEngine, Session, Steps; the
// entitlement engine's steps and stores), so the unit-test compilation is a friend of both library
// jars — the same arrangement `:entitlement` has with `:sync`. Their own test classes are excluded:
// `:sync` and `:entitlement` run them, and running them twice would only double the build.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    if (name.startsWith("compile") && name.endsWith("UnitTestKotlin")) {
        val variant = name.removePrefix("compile").removeSuffix("UnitTestKotlin")
        for (friend in listOf(":sync", ":entitlement")) {
            friendPaths.from(
                project(friend).layout.buildDirectory.file(
                    "intermediates/compile_library_classes_jar/${variant.lowercase()}/bundleLibCompileToJar$variant/classes.jar",
                ),
            )
        }
    }
}

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
)

tasks.withType<Test>().configureEach {
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
}
