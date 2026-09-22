plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.messaging"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
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
