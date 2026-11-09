plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.media"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // The `MediaCrypto` facade answers `Unavailable` (not "not mocked") where the native library
    // is absent, but the `Uri` a `VideoExport` fake ignores would throw — return defaults instead.
    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    // JVM test infrastructure shared with :storage, :sync and :messaging (JdbcSqlExecutor, the migrated-database
    // fixtures), Phase 11 design §15.1: `:media`'s own unit tests stay module-local (the store, the reconcile, fakes of
    // the ports); a plain source directory, so no experimental test-fixtures support is needed.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
        }
    }
}

dependencies {
    // Phase 11 design §13.1: `:media` depends on `:crypto-bridge` (S2), the `:sync` API, `:storage` and Media3 (S5 to S7). The
    // store of slice S3 needs only the last two: the transaction a write takes from its caller is `:sync`'s, the executor a
    // read takes is `:storage`'s. Neither dependency brings a network class this module may name (gate G-DM1, extended
    // to `org.ghost.media.store`): `:sync` exposes `:network` as an `api` dependency, which is why that rule is a text gate.
    api(project(":sync"))
    api(project(":storage"))
    // Phase 11 §13.1 (slice S5): `MediaCrypto` is the only way the sender pipeline reaches the media
    // cryptography (the sealer/reader port of `SealingChannel`).
    implementation(project(":crypto-bridge"))
    // Phase 11 §13.1 (slice S5): Media3 1.11.1 (design §16.3) for the sender pipeline — Transformer,
    // `FragmentedMp4Muxer`, the effects. The no-plaintext rules of §10.2 gate the playback half (S7).
    implementation(libs.androidx.media3.transformer)
    implementation(libs.androidx.media3.exoplayer)
    implementation(libs.androidx.media3.muxer)
    implementation(libs.androidx.media3.effect)
    implementation(libs.androidx.media3.common)
    implementation(libs.androidx.media3.datasource)
    testImplementation(libs.junit)
    // JVM SQLite for the store tests (SQLCipher itself needs a device).
    testImplementation(libs.sqlite.jdbc)
}

// The JDK replay of the media vectors (Phase 11 design faza11-media.md §3.9, §15.2 item 1; slice S1):
// the vector files and the goldens it reads are test inputs, so a regenerated file re-runs the test
// instead of reusing a cached result (build caching is on).
tasks.withType<Test>().configureEach {
    // The media exit gate's cross-module close-out lines (§15.3; MediaStoreScenarioTest's SCN-ME
    // storage half): forward the report path to the test JVM, exactly like :messaging's
    // harnessProperties block does.
    providers.systemProperty("ghost.media.report")
        .orElse(providers.gradleProperty("ghost.media.report")).orNull
        ?.let { systemProperty("ghost.media.report", it) }
    inputs.files(
        rootProject.fileTree("../protocol/test-vectors") {
            include("media_object.txt", "media_descriptor.txt", "media_sniff.txt", "media_jpeg.txt", "media-goldens/**")
        },
    ).withPropertyName("mediaVectors").withPathSensitivity(PathSensitivity.RELATIVE)
}
