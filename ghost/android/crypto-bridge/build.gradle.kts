plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.crypto.bridge"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // No production dependency at all: this module is the JNI wrapper and the typed facade, and
    // the native code lives in libghost_client_net.so (Phase 9 design §13.1, §2.3). It must not
    // gain :storage or :messaging — the facade takes row values, not transactions (§2.6 note in
    // DmSessions).
    testImplementation(libs.junit)
}

// The JVM tests run the **real ratchet** through the host build `ghost-dm-host` (Phase 9 design
// §2.7, §15.1; evidence V-5): the `android` CI job builds it with
// `cargo build -p ghost-dm-host --release --locked` and passes
// `-Dghost.dm.native=<path to the cdylib>`. Declared as a test input so a rebuilt library re-runs
// the tests instead of reusing a cached result (build caching is on). Without the property the
// native tests report themselves skipped and the pure-JVM decoder tests still run, so a developer
// without the Rust toolchain can still build and test this module.
val hostLibrary = providers.systemProperty("ghost.dm.native")
    .orElse(providers.gradleProperty("ghost.dm.native"))
tasks.withType<Test>().configureEach {
    inputs.property("ghost.dm.native", hostLibrary.orElse(""))
    hostLibrary.orNull?.let { path ->
        systemProperty("ghost.dm.native", path)
        inputs.file(path)
            .withPropertyName("dmHostLibrary")
            .withPathSensitivity(PathSensitivity.NAME_ONLY)
    }
}
