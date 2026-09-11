plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.sync"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // JVM test infrastructure shared with :storage (JdbcSqlExecutor), design §1.5: a plain source
    // directory, so no experimental test-fixtures support is needed.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
        }
    }
}

dependencies {
    // The public sync API exposes SqlExecutor (SyncTransaction.sql) and OnionAddress (RelayEntry).
    // No new production dependency (design §7.1 T7): both are GHOST modules.
    api(project(":storage"))
    api(project(":network"))
    testImplementation(libs.junit)
    // JVM SQLite for store tests over file databases; SQLCipher itself needs a device.
    testImplementation(libs.sqlite.jdbc)
}

// ErrorPolicyTest parses the error-category table of client-core/README.md (design §3.6) and
// ModelRelayConformanceTest replays protocol/test-vectors/relay_semantics.txt (design §8.7):
// declare both as test inputs so a change to either file alone re-runs the tests (build caching
// is on).
//
// Exit-gate harness settings (design §8.5, §8.10) reach the test JVM from `-D` or `-P`:
// ghost.sync.seeds (seeded worlds, default 1000; 20000 in the sync-exit-gate CI job),
// ghost.sync.seed (replay one seed), ghost.sync.exhaustive=full (double crashes in both journal
// modes), ghost.sync.threads and ghost.sync.harness.dir. They are test inputs, so changing one
// re-runs the tests instead of reusing a cached result.
val harnessProperties = listOf("ghost.sync.seeds", "ghost.sync.seed", "ghost.sync.exhaustive", "ghost.sync.threads", "ghost.sync.harness.dir")
    .associateWith { name -> providers.systemProperty(name).orElse(providers.gradleProperty(name)) }
tasks.withType<Test>().configureEach {
    inputs.file(rootProject.file("../client-core/README.md"))
        .withPropertyName("clientCoreErrorCategories")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.file(rootProject.file("../protocol/test-vectors/relay_semantics.txt"))
        .withPropertyName("relaySemanticsVectors")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    for ((name, value) in harnessProperties) {
        inputs.property(name, value.orElse(""))
        value.orNull?.let { systemProperty(name, it) }
    }
    maxHeapSize = "2g"
    // K/R counts, mutant results and timings of this run (the sync-exit-gate job summary).
    val harnessReport = layout.buildDirectory.dir("harness")
    doFirst { harnessReport.get().asFile.deleteRecursively() }
}