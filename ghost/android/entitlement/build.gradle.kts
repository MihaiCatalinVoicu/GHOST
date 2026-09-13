plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.entitlement"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // JVM test infrastructure shared with :storage and :sync (JdbcSqlExecutor), and the Phase 7 sync
    // harness (World, Client, the harness driver and relay port, ModelRelay, the invariants, Runner
    // and Exhaustive), which the :entitlement harness extends with the real entitlement engine
    // (Phase 8 design §11.9, §19.17 point 5): plain source directories, as in :sync. The sync tests
    // among them run only in :sync (the filter below).
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
            kotlin.srcDir("../sync/src/test/kotlin")
        }
    }
}

dependencies {
    // Phase 8 design §11.1: project dependencies only, no new Maven coordinate. :sync carries the
    // session participant API, the stores and the sync database; :storage the SQL executor;
    // :network the entitlement JNI surface; :identity invites, drop sealing and the identity.
    implementation(project(":storage"))
    implementation(project(":network"))
    implementation(project(":sync"))
    implementation(project(":identity"))
    testImplementation(libs.junit)
    // JVM SQLite for store tests over the real schema (already a :sync and :storage test dependency).
    testImplementation(libs.sqlite.jdbc)
}

// The sync harness compiled into this module's unit tests uses :sync internals (SyncEngine, Session,
// Steps): the unit-test compilation is a friend of the :sync library classes it compiles against.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    if (name.startsWith("compile") && name.endsWith("UnitTestKotlin")) {
        val variant = name.removePrefix("compile").removeSuffix("UnitTestKotlin")
        friendPaths.from(
            project(":sync").layout.buildDirectory.file(
                "intermediates/compile_library_classes_jar/${variant.lowercase()}/bundleLibCompileToJar$variant/classes.jar",
            ),
        )
    }
}

// The conformance and vector tests replay protocol/test-vectors files and the committed test keys
// (design §13.2, §2.9, §11.9): declared as test inputs so a change to one of them alone re-runs the
// tests (build caching is on).
//
// Exit-gate harness settings (design §13.2, §13.6) reach the test JVM from `-D` or `-P`:
// ghost.entitlement.seeds (seeded liveness worlds, default 1000; 20000 in the entitlement-exit-gate
// workflow), ghost.entitlement.seed (replay one seed), ghost.entitlement.exhaustive (full: every
// double crash in both journal modes; default: every 8th first-crash class, WAL only),
// ghost.entitlement.shard=i/n (one n-th of the crash classes, double crashes and seeds: the
// exit-gate matrix), ghost.entitlement.threads and ghost.entitlement.harness.dir. The
// Phase 7 harness compiled here reads its own names, so exhaustive, threads and harness.dir are
// forwarded under them too.
val harnessProperties = listOf(
    "ghost.entitlement.seeds", "ghost.entitlement.seed", "ghost.entitlement.exhaustive", "ghost.entitlement.shard",
    "ghost.entitlement.threads", "ghost.entitlement.harness.dir",
).associateWith { name -> providers.systemProperty(name).orElse(providers.gradleProperty(name)) }
val syncHarnessNames = mapOf(
    "ghost.entitlement.exhaustive" to "ghost.sync.exhaustive",
    "ghost.entitlement.threads" to "ghost.sync.threads",
    "ghost.entitlement.harness.dir" to "ghost.sync.harness.dir",
)
val vectorFiles = listOf("blind_rsa_pp2.txt", "issuer_semantics.txt", "redeem.txt", "entitlement_policy.txt")
tasks.withType<Test>().configureEach {
    filter {
        excludeTestsMatching("org.ghost.sync.*")
    }
    for (file in vectorFiles) {
        inputs.file(rootProject.file("../protocol/test-vectors/$file"))
            .withPropertyName("vectors-$file")
            .withPathSensitivity(PathSensitivity.RELATIVE)
    }
    inputs.file(rootProject.file("../issuer/crates/entitlement/tests/fixtures/test_keys.txt"))
        .withPropertyName("testKeys")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    for ((name, value) in harnessProperties) {
        inputs.property(name, value.orElse(""))
        value.orNull?.let { v ->
            systemProperty(name, v)
            syncHarnessNames[name]?.let { systemProperty(it, v) }
        }
    }
    maxHeapSize = "2g"
    // K/R counts, mutant results and timings of this run (the entitlement-exit-gate job summary).
    val harnessReport = layout.buildDirectory.dir("harness")
    doFirst { harnessReport.get().asFile.deleteRecursively() }
}
