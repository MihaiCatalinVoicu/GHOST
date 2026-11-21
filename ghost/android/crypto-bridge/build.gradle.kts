plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.crypto.bridge"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
        // The emulator job's runner (Phase 9 design §15.9; slice S12): JUnit 4 through a plain
        // Instrumentation, because §16.3 adds no Gradle coordinate and the AndroidX runner is one.
        testInstrumentationRunner = "org.ghost.crypto.bridge.device.CryptoBridgeDeviceRunner"
    }

    // The host/Android equivalence test (§15.9 item 7, §22.8.10 point 6; slice S12). `src/equivalence`
    // holds `DmEquivalence`, the test-vectors entry point's declaration and the comparator: the JVM
    // tests record the host fixture with it, the `androidTest` APK replays it. Neither is a release
    // source set (gate G-DM5).
    sourceSets {
        getByName("test") {
            kotlin.srcDir("src/equivalence/kotlin")
        }
        getByName("androidTest") {
            kotlin.srcDir("src/equivalence/kotlin")
            kotlin.srcDir("src/deviceRunner/kotlin")
            // The emulator's test library: `ghost-dm-host` built for `x86_64-linux-android` by
            // `dm-emulator.yml` into this directory (`<dir>/x86_64/libghost_dm_host.so`).
            jniLibs.srcDir(file("build/dm-test-jni"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // The `gate` build type (Phase 9 design §21.13 point 7; slice S12): the debug build plus
    // `src/gate`, which holds the debug key-change hook §21.13 point 7 puts in this module. `:app`'s
    // `gate` variant consumes it; no other variant compiles `src/gate` (gate G-DM5).
    buildTypes {
        create("gate") {
            initWith(getByName("debug"))
        }
        create("peer") {
            initWith(getByName("gate"))
        }
        create("peer2") {
            initWith(getByName("gate"))
        }
    }
    sourceSets {
        getByName("peer") {
            // The local two-device variant consumes the same gate hook as `:app`'s peer build.
            kotlin.srcDir("src/gate/kotlin")
        }
        getByName("peer2") {
            kotlin.srcDir("src/gate/kotlin")
        }
    }
}

dependencies {
    // No production dependency at all: this module is the JNI wrapper and the typed facade, and
    // the native code lives in libghost_client_net.so (Phase 9 design §13.1, §2.3). It must not
    // gain :storage or :messaging — the facade takes row values, not transactions (§2.6 note in
    // DmSessions).
    testImplementation(libs.junit)
    // The device suites run through `org.ghost.device.DeviceRunner` on `junit:junit` alone (§16.3).
    androidTestImplementation(libs.junit)
}

// The equivalence test's assets (§15.9 item 7): the case file and the host fixture the JVM test
// `DmEquivalenceHostTest` writes to build/dm-equivalence/. `dm-emulator.yml` runs that test first,
// with the same `-Dghost.dm.commit`, and the device test refuses a fixture of another commit.
// A missing host fixture is not an error here: the device test then fails on the missing asset,
// which is the loud outcome a skipped recording must have.
abstract class DmEquivalenceAssets : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val sources: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun copy() {
        val directory = outputDirectory.get().asFile
        directory.deleteRecursively()
        directory.mkdirs()
        for (file in sources.files) if (file.isFile) file.copyTo(directory.resolve(file.name))
    }
}

val dmEquivalenceAssets = tasks.register<DmEquivalenceAssets>("dmEquivalenceAssets") {
    sources.from(rootProject.file("../protocol/test-vectors/dm_equivalence.txt"))
    sources.from(layout.buildDirectory.file("dm-equivalence/dm_equivalence_host.txt"))
    outputDirectory.set(layout.buildDirectory.dir("generated/dmEquivalenceAssets"))
}
androidComponents {
    onVariants { variant ->
        variant.androidTest?.sources?.assets?.addGeneratedSourceDirectory(dmEquivalenceAssets, DmEquivalenceAssets::outputDirectory)
    }
}

// The commit the equivalence fixture is recorded for (§15.9: "the comparison refuses fixtures from
// another commit"), forwarded to the JVM tests.
val dmCommit = providers.systemProperty("ghost.dm.commit").orElse(providers.gradleProperty("ghost.dm.commit"))
tasks.withType<Test>().configureEach {
    inputs.property("ghost.dm.commit", dmCommit.orElse(""))
    inputs.file(rootProject.file("../protocol/test-vectors/dm_equivalence.txt"))
        .withPropertyName("dmEquivalenceCases")
        .withPathSensitivity(PathSensitivity.NAME_ONLY)
    dmCommit.orNull?.let { systemProperty("ghost.dm.commit", it) }
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
