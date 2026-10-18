import java.security.MessageDigest

plugins {
    alias(libs.plugins.android.library)
}

// The emulator probe's lyrebird assets (PT-1, the V-T6 re-run): the same generated `pt/` tree
// :app packages. The transformation mirrors `:app`'s `ptAssets` task (app/build.gradle.kts) —
// `<abi>/lyrebird` names, the sums file in the APK format, the drift check — so the test APK and
// the shipping APK carry byte-identical PT assets from the same `ghost/third_party/lyrebird/out`.
abstract class PtTestAssets : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val sources: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun write() {
        val directory = outputDirectory.get().asFile
        directory.deleteRecursively()
        directory.mkdirs()
        val pt = directory.resolve("pt")
        val byName = sources.files.filter { it.isFile }.associateBy { it.name }
        val sumsFile = byName["SHA256SUMS"] ?: return
        val sums = HashMap<String, String>()
        for (line in sumsFile.readLines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            val parts = trimmed.split(Regex("\\s+"))
            if (parts.size == 2 && parts[0].matches(Regex("[0-9a-fA-F]{64}"))) sums[parts[1]] = parts[0].lowercase()
        }
        val out = StringBuilder("# GHOST Phase 12 lyrebird APK-asset sums (generated; G-T4's twin)\n")
        for ((fileName, abi) in listOf("lyrebird-android-arm64" to "arm64-v8a", "lyrebird-android-amd64" to "x86_64")) {
            val expected = sums[fileName] ?: continue
            val binary = byName[fileName] ?: continue
            val actual = binary.inputStream().use { stream ->
                val digest = MessageDigest.getInstance("SHA-256")
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = stream.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
                digest.digest().joinToString("") { "%02x".format(it) }
            }
            check(actual == expected) {
                "$fileName drifts from SHA256SUMS ($actual != $expected); re-run third_party/lyrebird/BUILD.sh"
            }
            val target = pt.resolve(abi)
            target.mkdirs()
            binary.copyTo(target.resolve("lyrebird"), overwrite = true)
            out.append("$expected  $abi/lyrebird\n")
        }
        pt.mkdirs()
        pt.resolve("SHA256SUMS").writeText(out.toString())
    }
}

val lyrebirdOutDir = rootProject.layout.projectDirectory.dir("../third_party/lyrebird/out")
val ptTestAssets = tasks.register<PtTestAssets>("ptTestAssets") {
    sources.from(lyrebirdOutDir.asFileTree.matching { include("SHA256SUMS", "lyrebird-android-*") })
    outputDirectory.set(layout.buildDirectory.dir("generated/ptTestAssets"))
}

android {
    namespace = "org.ghost.network"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
        // The PT-1 emulator probe (Phase 12 §12.1 V-T6 re-run): JUnit 4 through the plain
        // instrumentation of `crypto-bridge`'s deviceRunner, the emulator job's runner discipline.
        testInstrumentationRunner = "org.ghost.network.PtDeviceRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // JVM SQLite for the storage-side suites (PT-U7/U9); the shared executor lives in :storage's
    // test source set, the same pattern :app uses for its end-to-end wiring test. The androidTest
    // half carries the deviceRunner sources and the lyrebird assets the probe extracts.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
        }
        getByName("androidTest") {
            kotlin.srcDir("../crypto-bridge/src/deviceRunner/kotlin")
        }
    }
}

// The probe's assets join the androidTest variants through the Variant API (AGP disallows
// Provider-typed source directories on the SourceSet API), the `dmEquivalenceAssets` pattern.
androidComponents {
    onVariants { variant ->
        variant.androidTest?.sources?.assets?.addGeneratedSourceDirectory(ptTestAssets, PtTestAssets::outputDirectory)
    }
}

dependencies {
    // The bridge-line table's DAO (Phase 12 §8.1: written through :network's repository class).
    implementation(project(":storage"))
    // SHA3-256 for the v3 onion checksum (already shipped via :identity, ADR-17).
    implementation(libs.bouncycastle.bcprov)
    testImplementation(libs.junit)
    // JDBC SQLite for the PT-U7/U9 storage-side suites on the host build.
    testImplementation(libs.sqlite.jdbc)
    // The device suites run through `org.ghost.device.DeviceRunner` on `junit:junit` alone.
    androidTestImplementation(libs.junit)
}

// The JVM suites run the real native validator through the host build of `ghost-client-net`
// (Phase 12 slice S2): the `android` CI job builds it with
// `cargo build -p ghost-client-net --release --locked` and passes
// `-Dghost.net.native=<path to the cdylib>` (the shipped crate itself, host-compiled — the same
// symbols `libghost_client_net.so` carries). Declared as a test input so a rebuilt library
// re-runs the tests; without the property the native tests report themselves skipped and the
// pure-JVM suites still run, the repo's standing rule.
val netHostLibrary = providers.systemProperty("ghost.net.native")
    .orElse(providers.gradleProperty("ghost.net.native"))
tasks.withType<Test>().configureEach {
    inputs.property("ghost.net.native", netHostLibrary.orElse(""))
    netHostLibrary.orNull?.let { path ->
        systemProperty("ghost.net.native", path)
        inputs.file(path)
            .withPropertyName("netHostLibrary")
            .withPathSensitivity(PathSensitivity.NAME_ONLY)
    }
    // PtInstallerReleaseTwinTest reads the production source it pins (the G-DM5 twin rule for
    // the PT extractor: no debug-only bypass around the hash verification).
    systemProperty("ghost.network.sourcedir", file("src/main/kotlin").absolutePath)
    inputs.dir("src/main/kotlin")
        .withPropertyName("networkMainSources")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

// OnionAddressTest reads the vector file shared with the Rust parser: declare it as a test input
// so a change to the vectors alone re-runs the tests (build caching is on).
tasks.withType<Test>().configureEach {
    inputs.file(rootProject.file("../protocol/test-vectors/onion_addresses.txt"))
        .withPropertyName("sharedOnionVectors")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}
