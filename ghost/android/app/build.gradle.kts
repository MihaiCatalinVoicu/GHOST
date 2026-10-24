import java.security.MessageDigest

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "org.ghost.app"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "org.ghost.app"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.1.0-devpreview"
        // The Tor core (libghost_client_net.so) is built for these ABIs only (ADR-19). Other devices
        // get INSTALL_FAILED_NO_MATCHING_ABIS at install time instead of a crash at first use.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        // The release smoke test (Phase 9 design §15.9 item 3; slice S12) runs through the
        // plain-Instrumentation runner of `:crypto-bridge`'s `src/deviceRunner` (§16.3).
        testInstrumentationRunner = "org.ghost.app.smoke.AppDeviceRunner"
    }

    // `dm-emulator.yml` runs the smoke test against the R8-shrunk release (§15.9 item 3, §21.13
    // point 5): `-Pghost.smoke.release=true` makes the release the tested build type and signs it
    // with the build machine's throwaway debug key — in that job only, which uploads nothing (G-L5).
    // Every other build keeps the unsigned, reproducible release of ADR-07 and tests the debug build.
    val smokeRelease = providers.gradleProperty("ghost.smoke.release").orNull == "true"
    testBuildType = if (smokeRelease) "release" else "debug"

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Signing is done offline (FR-8.2, ADR-07); CI produces the unsigned, reproducible artifact.
            // The one exception is the emulator job's smoke run (see `smokeRelease` above).
            if (smokeRelease) signingConfig = signingConfigs.getByName("debug")
        }
        debug {
            applicationIdSuffix = ".debug"
        }
        // The `gate` build type (Phase 9 design §15.10, §21.13 points 4 and 7, ADR-34; slice S12):
        // the debug build plus `src/gate` — the debug key-change hook of `:crypto-bridge`, the order
        // digest export and the instrumentation `scripts/device/dm-gate.sh` drives. Built locally or
        // in a job that uploads nothing, signed with the build machine's throwaway debug key,
        // installed only on the gate devices, never distributed (G-L5, ADR-39). Modules without a
        // `gate` source set of their own resolve to their debug variant.
        create("gate") {
            initWith(getByName("debug"))
            applicationIdSuffix = ".gate"
            matchingFallbacks += listOf("debug")
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    // The release pins the NDK the CI jobs install (Phase 9 design §21.13 point 2; slice S12): the
    // `android`, `reproducible` and `dm-emulator` jobs install `ndk;30.0.16248370` (ci.yml
    // NDK_PACKAGE), and AGP strips and packages the prebuilt Tor core with this one.
    ndkVersion = "30.0.16248370"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = false
    }

    testOptions {
        // Phase 13 §12.1: Robolectric reads the merged resources of the unit-tested variant.
        unitTests.isIncludeAndroidResources = true
    }

    packaging {
        // Reproducibility: drop build-host metadata that varies between machines.
        resources.excludes += setOf("META-INF/*.version", "META-INF/DEPENDENCIES", "kotlin/**")
        // Phase 9 review A-6: kotlinx-coroutines' JVM debug agent, a resource ART never runs.
        resources.excludes += "DebugProbesKt.bin"
        // The Tor core is already stripped by cargo; AGP must not re-strip it, so the packaged
        // bytes equal the reviewed build recorded in native-libs.sha256 (reproducible-build gate).
        jniLibs.keepDebugSymbols += "**/libghost_client_net.so"
    }

    dependenciesInfo {
        // Do not embed the Play Store dependency block: it is encrypted with a Google key and
        // breaks independent reproducibility verification (ADR-07).
        includeInApk = false
        includeInBundle = false
    }

    // `MessagingWiring`'s end-to-end test runs the real DM stack over a real migrated database
    // (Phase 9 design §13.7; slice S12), through the shared JDBC executor of :storage, :sync and
    // :messaging (Phase 7 design §1.5).
    //
    // `src/gate/digests` is the gate's order digest export (§15.10 steps 2 and 3): compiled into the
    // `gate` variant and into the JVM tests, which pin its pure half (`OrderDigestsTest`, S12
    // review) — this AGP creates unit tests for the tested build type only, so a `testGate` source
    // set would never run. It is under `src/gate/`, so gate G-DM5 and anti-placeholder treat it as
    // the gate's, and no release source set compiles it.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
            kotlin.srcDir("src/gate/digests/kotlin")
        }
        getByName("gate") {
            kotlin.srcDir("src/gate/digests/kotlin")
        }
        getByName("androidTest") {
            kotlin.srcDir("../crypto-bridge/src/deviceRunner/kotlin")
        }
    }
}

// The end-to-end wiring test loads the host build of the DM library, as :messaging's worlds do
// (Phase 9 design §2.7, §15.1): the `android` CI job passes `-Dghost.dm.native`; without it that
// test reports itself skipped and the decision tests still run. Declared as a test input so a
// rebuilt library re-runs the tests instead of reusing a cached result.
val dmHostLibrary = providers.systemProperty("ghost.dm.native")
    .orElse(providers.gradleProperty("ghost.dm.native"))
tasks.withType<Test>().configureEach {
    inputs.property("ghost.dm.native", dmHostLibrary.orElse(""))
    dmHostLibrary.orNull?.let { path ->
        systemProperty("ghost.dm.native", path)
        inputs.file(path)
            .withPropertyName("dmHostLibrary")
            .withPathSensitivity(PathSensitivity.NAME_ONLY)
    }
    // Phase 13 design §12.1: Robolectric runs offline — the android-all-instrumented jars the
    // runner needs are a test-runtime configuration resolved by Gradle (pinned in
    // verification-metadata.xml) and copied next to the test task; never downloaded at test time.
    systemProperty("robolectric.offline", "true")
    val robolectricDeps = layout.buildDirectory.dir("rbdeps")
    systemProperty("robolectric.dependency.dir", robolectricDeps.get().asFile.absolutePath)
}

// The android-all-instrumented images, one detached resolvable configuration each: four
// versions of one coordinate in one classpath would resolve to the newest only (Gradle's
// conflict resolution), and each SDK needs its own image.
val robolectricImages = listOf(
    "15-robolectric-13954326-i7", // SDK 35 (the default)
    "14-robolectric-10818077-i7", // SDK 34
    "13-robolectric-9030017-i7", // SDK 33
    "10-robolectric-5803371-i7", // SDK 29
)
val robolectricImageConfigurations = robolectricImages.map { version ->
    val confName = "robolectricImage$version"
    configurations.create(confName) {
        isCanBeResolved = true
        isCanBeConsumed = false
    }.also {
        project.dependencies.add(confName, "org.robolectric:android-all-instrumented:$version")
    }
}

val copyRobolectricDeps = tasks.register<Copy>("copyRobolectricDeps") {
    description = "Copies the android-all-instrumented jars into build/rbdeps for offline Robolectric (design §12.1)."
    // Resolved at execution: the configurations exist once the module's dependencies are set.
    from({
        robolectricImageConfigurations.flatMap { it.resolve() }
            .filter { it.name.startsWith("android-all-instrumented") && it.name.endsWith(".jar") }
    }) {
        eachFile { path = name }
        includeEmptyDirs = false
    }
    into(layout.buildDirectory.dir("rbdeps"))
}
tasks.withType<Test>().configureEach {
    dependsOn(copyRobolectricDeps)
}

// Third-party notices (ADR-37; Phase 9 design §2.10.2, gates G-L1 … G-L3). Every variant packages
// assets/THIRD_PARTY_NOTICES.txt, the byte concatenation of the committed files below: the notices
// preamble (with the SQLCipher credit), the Gradle part and the part of the Rust library
// libghost_client_net.so. scripts/gates/license-notices.sh regenerates the two parts and fails on a
// difference; scripts/gates/apk-notices.sh checks the asset of the built APK against the same bytes.
abstract class ThirdPartyNoticesAsset : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val parts: ListProperty<RegularFile>

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun write() {
        val directory = outputDirectory.get().asFile
        directory.deleteRecursively()
        directory.mkdirs()
        directory.resolve("THIRD_PARTY_NOTICES.txt").outputStream().use { out ->
            parts.get().forEach { part -> part.asFile.inputStream().use { it.copyTo(out) } }
        }
    }
}

val licensesDir = rootProject.layout.projectDirectory.dir("../licenses")
val thirdPartyNoticesAsset = tasks.register<ThirdPartyNoticesAsset>("thirdPartyNoticesAsset") {
    parts.add(licensesDir.file("apk-notices-preamble.txt"))
    parts.add(licensesDir.file("THIRD_PARTY_NOTICES-android.txt"))
    parts.add(licensesDir.file("THIRD_PARTY_NOTICES-client-net.txt"))
    outputDirectory.set(layout.buildDirectory.dir("generated/thirdPartyNotices"))
}

// Phase 12 PT assets (design faza12-transports.md §4.1, §5.4.3; ADR-61 point 5): the built
// lyrebird binaries ship in the APK as `assets/pt/<abi>/lyrebird` plus a `pt/SHA256SUMS` asset
// generated from the in-repo sums — the app extracts its ABI's binary at first PT use and
// verifies it against exactly these sums (PtInstaller, the G-T5 runtime check; G-T4 checks the
// APK asset bytes against the in-repo SHA256SUMS). Copied only when present: a build without
// the binaries (the host/JVM test build) compiles and runs with PT config rejected (§8.4).
// A binary whose bytes drift from the sums fails the build here, loudly, instead of shipping.
// The ABI-keyed layout (`pt/arm64-v8a`, `pt/x86_64`) mirrors the jniLibs abiFilters; aapt's
// default deflate keeps the compressed budget of §9.1 (measured gzip-9 2.76/2.96 MiB against
// the pinned ≤ 2 899 241 / ≤ 3 107 257 B).
abstract class PtAssets : DefaultTask() {
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
        // The in-repo sums: "<sha256>  lyrebird-android-<arch>" lines (comments ignored).
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

val lyrebirdOut = rootProject.layout.projectDirectory.dir("../third_party/lyrebird/out")
val ptAssets = tasks.register<PtAssets>("ptAssets") {
    sources.from(
        lyrebirdOut.file("SHA256SUMS"),
        lyrebirdOut.file("lyrebird-android-arm64"),
        lyrebirdOut.file("lyrebird-android-amd64"),
    )
    outputDirectory.set(layout.buildDirectory.dir("generated/ptAssets"))
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(thirdPartyNoticesAsset, ThirdPartyNoticesAsset::outputDirectory)
        variant.sources.assets?.addGeneratedSourceDirectory(ptAssets, PtAssets::outputDirectory)
    }
}

// The external components whose classes the release APK packages, one
// "group:artifact:version<TAB>classes jar" line each (the Gradle input of G-L1 and G-L2):
// ./gradlew :app:releaseRuntimeComponents, then build/licenses/release-runtime-components.txt.
abstract class RuntimeComponents : DefaultTask() {
    @get:Input
    abstract val components: ListProperty<String>

    @get:OutputFile
    abstract val output: RegularFileProperty

    @TaskAction
    fun write() {
        output.get().asFile.writeText(components.get().sorted().joinToString("") { "$it\n" })
    }
}

tasks.register<RuntimeComponents>("releaseRuntimeComponents") {
    val classes = configurations.named("releaseRuntimeClasspath").flatMap { configuration ->
        configuration.incoming.artifactView {
            attributes { attribute(Attribute.of("artifactType", String::class.java), "android-classes-jar") }
        }.artifacts.resolvedArtifacts
    }
    components.set(classes.map { artifacts ->
        artifacts.mapNotNull { artifact ->
            (artifact.id.componentIdentifier as? ModuleComponentIdentifier)?.let {
                "${it.group}:${it.module}:${it.version}\t${artifact.file.absolutePath}"
            }
        }.distinct()
    })
    output.set(layout.buildDirectory.file("licenses/release-runtime-components.txt"))
}

dependencies {
    implementation(project(":identity"))
    implementation(project(":crypto-bridge"))
    implementation(project(":messaging"))
    implementation(project(":storage"))
    implementation(project(":sync"))
    // Phase 14 design §9.1: the update engine and facade (S2).
    implementation(project(":update"))
    implementation(project(":network"))
    implementation(project(":entitlement"))
    implementation(project(":media"))
    // Phase 13 design §3.1 (slice S0b): the UI module; :app is the composition root.
    implementation(project(":ui"))
    // `PickedVideo` and `NoBitmapsLoader` (the sender pipeline's `:app` half, slice S5): media3's
    // `MediaItem`/`BitmapLoader` types cross the module boundary; the pipeline itself is `:media`.
    implementation(libs.androidx.media3.common)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    // GhostApp: ProcessLifecycleOwner drives the sync foreground session (design §11.2 #21, ADR-20).
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)

    testImplementation(libs.junit)
    testImplementation(libs.sqlite.jdbc)
    // Phase 13 design §12.1, §13.3 (Q25): the JVM-instrumentation runner, pinned and offline —
    // the android-all-instrumented jars resolve through Gradle (verification-metadata pins
    // them) and the test task copies them into build/rbdeps, where the runner's
    // dependency.dir points; nothing is downloaded at test time. SDK 35 default (36/37 are
    // emulator-only).
    testImplementation("org.robolectric:robolectric:4.17")
    // The android-all-instrumented images the runner would fetch at runtime are declared as the
    // detached configurations above (one per SDK image) — four versions of one coordinate
    // cannot share one classpath (conflict resolution keeps the newest only). SDK 35 default,
    // 29/33/34 for the version-gated cases; SDK 36/37 stay emulator-only (JDK 21, ADR-34).
    testImplementation("androidx.compose.ui:ui-test-junit4")
    testImplementation("androidx.test:core:1.6.1")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    androidTestImplementation(libs.junit)
}
