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
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Signing is done offline (FR-8.2, ADR-07); CI produces the unsigned, reproducible artifact.
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = false
    }

    packaging {
        // Reproducibility: drop build-host metadata that varies between machines.
        resources.excludes += setOf("META-INF/*.version", "META-INF/DEPENDENCIES", "kotlin/**")
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
androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(thirdPartyNoticesAsset, ThirdPartyNoticesAsset::outputDirectory)
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
    implementation(project(":network"))
    implementation(project(":entitlement"))
    implementation(project(":media"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    // GhostApp: ProcessLifecycleOwner drives the sync foreground session (design §11.2 #21, ADR-20).
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)

    testImplementation(libs.junit)
}
