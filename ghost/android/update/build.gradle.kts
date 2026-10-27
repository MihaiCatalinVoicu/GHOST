plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.update"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // JVM tests open a migrated database through :storage's shared test executor.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
        }
    }
}

dependencies {
    implementation(project(":storage"))
    implementation(project(":network"))
    implementation(project(":sync"))
    testImplementation(libs.junit)
    testImplementation(libs.sqlite.jdbc)
}

// The JVM update world runs the real native decision core through the host build of
// `ghost-client-net` (Phase 14 design §11.2; the :network module's Phase 12 slice-S2 pattern):
// the `android` CI job passes `-Dghost.net.native=<path to the cdylib>`. Declared as a test
// input so a rebuilt library re-runs the tests; without the property the native world tests
// report themselves skipped and the pure-JVM suites still run, the repo's standing rule.
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
}
