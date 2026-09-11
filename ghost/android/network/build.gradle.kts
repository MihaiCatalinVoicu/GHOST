plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.network"
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
    // SHA3-256 for the v3 onion checksum (already shipped via :identity, ADR-17).
    implementation(libs.bouncycastle.bcprov)
    testImplementation(libs.junit)
}

// OnionAddressTest reads the vector file shared with the Rust parser: declare it as a test input
// so a change to the vectors alone re-runs the tests (build caching is on).
tasks.withType<Test>().configureEach {
    inputs.file(rootProject.file("../protocol/test-vectors/onion_addresses.txt"))
        .withPropertyName("sharedOnionVectors")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}
