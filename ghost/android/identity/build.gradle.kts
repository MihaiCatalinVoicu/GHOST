plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.identity"
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
    // Ed25519 (RFC 8032) deterministic from seed; reviewed library, see ADR-17.
    implementation(libs.bouncycastle.bcprov)
    testImplementation(libs.junit)
}
