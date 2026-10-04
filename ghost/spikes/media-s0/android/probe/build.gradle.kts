// The S0 probe app: one self-instrumenting debug APK (`org.ghost.spike.media`) that holds every
// emulator check of design Appendix C.3 as a named probe (`am instrument -e probe <name>`), the
// isolated decoding service of §9.2 (`:mdec`) and two small activities (V-M20 snapshots, V-M21
// picker). Evidence tooling only; it is never built by ghost/android and nothing of it ships.
plugins {
    id("com.android.application")
}

android {
    namespace = "org.ghost.spike.media"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.ghost.spike.media"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "s0"
        ndk { abiFilters += listOf("x86_64") }
    }

    buildTypes {
        debug { isMinifyEnabled = false }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs.useLegacyPackaging = false
    }
}

dependencies {
    // The design's pins (§16.3): Media3 1.11.1.
    implementation("androidx.media3:media3-transformer:1.11.1")
    implementation("androidx.media3:media3-exoplayer:1.11.1")
    implementation("androidx.media3:media3-muxer:1.11.1")
    implementation("androidx.media3:media3-effect:1.11.1")
    implementation("androidx.media3:media3-common:1.11.1")
    // Test-input writers only (the orientation corpus, HEIC/AVIF sources); never on a GHOST path.
    implementation("androidx.exifinterface:exifinterface:1.4.2")
    implementation("androidx.heifwriter:heifwriter:1.1.0")
}
