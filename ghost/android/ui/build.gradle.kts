// Phase 13 (design faza13-ux.md §3.1, slice S0b): the :ui module. No project() dependency
// (G-U5), no engine package, no network/storage/file API — the UI talks to the engines only
// through the gateway interfaces of org.ghost.ui.gateway (slice S1).
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "org.ghost.ui"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = false
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    // §3.1: androidx.window 1.5.0 for the size-class two-pane layout (slice S1).
    // WindowSizeClass lives in window-core, which :window does not expose as an API
    // dependency (checked against the 1.5.0 artifacts in S1, not assumed) — declared directly.
    implementation("androidx.window:window:1.5.0")
    implementation("androidx.window:window-core:1.5.0")
    // §4.7 (Q12, ADR-57): QR encode/decode — Apache-2.0, no runtime dependency.
    implementation(libs.zxing.core)
}
