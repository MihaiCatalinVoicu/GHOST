// Phase 13 design §3.1, §12.1, Q25: the emulator platform-test module. `com.android.test` builds
// an APK that runs IN :app's gate process (targetProjectPath), with AndroidJUnitRunner and the
// Compose rules; it is never shipped (a test module produces no artifact for the release).
plugins {
    // AGP 9.4.0 is already on the root build's classpath (the application/library plugins share
    // its artifact); the test plugin id resolves from there, no version request.
    id("com.android.test")
}

android {
    namespace = "org.ghost.uitest"
    compileSdk = libs.versions.compileSdk.get().toInt()
    // Q25, §3.1: the platform tests run inside :app's process; the variant under test is the
    // gate build type (matchingFallbacks resolves :app's dependencies to their debug variants).
    targetProjectPath = ":app"

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":app"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.junit)
    implementation("androidx.test:runner:1.6.2")
    implementation("androidx.test:rules:1.6.1")
    implementation("androidx.test.ext:junit:1.2.1")
    implementation("androidx.compose.ui:ui-test-junit4")
    implementation("androidx.test:core:1.6.1")
}
