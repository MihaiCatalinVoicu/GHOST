// Phase 13 design §3.1, §12.1, Q25: the emulator platform-test module. `com.android.test` builds
// an APK that runs IN :app's gate process (targetProjectPath), with AndroidJUnitRunner and the
// Compose rules; it is never shipped (a test module produces no artifact for the release).
plugins {
    // AGP 9.4.0 is already on the root build's classpath (the application/library plugins share
    // its artifact); the test plugin id resolves from there, no version request.
    id("com.android.test")
    // The S9 suite calls setContent with composable lambdas - without the Compose compiler
    // plugin they compile as plain Function0 and the rule's setContent rejects them at runtime.
    alias(libs.plugins.kotlin.compose)
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

    buildTypes {
        // The test module's target variant is chosen by build-type name: the `gate` build type
        // wires this module's gate APK at :app's gate variant (org.ghost.app.gate — the process
        // Q25's suites must run in), the debug build type at :app's debug variant. Both keep the
        // module's applicationId (org.ghost.uitest), so only one installs at a time.
        create("gate") {
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
        }
        create("peer") {
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":app"))
    // The S9 accessibility suite composes :ui's screens directly; :app's dependency on :ui is
    // an implementation one, so the test module names it too.
    implementation(project(":ui"))
    implementation(project(":entitlement"))
    implementation(project(":sync"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.junit)
    implementation("androidx.compose.foundation:foundation")
    // Phase 13 §9.2 (ADR-57 item 7): Accessibility Test Framework over the semantics tree -
    // test-only, like the rest of this module.
    implementation("com.google.android.apps.common.testing.accessibility.framework:accessibility-test-framework:4.1.1")
    implementation("androidx.test:runner:1.6.2")
    implementation("androidx.test:rules:1.6.1")
    implementation("androidx.test.ext:junit:1.2.1")
    implementation("androidx.compose.ui:ui-test-junit4")
    implementation("androidx.test:core:1.6.1")
}
