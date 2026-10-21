// Staging harness: a JVM CLI that runs the real engines against the live staging deployment
// (design faza13-ux.md Appendix B.2, T6's twin and the real-session re-test of J3-J5).
// Test artifact only - never shipped; no production module depends on it.
plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.stagingharness"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":identity"))
    implementation(project(":crypto-bridge"))
    implementation(project(":storage"))
    implementation(project(":sync"))
    implementation(project(":entitlement"))
    implementation(project(":messaging"))
}

// The harness entry point lives in the unit-test source set so it rides the same runtime the
// engine worlds use (JVM + the host native libraries). Run:
//   ./gradlew :tools:staging-harness:stagingRun --args='activate --state /srv/harness/alice'
tasks.register<JavaExec>("stagingRun") {
    group = "verification"
    description = "Run the staging harness CLI (activate | dm | t6-twin) over the unit-test runtime."
    dependsOn("compileDebugUnitTestKotlin")
    classpath =
        files(layout.buildDirectory.dir("tmp/kotlin-classes/debugUnitTest")) +
            configurations.getByName("testDebugUnitTestRuntimeClasspath")
    mainClass = "org.ghost.staging.StagingHarnessKt"
    systemProperty("ghost.dm.native", providers.gradleProperty("ghost.dm.native").orElse(""))
    systemProperty("ghost.net.native", providers.gradleProperty("ghost.net.native").orElse(""))
}
