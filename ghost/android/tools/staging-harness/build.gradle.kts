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
val unitTestRuntime: Provider<FileCollection> = provider {
    (tasks.named("testDebugUnitTest").get() as Test).classpath
}

tasks.register<JavaExec>("stagingRun") {
    group = "verification"
    description = "Run the staging harness CLI (activate | dm | t6-twin) over the unit-test runtime."
    dependsOn("compileDebugUnitTestKotlin")
    classpath = files(unitTestRuntime)
    mainClass = "org.ghost.staging.StagingHarnessKt"
    systemProperty("ghost.dm.native", providers.gradleProperty("ghost.dm.native").orElse(""))
}

// The WSL runner cannot install platform android-37 (the sdkmanager repo offers it in --list but
// refuses the install, all channels), so the harness compiles on Windows and RUNS in WSL over a
// staged runtime: this task copies every test-runtime jar plus the compiled harness classes into
// build/harness-runtime/, a directory that travels to WSL as-is (jars are bytecode, platform
// independent; the only native piece is libghost_dm_host.so, built in WSL, named at run time via
// -Dghost.dm.native). See README.md "Rulare".
tasks.register<Copy>("stageHarnessRuntime") {
    group = "verification"
    description = "Copy the harness test runtime into build/harness-runtime/ for the WSL runner."
    dependsOn("compileDebugUnitTestKotlin")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(layout.buildDirectory.dir("tmp/kotlin-classes/debugUnitTest"))
    from(unitTestRuntime)
    into(layout.buildDirectory.dir("harness-runtime"))
}
