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

    // The harness rides the same JVM fixtures the engine tests do (the repo's established
    // pattern: messaging grafts these source sets into its test sources). JdbcSqlExecutor and
    // friends come from :storage's testShared.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../../storage/src/testShared/kotlin")
        }
    }
}

dependencies {
    implementation(project(":identity"))
    implementation(project(":crypto-bridge"))
    implementation(project(":storage"))
    implementation(project(":sync"))
    implementation(project(":entitlement"))
    implementation(project(":messaging"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.xerial:sqlite-jdbc:3.53.4.0")
}

// (sourceSets moved inside android {} above)

// This source set contains the resumable CLI harness, not JUnit tests. Gradle 9.7 otherwise fails
// the aggregate `build` merely because this intentionally test-less source set discovers no tests.
tasks.withType<Test>().configureEach {
    failOnNoDiscoveredTests = false
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
// staged runtime: this task copies every entry of the test runtime classpath - dependency jars AND
// the engine modules' compiled classes - into build/harness-runtime/ under unique names (a flat
// Copy drops same-named entries, which is how module classes vanished). Bytecode is platform
// independent; the only native piece is libghost_dm_host.so, built in WSL, named at run time via
// -Dghost.dm.native. See README.md "Rulare".
tasks.register("stageHarnessRuntime") {
    group = "verification"
    description = "Copy the harness test runtime into build/harness-runtime/ for the WSL runner."
    dependsOn("compileDebugUnitTestKotlin")
    // The module class jars appear on the test classpath as entries that only exist once their
    // producing tasks ran (on a fresh WSL checkout they are missing and the stage silently
    // skipped them - SqlExecutor and friends). Depending on the classpath pulls those producers in.
    dependsOn((tasks.named("testDebugUnitTest").get() as Test).classpath)
    doLast {
        val testTask = tasks.named("testDebugUnitTest").get() as Test
        val out = layout.buildDirectory.dir("harness-runtime").get().asFile
        out.deleteRecursively()
        out.mkdirs()
        testTask.classpath.files.toList().forEachIndexed { index, entry ->
            if (!entry.exists()) return@forEachIndexed
            val dest = File(out, "%03d_%s".format(index, entry.name))
            if (entry.isDirectory) entry.copyRecursively(dest) else entry.copyTo(dest)
        }
        File(out, "harness-classes").mkdirs()
        val ktClasses = layout.buildDirectory.dir("tmp/kotlin-classes/debugUnitTest").get().asFile
        if (ktClasses.exists()) ktClasses.copyRecursively(File(out, "harness-classes"), overwrite = true)
    }
}
