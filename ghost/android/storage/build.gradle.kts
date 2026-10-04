plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.storage"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // JVM test infrastructure shared with :sync (JdbcSqlExecutor); plain source directory, so no
    // experimental test-fixtures support is needed.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("src/testShared/kotlin")
        }
    }
}

// The expired-row lints (`DmExpiredRowLint`, `ChannelExpiredRowLint`; Phase 9 §10.7 and Phase 10 §8.2, mutant ME-16)
// read the production Kotlin and Java sources of **every** Android module at run time: each `src/main` under the
// Android root (`DmExpiredRowLint.androidProductionSources`). Gradle cannot see that, so without the declaration
// below a pull request that touches `:messaging` alone finds this module's test task FROM-CACHE (`org.gradle.caching`
// is on and the CI restores the cache) or UP-TO-DATE, and the lint does not run on the query the pull request added:
// shown in the review of S3 with an unregistered `SELECT body_env FROM ch_post …` in `PostStore`, where only
// `--rerun` made the lint fail. The sources are declared as inputs, with relative path sensitivity (the checkout's
// location is not an input), and every directory the scan prunes is excluded here too. The test
// `ChannelExpiredRowLintTest.theStorageTestTaskDeclaresTheSourcesTheLintReads` pins this block.
tasks.withType<Test>().configureEach {
    inputs.files(
        fileTree(rootProject.projectDir) {
            include("**/src/main/**/*.kt", "**/src/main/**/*.java")
            exclude("**/build/**", "**/target/**", "**/.git/**", "**/.gradle/**", "**/.idea/**", "**/node_modules/**")
        },
    )
        .withPropertyName("androidProductionSources")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

dependencies {
    implementation(project(":identity"))
    // Encrypted local database (spec Appendix A: sqlcipher-android current API) over androidx.sqlite.
    implementation(libs.sqlcipher.android)
    implementation(libs.androidx.sqlite)
    implementation(libs.androidx.sqlite.framework)
    testImplementation(libs.junit)
    // JVM SQLite for schema and migration tests; SQLCipher itself needs a device (instrumented tests).
    testImplementation(libs.sqlite.jdbc)
}
