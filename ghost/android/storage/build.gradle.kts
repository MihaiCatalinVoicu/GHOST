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
