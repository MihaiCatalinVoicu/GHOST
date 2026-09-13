plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.entitlement"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // JVM test infrastructure shared with :storage and :sync (JdbcSqlExecutor): a plain source
    // directory, as in :sync.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
        }
    }
}

dependencies {
    // Phase 8 design §11.1: project dependencies only, no new Maven coordinate. :sync carries the
    // session participant API, the stores and the sync database; :storage the SQL executor;
    // :network the entitlement JNI surface; :identity invites, drop sealing and the identity.
    implementation(project(":storage"))
    implementation(project(":network"))
    implementation(project(":sync"))
    implementation(project(":identity"))
    testImplementation(libs.junit)
    // JVM SQLite for store tests over the real schema (already a :sync and :storage test dependency).
    testImplementation(libs.sqlite.jdbc)
}

tasks.withType<Test>().configureEach {
    maxHeapSize = "2g"
}
