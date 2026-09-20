plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.messaging"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // JVM test infrastructure shared with :storage and :sync (JdbcSqlExecutor), Phase 7 design
    // §1.5: a plain source directory, so no experimental test-fixtures support is needed. The
    // owner-side steps of S6 are proved against a real migrated v5 database, not against a mock:
    // every guard this slice relies on (the `dm_self_monotonic` trigger, the partial unique index
    // of `olm_prekey_gen`, the REPLACE guards) lives in the schema.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
        }
    }
}

dependencies {
    // Phase 9 design §13.1: `:messaging` depends on `:crypto-bridge`, the `:sync` API and
    // `:identity`. It has **no** dependency on `:entitlement`: the K20 activation hook points the
    // other way (`:entitlement` calls into this module through a port that `:app` wires, §13.4),
    // and the ES slot table reaches the owner steps through `EsSlots`, for the same reason.
    api(project(":sync"))
    implementation(project(":crypto-bridge"))
    // `ZBase32`: the `ghost://contact/` link of §3.3 is the same encoding as the `ghost1…` string
    // and the invite payload, and a second copy of an alphabet is a second place to get it wrong.
    implementation(project(":identity"))
    testImplementation(libs.junit)
    testImplementation(libs.sqlite.jdbc)
}
