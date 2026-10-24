plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.update"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // JVM tests open a migrated database through :storage's shared test executor.
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
        }
    }
}

dependencies {
    implementation(project(":storage"))
    implementation(project(":network"))
    testImplementation(libs.junit)
    testImplementation(libs.sqlite.jdbc)
}
