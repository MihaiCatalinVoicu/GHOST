plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.ghost.media"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    testImplementation(libs.junit)
}

// The JDK replay of the media vectors (Phase 11 design faza11-media.md §3.9, §15.2 item 1; slice S1):
// the vector files and the goldens it reads are test inputs, so a regenerated file re-runs the test
// instead of reusing a cached result (build caching is on).
tasks.withType<Test>().configureEach {
    inputs.files(
        rootProject.fileTree("../protocol/test-vectors") {
            include("media_object.txt", "media_descriptor.txt", "media_sniff.txt", "media_jpeg.txt", "media-goldens/**")
        },
    ).withPropertyName("mediaVectors").withPathSensitivity(PathSensitivity.RELATIVE)
}
