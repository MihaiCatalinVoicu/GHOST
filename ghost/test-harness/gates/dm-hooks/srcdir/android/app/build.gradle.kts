// Fixture for G-DM5's build-script half (not compiled): two lines add a directory to a release
// source set; the test set's line is allowed.
android {
    sourceSets {
        getByName("main") {
            kotlin.srcDir("src/deviceRunner/kotlin")
        }
        getByName("test") {
            kotlin.srcDir("../storage/src/testShared/kotlin")
        }
    }
}
android.sourceSets["release"].java.srcDirs("src/gate/java")
