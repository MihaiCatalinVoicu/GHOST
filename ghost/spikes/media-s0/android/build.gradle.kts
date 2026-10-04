// The AGP and Kotlin versions of ghost/android (libs.versions.toml: agp 9.4.0, kotlin 2.4.20), so
// the spike compiles exactly as the product modules would. The Kotlin compose plugin is declared
// only to put Kotlin 2.4.20 on the build classpath, as ghost/android's root build does.
plugins {
    id("com.android.application") version "9.4.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}
