// T4's control application (design faza13-ux.md Appendix B.2, T4; ADR-57's pattern): a minimal
// app with RELAXED backup rules whose canary file must appear in a backup - so a run can prove
// the backup pipeline actually carried data when GHOST's own archive is empty. Test-only, never
// shipped, installed on gate devices only.
plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "org.ghost.backupctl"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "org.ghost.backupctl"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
