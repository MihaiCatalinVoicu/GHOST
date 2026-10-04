// Phase 11 S0 evidence spike (docs/design/faza11-media.md §17.1 S0a; evidence in
// docs/design/faza11-s0-evidence.md). A standalone Gradle build: NOT part of ghost/android, not in
// its settings, its version catalog, its dependency verification or its gates. Nothing here ships.
pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "ghost-media-s0-spike"

// The probe app: every emulator check (self-instrumenting APK with the isolated service).
include(":probe")
// V-M7 / V-M14: a minimal app in two flavours (with and without Media3 used as the design uses it)
// whose R8-shrunk release dex and APK are listed and measured.
include(":r8probe")

// V-M15 (manifest-level only): memtagMode for the isolated process alone.
include(":mteprobe")
