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

rootProject.name = "ghost-android"

include(":app")
include(":identity")
include(":crypto-bridge")
include(":messaging")
include(":storage")
include(":sync")
include(":network")
include(":entitlement")
include(":media")
// Phase 13 design §3.1 (slice S0b): the UI module. No project() dependency of its own (G-U5).
include(":ui")
// Phase 13 design §3.1 (slice S1b): the emulator platform-test module, never shipped.
include(":app-uitest")
// Phase 13 Appendix B.2 (T4): the backup control application, test-only, never shipped.
include(":backupctl")
// Phase 14 design §9.1 (slice S2): the update engine. The updater lives in its own Gradle module
// so the store flavor is a dependency switch (§8.2 entry condition (c)).
include(":update")
// Phase 13 Appendix B.2 (T6 twin, J3-J5 real sessions): the staging harness, test-only.
include(":tools:staging-harness")
