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
