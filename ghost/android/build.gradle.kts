// Root build for the GHOST Android client. Module responsibilities: spec v2.0 §6.1 amended by
// docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md §5 (no wallet module; entitlement = Privacy Pass client).
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.compose) apply false
}
