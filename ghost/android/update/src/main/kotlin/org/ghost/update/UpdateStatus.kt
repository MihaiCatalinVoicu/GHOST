package org.ghost.update

/**
 * The channel status Phase 13 shows and the copy names (Phase 14 design §9.5). Everything is
 * derived from the stored facts at start; nothing here is persisted beyond `upd_state` and
 * `upd_staged`.
 */
sealed interface UpdateStatus {
    /** No manifest offer: the exact reason is one of the channel codes. */
    data object UpToDate : UpdateStatus
    data class Available(val name: String, val versionCode: Int) : UpdateStatus
    data class Downloading(val received: Long, val total: Long) : UpdateStatus
    data class Ready(val name: String, val versionCode: Int) : UpdateStatus
    data object Installing : UpdateStatus
    data class Installed(val versionCode: Int) : UpdateStatus
    data class Stale(val day: Int) : UpdateStatus
    data class Unsupported(val floor: Int) : UpdateStatus
    data object SdkUnsupported : UpdateStatus
    data object NoManifest : UpdateStatus
    data object Conflict : UpdateStatus
    data object RootConflict : UpdateStatus
    data object NoChannel : UpdateStatus
    data class Failed(val code: Int) : UpdateStatus
}
