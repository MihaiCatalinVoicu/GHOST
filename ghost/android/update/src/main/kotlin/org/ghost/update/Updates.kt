package org.ghost.update

/**
 * The UI-less facade Phase 13 builds on (Phase 14 design §9.5). User-initiated calls run in the
 * foreground only (§7.3); the platform confirms an install, never the app.
 */
interface Updates {
    val status: UpdateStatus

    /** `issued_day` of the newest manifest held: public data, not a time of activity (§9.6). */
    val manifestIssuedDay: Int?

    /** A user-initiated check (foreground only). */
    fun requestCheck(): CheckOutcome

    /** A user-initiated download of the offered release (foreground only). */
    fun requestDownload(): DownloadOutcome

    /** §7.7: a platform install session; the platform shows its own confirmation. */
    fun install(): InstallHandle

    sealed interface CheckOutcome {
        data object Ok : CheckOutcome
        data class Refused(val code: Int) : CheckOutcome
        data class Unchanged(val code: Int) : CheckOutcome
    }

    sealed interface DownloadOutcome {
        data object Started : DownloadOutcome
        data object NothingToDownload : DownloadOutcome
        data class Refused(val code: Int) : DownloadOutcome
    }

    /** A platform install session; [commit] is called only after the native check returned OK. */
    interface InstallHandle {
        fun commit()
        fun abandon()
    }
}
