package org.ghost.ui.feature.channel

import org.ghost.ui.R

internal fun channelPostStateLabel(state: String): Int = when (state.lowercase()) {
    "queued" -> R.string.dm_state_sending
    "failed" -> R.string.dm_state_failed
    "indeterminate" -> R.string.dm_state_held
    else -> R.string.dm_state_sent
}

internal fun channelPostKindLabel(kind: Int): Int = when (kind) {
    2 -> R.string.ch_post_reaction
    3 -> R.string.ch_post_invite
    4 -> R.string.ch_post_leave
    5 -> R.string.ch_post_reveal
    else -> R.string.ch_post_control
}

internal fun formatChannelMinute(minute: Long): String =
    java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT).format(java.util.Date(minute * 60_000L))

internal fun channelCreateFailureLabel(result: String?): Int = when (result) {
    "LIMIT_REACHED" -> R.string.ch_create_limit
    "NO_REPLICAS" -> R.string.ch_create_no_replicas
    "CRYPTO_UNAVAILABLE", "UNAVAILABLE" -> R.string.ch_create_crypto
    "INVALID" -> R.string.ch_create_invalid
    "STORAGE_FULL" -> R.string.ch_create_storage
    else -> R.string.ch_create_failed
}
