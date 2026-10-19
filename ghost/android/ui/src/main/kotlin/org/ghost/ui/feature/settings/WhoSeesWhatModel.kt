package org.ghost.ui.feature.settings

import org.ghost.ui.R

/**
 * Phase 13 design §8.2 ("Cine vede ce"): the reference table — one row per actor of plan §4 plus
 * the design's additions. Three columns per row: **Vede** (a LIMIT, always written "vede cel
 * puțin" — never "doar"), **Nu ar trebui să vadă** (a GOAL, always printed with its status —
 * today "obiectiv de design, neverificat încă"), and **Dovada** (the register's evidence IDs and
 * their status; today none is green, so the cell is the em dash, which is the honest value, not
 * a missing one). Every effect sentence of the rows lives in claims.tsv (ADR-56); the three that
 * trip the trigger list are allowlisted with their reasons.
 */
class WhoSeesWhatModel {
    /** One actor row: the string ids of the actor, the sees column and the goal column. */
    data class Row(val actor: Int, val sees: Int, val goal: Int)

    val rows: List<Row> = listOf(
        Row(R.string.who_relay, R.string.who_relay_sees, R.string.who_relay_goal),
        Row(R.string.who_issuer, R.string.who_issuer_sees, R.string.who_issuer_goal),
        Row(R.string.who_isp, R.string.who_isp_sees, R.string.who_isp_goal),
        Row(R.string.who_channel_members, R.string.who_channel_members_sees, R.string.who_channel_members_goal),
        Row(R.string.who_dm_peer, R.string.who_dm_peer_sees, R.string.who_dm_peer_goal),
        Row(R.string.who_operator, R.string.who_operator_sees, R.string.who_operator_goal),
        Row(R.string.who_monero, R.string.who_monero_sees, R.string.who_monero_goal),
        Row(R.string.who_unlocked, R.string.who_unlocked_sees, R.string.who_unlocked_goal),
        Row(R.string.who_card_holder, R.string.who_card_holder_sees, R.string.who_card_holder_goal),
        Row(R.string.who_moderators, R.string.who_moderators_sees, R.string.who_moderators_goal),
        Row(R.string.who_mirror_ops, R.string.who_mirror_ops_sees, R.string.who_mirror_ops_goal),
        Row(R.string.who_google, R.string.who_google_sees, R.string.who_google_goal),
        Row(R.string.who_usage_apps, R.string.who_usage_apps_sees, R.string.who_usage_apps_goal),
    )

    /** The GOAL column's status, printed with every goal cell (§8.2: always with its status). */
    val goalStatus: Int = R.string.who_goal_status
}
