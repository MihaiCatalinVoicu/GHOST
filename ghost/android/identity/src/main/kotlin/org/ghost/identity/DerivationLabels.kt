package org.ghost.identity

/**
 * Versioned HKDF domain-separation labels (spec v2.0 §7.1 step 3, ADR-03, ADR-04, ADR-05).
 *
 * Every long-lived key branch is derived from the 256-bit root entropy with HKDF-SHA-256 and one
 * of these labels as `info`. Labels are part of the wire/storage compatibility contract: changing
 * a label is a derivation-version bump, never an in-place edit.
 */
object DerivationLabels {
    const val DERIVATION_VERSION: Int = 1

    private const val PREFIX = "ghost/v1/"

    /** Ed25519 identity signing key; public identity = z-base-32 hash prefixed `ghost1` (FR-1.3). */
    const val IDENTITY: String = PREFIX + "identity"

    /** Messaging branch: seeds the libsignal identity key pair (§7.2). */
    const val MESSAGING: String = PREFIX + "messaging"

    /** Reserved for an optional on-chain rail (ADR-03). Defined so a later rail needs no seed migration. */
    const val WALLET_RESERVED: String = PREFIX + "wallet"

    /** Wrapping material for the local backup/export envelope (§7.1 step 5). */
    const val BACKUP_WRAP: String = PREFIX + "backup-wrap"

    /** Per-channel pseudonym signing key: HKDF(info = CHANNEL_PSEUDONYM || channelId) (ADR-04). */
    const val CHANNEL_PSEUDONYM: String = PREFIX + "channel-pseudonym"

    /** Ephemeral invite-signing key, distinct from the base identity (ADR-05). */
    const val INVITE_SIGNING: String = PREFIX + "invite-signing"

    /** Referral secret whose commitment travels inside invites (ADR-02, ADR-05). */
    const val REFERRAL_SECRET: String = PREFIX + "referral-secret"

    val ALL: List<String> = listOf(
        IDENTITY, MESSAGING, WALLET_RESERVED, BACKUP_WRAP, CHANNEL_PSEUDONYM, INVITE_SIGNING, REFERRAL_SECRET,
    )
}
