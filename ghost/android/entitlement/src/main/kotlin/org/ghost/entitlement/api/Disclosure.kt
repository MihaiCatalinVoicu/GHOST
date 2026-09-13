package org.ghost.entitlement.api

/** What the user acknowledges before payment instructions exist (design §5.3 step 3, §11.2). */
enum class Disclosure {
    /** FR-6.8: paying from a KYC exchange links a person to an invoice. */
    KYC_EXCHANGE,

    /** No refunds. */
    NO_REFUND,

    /** Exactly the amount, to the given subaddress. */
    EXACT_AMOUNT,

    /** No lock time. */
    NO_LOCK_TIME,

    /** 24 h to pay, then up to 72 h to confirm; pay from another device or later without GHOST open. */
    WINDOWS,
}
