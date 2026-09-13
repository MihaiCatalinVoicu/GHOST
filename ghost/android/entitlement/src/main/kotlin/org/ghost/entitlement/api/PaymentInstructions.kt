package org.ghost.entitlement.api

/**
 * What the user pays (design §5.3 step 3, §19.11): the invoice subaddress and amount, the amount still
 * outstanding (amount − credited − seen, from the latest issuer answer), the deadline (invoice
 * receipt + 24 h, a unix minute) and the `monero:` URI for the outstanding amount, built natively from
 * validated values (null when nothing is outstanding). None exist after the deadline. Never printed.
 */
class PaymentInstructions(
    val subaddress: String,
    val amountAtomic: Long,
    val outstandingAtomic: Long,
    val deadlineMinute: Long,
    val uri: String?,
) {
    override fun toString(): String = "PaymentInstructions(redacted)"
}
