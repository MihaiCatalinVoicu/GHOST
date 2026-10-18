package org.ghost.ui.feature.dm
import org.ghost.ui.protect.SensitiveText
class EvilModel(val body: SensitiveText) {
    fun leak() = body.value
}
