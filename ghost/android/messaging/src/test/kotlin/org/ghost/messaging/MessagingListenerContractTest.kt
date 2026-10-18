package org.ghost.messaging

import java.lang.reflect.Modifier
import org.ghost.messaging.api.ChangeKind
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.api.MessagingListener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §3.6's listener contract (the §12.2 recording-half pattern, on the §10.7 NotificationPort
 * contract test's shape): `MessagingListener` carries one method over one enum set — content-free
 * kinds, nothing a UI could render without re-querying; `setListener` takes a nullable so the UI
 * detaches at lock without a second surface.
 */
class MessagingListenerContractTest {
    @Test
    fun theListenerCarriesKindsAndNothingElse() {
        val methods = MessagingListener::class.java.declaredMethods.filter { !it.isSynthetic }
        assertEquals("one method", 1, methods.size)
        val method = methods.single()
        assertEquals("onChanged", method.name)
        assertEquals(Set::class.java, method.parameterTypes.single().rawTypeOrItself())
        // The element type is ChangeKind (the generic signature survives as the only parameter).
        assertTrue(
            method.genericParameterTypes.single().typeName.contains("ChangeKind"),
        )
        assertEquals("void (Kotlin Unit)", Void.TYPE, method.returnType)
    }

    @Test
    fun theKindSetIsTheSectionThreesClosedList() {
        assertEquals(
            listOf("CONTACTS", "MESSAGES", "REQUESTS", "TRUST", "OUTCOMES", "STATUS"),
            ChangeKind.entries.map { it.name },
        )
    }

    @Test
    fun setListenerIsOnTheFacadeAndNullable() {
        val method = Messaging::class.java.getMethod("setListener", MessagingListener::class.java)
        assertTrue(Modifier.isPublic(method.modifiers))
        // The Kotlin nullable is what lets the UI clear the listener at lock with one call.
        assertNull(method.getAnnotation(Deprecated::class.java))
        assertTrue(method.parameterTypes.single() == MessagingListener::class.java)
    }

    private fun Class<*>.rawTypeOrItself(): Class<*> = this
}
