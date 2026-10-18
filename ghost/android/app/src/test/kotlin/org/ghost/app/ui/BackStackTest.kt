package org.ghost.app.ui

// The BackStack lives in :ui; this test drives it from :app's JVM suite because the shell's
// behaviours under test (MC-U8, the lock's one-shot pops of §3.3) are UI-layer properties the
// gate's behavioural half needs on the JVM.

import org.ghost.ui.shell.BackStack
import org.ghost.ui.shell.Route
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackStackTest {
    @Test
    fun pushPopReplaceAndTheRootNeverPops() {
        val s = BackStack(Route.Home(Route.HomeTab.CONVERSATIONS))
        assertEquals(Route.Home(Route.HomeTab.CONVERSATIONS), s.current)
        assertFalse(s.pop())
        s.push(Route.Conversation("c1"))
        s.push(Route.SafetyNumber("c1"))
        assertEquals(3, s.size)
        assertTrue(s.pop())
        assertEquals(Route.Conversation("c1"), s.current)
        s.replace(Route.Conversation("c2"))
        assertEquals(Route.Conversation("c2"), s.current)
        assertTrue(s.pop())
        assertFalse(s.pop())
    }

    @Test
    fun lockPopsTheOneShotRoutes() {
        // §3.3: at lock the routes that must not reappear after an unlock are popped, so the
        // user lands on their parent screen. A PaymentInstructions on top of a Payment on top of
        // Home collapses to Payment.
        val s = BackStack(Route.Home(Route.HomeTab.CONVERSATIONS))
        s.push(Route.Purchase("p1"))
        s.push(Route.PaymentInstructions("p1"))
        s.popOneShots()
        assertEquals(Route.Purchase("p1"), s.current)
        // A ViewOnce above a Conversation collapses to the conversation.
        s.push(Route.ViewOnce("m1"))
        s.popOneShots()
        assertEquals(Route.Purchase("p1"), s.current)
        // Non-one-shot routes survive.
        s.push(Route.Settings(Route.SettingsSection.SECURITY))
        s.popOneShots()
        assertEquals(Route.Settings(Route.SettingsSection.SECURITY), s.current)
    }

    @Test
    fun theRootIsNeverPoppedEvenWhenOneShot() {
        // Defence in depth: the root route is never a one-shot in practice, but the pop loop
        // must stop at size 1 regardless.
        val s = BackStack(Route.Wipe)
        s.popOneShots()
        assertEquals(Route.Wipe, s.current)
        assertEquals(1, s.size)
    }
}
