package org.ghost.ui.protect

import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputInterceptor
import androidx.compose.ui.platform.PlatformTextInputMethodRequest
import androidx.compose.ui.platform.PlatformTextInputSession

/**
 * Phase 13 design §4.5: no IME learns from GHOST text. `GhostRoot` wraps every window's content
 * in this interceptor; it wraps each [PlatformTextInputMethodRequest] and ORs
 * `EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING` into `imeOptions` in `createInputConnection`.
 * Compose's own `KeyboardOptions` has no field for the flag, and the interceptor reaches every
 * platform text input of the window — dialogs included, because composition locals reach dialog
 * content (V-U4 confirms on AOSP's keyboard and Gboard).
 *
 * The design called this helper `ImeIncognito`; Compose 1.12.1 (BOM 2026.09.00) ships the
 * primitive (`InterceptPlatformTextInput`, public in `PlatformTextInputModifierNode.kt`) but no
 * ready-made flag wrapper — checked in S0b against the artifact, not assumed (C.4's rule), so
 * the wrapper lives here. The interceptor of this Compose version drives the session itself
 * (`interceptStartInputMethod` never returns), so the wrapper delegates to `nextHandler` with
 * the wrapped request.
 */
@Composable
fun ImeIncognito(content: @Composable () -> Unit) {
    InterceptPlatformTextInput(NoPersonalizedLearningInterceptor, content)
}

/** The interceptor: hands every session a request that sets the incognito flag. */
private object NoPersonalizedLearningInterceptor : PlatformTextInputInterceptor {
    override suspend fun interceptStartInputMethod(
        request: PlatformTextInputMethodRequest,
        nextHandler: PlatformTextInputSession,
    ): Nothing {
        nextHandler.startInputMethod(IncognitoRequest(request))
    }
}

/** The wrapped request: the only place `imeOptions` is touched (G-U4's anchor for §4.5). */
private class IncognitoRequest(
    private val delegate: PlatformTextInputMethodRequest,
) : PlatformTextInputMethodRequest {
    override fun createInputConnection(outAttributes: EditorInfo): InputConnection {
        outAttributes.imeOptions = outAttributes.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        return delegate.createInputConnection(outAttributes)
    }
}
