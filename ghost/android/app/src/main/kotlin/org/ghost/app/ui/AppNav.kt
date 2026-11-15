package org.ghost.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.window.core.layout.WindowSizeClass
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.ghost.app.GhostApp
import org.ghost.app.R
import org.ghost.ui.feature.access.AccessScreen
import org.ghost.ui.feature.access.PaymentInstructionsScreen
import org.ghost.ui.feature.access.PaymentModel
import org.ghost.ui.feature.access.PurchaseProgressScreen
import org.ghost.ui.feature.dm.ConversationListScreen
import org.ghost.ui.feature.dm.ConversationScreen
import org.ghost.ui.feature.lock.LockScreen
import org.ghost.ui.feature.onboarding.ActivatingScreen
import org.ghost.ui.feature.onboarding.BackupScreen
import org.ghost.ui.feature.onboarding.DisclosuresScreen
import org.ghost.ui.feature.onboarding.InviteScreen
import org.ghost.ui.feature.onboarding.OnboardingModel
import org.ghost.ui.feature.onboarding.PinSetupScreen
import org.ghost.ui.feature.onboarding.PrepareScreen
import org.ghost.ui.feature.onboarding.WelcomeScreen
import org.ghost.ui.feature.onboarding.PrivacyChoiceScreen
import org.ghost.ui.feature.onboarding.NotificationPermissionScreen
import org.ghost.ui.feature.onboarding.WordsScreen
import org.ghost.ui.feature.restore.RestoreIntroScreen
import org.ghost.ui.feature.restore.RestoreModel
import org.ghost.ui.feature.restore.RestoreNextScreen
import org.ghost.ui.feature.restore.RestoreWordsScreen
import org.ghost.ui.feature.settings.AboutScreen
import org.ghost.ui.feature.settings.SecurityModel
import org.ghost.ui.feature.settings.SecurityScreen
import org.ghost.ui.feature.settings.SettingsScreen
import org.ghost.ui.gateway.ActivateResult
import org.ghost.ui.gateway.ConversationSummary
import org.ghost.ui.gateway.ConversationView
import org.ghost.ui.gateway.InviteView
import org.ghost.ui.gateway.PaymentView
import org.ghost.ui.gateway.PurchaseView
import org.ghost.ui.gateway.PinSubmitResult
import org.ghost.ui.protect.CONFIRM
import org.ghost.ui.protect.DELETE
import org.ghost.ui.protect.SensitiveText
import org.ghost.ui.shell.BackStack
import org.ghost.ui.shell.Route
import org.ghost.ui.shell.RouteHost

/**
 * The composition root's navigation (Phase 13 §3.4, D6) — the screen registry the shell never
 * had: it maps [Route] to the feature screens, owns the session's [BackStack], resolves the
 * first route from the identity/lock state, and renders the app lock over everything.
 *
 * Slice 2026-11-15 (first physical-device run): onboarding, restore, lock, home (conversations,
 * access and payment, settings shell), the conversation screen. Routes whose facades the
 * composition root does not expose yet (channels, media viewer, update, wipe, the settings
 * sub-screens needing more models) render [UnavailableScreen] — an explicit state, not a dead
 * control; the next slice wires them as their facades land.
 */

/** The process-wide lock flag: MainActivity's §3.3 lock duty flips it; the nav renders the pad. */
internal object SessionLock {
    var locked by mutableStateOf(false)
}

@Composable
fun AppNav(app: GhostApp, windowSizeClass: WindowSizeClass) {
    val gateways = remember { app.uiGateways }
    val appScope = rememberCoroutineScope()

    val onboardingModel = remember { OnboardingModel(gateways.identity(), gateways.settings()) }
    val restoreModel = remember { RestoreModel(gateways.identity(), gateways.settings()) }
    val paymentModel = remember { PaymentModel(gateways.access()) }

    var startRoute by remember { mutableStateOf<Route?>(null) }
    LaunchedEffect(Unit) {
        val hasIdentity = app.identityManager.hasIdentity()
        startRoute = when {
            !hasIdentity -> Route.OnboardingWelcome
            else -> {
                if (gateways.lock().isConfigured()) SessionLock.locked = true
                Route.Home(Route.HomeTab.CONVERSATIONS)
            }
        }
    }
    val initial = startRoute
    if (initial == null) return
    val backStack = remember(initial) { BackStack(initial) }

    if (SessionLock.locked) {
        // §3.3: the protected content is dropped; only the pad renders.
        LockPad(gateways, onUnlocked = {
            app.onUnlock()
            SessionLock.locked = false
            backStack.popOneShots()
        })
        return
    }

    RouteHost(backStack, windowSizeClass) { current ->
        when (current) {
            Route.OnboardingWelcome -> WelcomeScreen(
                onInvite = {
                    onboardingModel.onWelcomeInvite()
                    backStack.replace(Route.OnboardingPrepare)
                },
                onRestore = { backStack.push(Route.RestoreIntro) },
            )

            Route.OnboardingPrepare -> PrepareScreen(
                onContinue = {
                    appScope.launch {
                        gateways.identity().createDatabaseKey()
                        onboardingModel.onPrepared()
                        backStack.replace(Route.OnboardingLock)
                    }
                },
            )

            Route.OnboardingLock -> PinSetupScreen(
                onPinSet = { digits ->
                    val ok = runCatching {
                        gateways.lock().setPin(digits)
                        onboardingModel.onLockSet()
                    }.isSuccess
                    if (ok) backStack.replace(Route.OnboardingPrivacy)
                    ok
                },
            )

            Route.OnboardingPrivacy -> PrivacyChoiceScreen(
                onChoose = { mode ->
                    appScope.launch {
                        onboardingModel.onChooseMode(mode)
                        backStack.replace(Route.OnboardingInvite)
                    }
                },
            )

            Route.OnboardingInvite -> InviteScreen(
                onInspect = { onboardingModel.onInviteInspect(it) },
                onConfirm = { text ->
                    val result = onboardingModel.onInviteConfirmed(text)
                    if (result == ActivateResult.ACTIVATED || result == ActivateResult.ALREADY_ACTIVE) {
                        backStack.replace(Route.OnboardingWords)
                    }
                    result
                },
                onGenesis = {
                    val result = onboardingModel.onGenesisConfirmed(true)
                    if (result == ActivateResult.ACTIVATED || result == ActivateResult.ALREADY_ACTIVE) {
                        backStack.replace(Route.OnboardingWords)
                    }
                    result
                },
                busy = false,
            )

            Route.OnboardingBackup -> BackupRoute(gateways, onboardingModel, backStack)

            Route.OnboardingWords -> WordsRoute(gateways, onboardingModel, backStack)

            Route.OnboardingNotifications -> NotificationPermissionScreen(
                onAllow = {
                    onboardingModel.onNotificationsAnswered()
                    backStack.replace(Route.OnboardingDisclosures)
                },
                onSkip = {
                    onboardingModel.onNotificationsAnswered()
                    backStack.replace(Route.OnboardingDisclosures)
                },
            )

            Route.OnboardingDisclosures -> DisclosuresScreen(
                onRead = {
                    onboardingModel.onDisclosuresRead()
                    backStack.replace(Route.Home(Route.HomeTab.CHANNELS))
                },
            )

            Route.RestoreIntro -> RestoreIntroScreen(
                onRead = {
                    restoreModel.onIntroRead()
                    backStack.replace(Route.RestoreWords)
                },
            )

            Route.RestoreWords -> RestoreWordsScreen(
                onWords = { restoreModel.onWordsConfirmed(it) },
                onRestored = {
                    restoreModel.onNextStepsRead()
                    backStack.replace(Route.Home(Route.HomeTab.CONVERSATIONS))
                },
            )

            Route.RestoreNext -> RestoreNextScreen(
                onRead = {
                    restoreModel.onNextStepsRead()
                    backStack.replace(Route.Home(Route.HomeTab.CONVERSATIONS))
                },
            )

            is Route.Home -> HomeTabs(current.tab, backStack, gateways, appScope)

            is Route.Conversation -> ConversationRoute(current.contactId, gateways, appScope)

            Route.Access -> AccessRoute(backStack, gateways, appScope)

            is Route.Purchase -> PurchaseRoute(current.purchaseId, backStack, paymentModel, gateways, appScope)

            is Route.PaymentInstructions -> PaymentInstructionsRoute(current.purchaseId, paymentModel, appScope)

            Route.About -> AboutRoute(app, backStack)

            Route.Licences, Route.Update -> UnavailableScreen()

            is Route.Settings -> when (current.section) {
                Route.SettingsSection.SECURITY ->
                    SecurityScreen(SecurityModel(gateways.lock()), onChangePin = {})
                else -> UnavailableScreen()
            }

            else -> UnavailableScreen()
        }
    }
}

/** The unlock pad: collects the PIN through [LockScreen] and submits it once complete. */
@Composable
private fun LockPad(gateways: GatewaySet, onUnlocked: () -> Unit) {
    val scope = rememberCoroutineScope()
    var digits by remember { mutableStateOf(CharArray(0)) }
    var failures by remember { mutableStateOf(0) }
    LockScreen(
        lockedMessageId = null,
        failures = failures,
        onPinDigit = { key ->
            when (key) {
                DELETE -> digits = digits.dropLast(1).toCharArray()
                CONFIRM -> {
                    if (digits.size >= 4) {
                        val pin = digits.copyOf()
                        digits = CharArray(0)
                        scope.launch {
                            when (val result = gateways.lock().submitPin(pin)) {
                                is PinSubmitResult.Unlocked -> {
                                    pin.fill('0')
                                    onUnlocked()
                                }
                                is PinSubmitResult.Locked -> {
                                    pin.fill('0')
                                    failures = result.failures
                                }
                            }
                        }
                    }
                }
                else -> if (digits.size < 8) digits = digits + key
            }
        },
        onBiometric = null,
    )
}

/** WORDS step: reads the mnemonic through the gateway and leaves through the model. */
@Composable
private fun WordsRoute(gateways: GatewaySet, model: OnboardingModel, backStack: BackStack) {
    var words by remember { mutableStateOf<List<String>?>(null) }
    LaunchedEffect(Unit) {
        val indices = gateways.identity().mnemonicIndices()
        val list = gateways.identity().wordList()
        words = indices.map { list[it] }
    }
    val w = words
    if (w == null) {
        ActivatingScreen()
    } else {
        WordsScreen(
            words = w,
            onShown = {
                model.onWordsShown()
                backStack.replace(Route.OnboardingBackup)
            },
        )
    }
}

/** BACKUP step: four random positions checked against the typed words. */
@Composable
private fun BackupRoute(gateways: GatewaySet, model: OnboardingModel, backStack: BackStack) {
    var positions by remember { mutableStateOf<List<Int>?>(null) }
    var indices by remember { mutableStateOf<IntArray?>(null) }
    var wordList by remember { mutableStateOf<List<String>?>(null) }
    LaunchedEffect(Unit) {
        val idx = gateways.identity().mnemonicIndices()
        val list = gateways.identity().wordList()
        indices = idx
        wordList = list
        positions = gateways.identity().backupChallenge(4, emptyList())
    }
    val p = positions
    val idx = indices
    val list = wordList
    if (p == null || idx == null || list == null) {
        ActivatingScreen()
    } else {
        BackupScreen(
            positions = p,
            words = list,
            onVerify = { answers -> gateways.identity().verifyBackup(idx, p, answers) },
            onDone = {
                model.onBackupVerified()
                backStack.replace(Route.OnboardingNotifications)
            },
        )
    }
}

/** HOME: the three tabs of this slice — messages, access and payment, settings. */
@Composable
private fun HomeTabs(tab: Route.HomeTab, backStack: BackStack, gateways: GatewaySet, appScope: kotlinx.coroutines.CoroutineScope) {
    var summaries by remember { mutableStateOf<List<ConversationSummary>>(emptyList()) }
    LaunchedEffect(tab) {
        if (tab == Route.HomeTab.CONVERSATIONS) summaries = gateways.dm().conversationSummaries()
    }
    Column(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.weight(1f)) {
            when (tab) {
                Route.HomeTab.CONVERSATIONS -> ConversationListScreen(
                    summaries = summaries,
                    names = emptyMap(),
                    onOpen = { backStack.push(Route.Conversation(it)) },
                    onAddContact = { backStack.push(Route.ContactAdd) },
                )
                Route.HomeTab.CHANNELS -> AccessRoute(backStack, gateways, appScope)
                Route.HomeTab.SETTINGS -> SettingsScreen(
                    onPrivacy = { backStack.push(Route.Settings(Route.SettingsSection.PRIVACY)) },
                    onSecurity = { backStack.push(Route.Settings(Route.SettingsSection.SECURITY)) },
                    onAbout = { backStack.push(Route.About) },
                    onHelp = { backStack.push(Route.Settings(Route.SettingsSection.HELP)) },
                    onWipe = { backStack.push(Route.Wipe) },
                )
            }
        }
        NavigationBar {
            NavigationBarItem(
                selected = tab == Route.HomeTab.CONVERSATIONS,
                onClick = { backStack.replace(Route.Home(Route.HomeTab.CONVERSATIONS)) },
                icon = { Text("") },
                label = { Text(stringResource(org.ghost.ui.R.string.home_tab_conversations)) },
            )
            NavigationBarItem(
                selected = tab == Route.HomeTab.CHANNELS,
                onClick = { backStack.replace(Route.Home(Route.HomeTab.CHANNELS)) },
                icon = { Text("") },
                label = { Text(stringResource(org.ghost.ui.R.string.home_tab_access)) },
            )
            NavigationBarItem(
                selected = tab == Route.HomeTab.SETTINGS,
                onClick = { backStack.replace(Route.Home(Route.HomeTab.SETTINGS)) },
                icon = { Text("") },
                label = { Text(stringResource(org.ghost.ui.R.string.home_tab_settings)) },
            )
        }
    }
}

@Composable
private fun ConversationRoute(
    contactId: String,
    gateways: GatewaySet,
    appScope: kotlinx.coroutines.CoroutineScope,
) {
    var view by remember { mutableStateOf<ConversationView?>(null) }
    LaunchedEffect(contactId) { view = gateways.dm().conversation(contactId) }
    val v = view ?: return
    ConversationScreen(
        conversation = v,
        names = emptyMap(),
        onSend = { body ->
            appScope.launch {
                gateways.dm().send(contactId, SensitiveText(body), null)
                view = gateways.dm().conversation(contactId)
            }
        },
    )
}

/** ACCESS: purchases polled while INTERACTIVE (§3.2's two-second rule), invites listed. */
@Composable
private fun AccessRoute(backStack: BackStack, gateways: GatewaySet, appScope: kotlinx.coroutines.CoroutineScope) {
    val access = gateways.access()
    var purchases by remember { mutableStateOf<List<PurchaseView>>(emptyList()) }
    var invites by remember { mutableStateOf<List<InviteView>>(emptyList()) }
    var active by remember { mutableStateOf(true) }
    DisposableEffect(Unit) {
        onDispose { active = false }
    }
    LaunchedEffect(Unit) {
        while (active) {
            purchases = access.purchases()
            invites = access.invites()
            delay(2_000)
        }
    }
    AccessScreen(
        purchases = purchases,
        invites = invites,
        onBuyXmr = {
            appScope.launch {
                // Reuse an open flow if one exists; a fresh tap otherwise. Either way, ask for
                // the invoice now (the user call of §8.3; STANDARD mode only — in HIGH the
                // invoice arrives at the next quiet run by design).
                val open = access.purchases().firstOrNull {
                    it.state == org.ghost.ui.gateway.PurchaseState.PREPARED ||
                        it.state == org.ghost.ui.gateway.PurchaseState.INVOICE_PENDING ||
                        it.state == org.ghost.ui.gateway.PurchaseState.READY ||
                        it.state == org.ghost.ui.gateway.PurchaseState.UNDERPAID
                }
                if (open == null) {
                    access.startPurchase("XMR")
                    delay(1_000)
                    access.purchases()
                        .firstOrNull { it.state == org.ghost.ui.gateway.PurchaseState.PREPARED }
                        ?.let { access.requestInvoiceNow(it.id) }
                } else {
                    access.requestInvoiceNow(open.id)
                }
            }
        },
        onOpenPurchase = { backStack.push(Route.Purchase(it)) },
        onRevokeInvite = { index -> appScope.launch { access.revokeInvite(index) } },
    )
}

@Composable
private fun PurchaseRoute(
    purchaseId: String,
    backStack: BackStack,
    paymentModel: PaymentModel,
    gateways: GatewaySet,
    appScope: kotlinx.coroutines.CoroutineScope,
) {
    var purchase by remember { mutableStateOf<PurchaseView?>(null) }
    var active by remember { mutableStateOf(true) }
    DisposableEffect(Unit) { onDispose { active = false } }
    LaunchedEffect(purchaseId) {
        while (active) {
            purchase = gateways.access().purchases().firstOrNull { it.id == purchaseId }
            delay(2_000)
        }
    }
    PurchaseProgressScreen(
        purchase = purchase,
        onOpenInstructions = {
            appScope.launch {
                if (paymentModel.mayOpenInstructions(purchaseId)) {
                    backStack.push(Route.PaymentInstructions(purchaseId))
                }
            }
        },
    )
}

/** The instructions read: marks the screen shown (D35) and renders the sensitive view. */
@Composable
private fun PaymentInstructionsRoute(
    purchaseId: String,
    paymentModel: PaymentModel,
    appScope: kotlinx.coroutines.CoroutineScope,
) {
    var payment by remember { mutableStateOf<PaymentView?>(null) }
    LaunchedEffect(purchaseId) {
        paymentModel.onOpenInstructions(purchaseId)
        payment = paymentModel.view(purchaseId)
    }
    DisposableEffect(purchaseId) {
        onDispose {
            // §3.3/§3.5: the leave (hide, back, lock) ends the shown-marked window.
            appScope.launch { paymentModel.onInstructionsClosed(purchaseId) }
        }
    }
    val p = payment
    if (p == null) {
        ActivatingScreen()
    } else {
        PaymentInstructionsScreen(payment = p)
    }
}

/** ABOUT: the version line and the three reference doors (the sub-screens land next slice). */
@Composable
private fun AboutRoute(app: GhostApp, backStack: BackStack) {
    val version = remember {
        runCatching {
            app.packageManager.getPackageInfo(app.packageName, 0).versionName ?: ""
        }.getOrDefault("")
    }
    AboutScreen(
        version = version,
        securityContact = "",
        onWhoSeesWhat = { backStack.push(Route.WhoSeesWhat) },
        onLimits = { backStack.push(Route.Update) },
        onLicences = { backStack.push(Route.Licences) },
    )
}

/** The explicit state for routes whose facades this slice does not expose yet. */
@Composable
private fun UnavailableScreen() {
    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
        Text(
            text = stringResource(org.ghost.ui.R.string.route_unavailable),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}
