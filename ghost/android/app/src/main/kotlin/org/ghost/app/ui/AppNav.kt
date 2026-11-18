package org.ghost.app.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
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
import org.ghost.ui.feature.access.InvitesScreen
import org.ghost.ui.feature.access.PaymentInstructionsScreen
import org.ghost.ui.feature.access.PayoutScreen
import org.ghost.ui.feature.access.PaymentModel
import org.ghost.ui.feature.access.PurchaseProgressScreen
import org.ghost.ui.feature.channel.ChannelAcceptModel
import org.ghost.ui.feature.channel.ChannelAcceptScreen
import org.ghost.ui.feature.channel.ChannelCreateModel
import org.ghost.ui.feature.channel.ChannelCreateScreen
import org.ghost.ui.feature.channel.ChannelInviteModel
import org.ghost.ui.feature.channel.ChannelInviteRequestScreen
import org.ghost.ui.feature.channel.ChannelInviteScreen
import org.ghost.ui.feature.channel.ChannelLinkScreen
import org.ghost.ui.feature.channel.ChannelListModel
import org.ghost.ui.feature.channel.ChannelListScreen
import org.ghost.ui.feature.channel.ChannelModel
import org.ghost.ui.feature.channel.ChannelScreen
import org.ghost.ui.feature.channel.MembersScreen
import org.ghost.ui.feature.channel.RevealScreen
import org.ghost.ui.feature.dm.ContactAddModel
import org.ghost.ui.feature.dm.ContactAddScreen
import org.ghost.ui.feature.dm.ContactInfoScreen
import org.ghost.ui.feature.dm.ConversationListScreen
import org.ghost.ui.feature.dm.ConversationScreen
import org.ghost.ui.feature.dm.MyCardScreen
import org.ghost.ui.feature.dm.RequestsScreen
import org.ghost.ui.feature.dm.SafetyNumberScreen
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
import org.ghost.ui.feature.settings.AccessibilityScreen
import org.ghost.ui.feature.settings.CrashReportsScreen
import org.ghost.ui.feature.settings.DiagnosticScreen
import org.ghost.ui.feature.settings.LicencesScreen
import org.ghost.ui.feature.settings.PrivacyScreen
import org.ghost.ui.feature.settings.SecurityModel
import org.ghost.ui.feature.settings.SecurityScreen
import org.ghost.ui.feature.settings.SettingsModel
import org.ghost.ui.feature.settings.SettingsScreen
import org.ghost.ui.feature.settings.TextPageScreen
import org.ghost.ui.feature.settings.WhoSeesWhatModel
import org.ghost.ui.feature.settings.WhoSeesWhatScreen
import org.ghost.ui.feature.settings.WipeScreen
import org.ghost.ui.feature.update.UpdateScreen
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
 * The composition root's navigation (Phase 13 §3.4, D6): every declared [Route] maps explicitly
 * to its real feature screen; the session owns [BackStack], and the app lock covers all content.
 * There is intentionally no generic unavailable route and no dead navigation control.
 */

/** The process-wide lock flag: MainActivity's §3.3 lock duty flips it; the nav renders the pad. */
internal object SessionLock {
    var locked by mutableStateOf(false)
}

/** Payment instruction reads are local; even a stuck database call must reach a terminal UI state. */
private const val PAYMENT_READ_TIMEOUT_MILLIS = 10_000L

@androidx.media3.common.util.UnstableApi
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

            is Route.Conversation -> ConversationRoute(current.contactId, gateways, appScope, backStack)

            Route.ContactAdd -> ContactAddRoute(gateways, backStack)

            Route.MyCard -> MyCardRoute(gateways, backStack)

            Route.Requests -> RequestsRoute(gateways, backStack)

            is Route.SafetyNumber -> SafetyNumberRoute(current.contactId, false, gateways, backStack)

            is Route.KeyChange -> SafetyNumberRoute(current.contactId, true, gateways, backStack)

            is Route.ContactInfo -> ContactInfoRoute(current.contactId, gateways, backStack)

            Route.ChannelList -> ChannelListRoute(gateways, backStack)

            Route.ChannelCreate -> ChannelCreateRoute(gateways, backStack)

            is Route.Channel -> ChannelRoute(current.channelId, gateways, backStack)

            is Route.ChannelAccept -> ChannelAcceptRoute(current.link, gateways, backStack)

            is Route.ChannelInvite -> ChannelInviteRoute(current.channelId, gateways, backStack, app)

            is Route.Members -> MembersRoute(current.channelId, gateways, backStack)

            is Route.Reveal -> RevealRoute(current.channelId, current.memberId, gateways, backStack)

            Route.Access -> AccessRoute(backStack, gateways, appScope)

            Route.Invites -> InvitesRoute(app, gateways, backStack)

            Route.Payout -> PayoutRoute(gateways, backStack)

            is Route.Purchase -> PurchaseRoute(current.purchaseId, backStack, paymentModel, gateways, appScope)

            is Route.PaymentInstructions -> PaymentInstructionsRoute(app, current.purchaseId, backStack, paymentModel, appScope)

            is Route.MediaViewer -> MediaViewerRoute(app, current.itemId, false, backStack)

            is Route.ViewOnce -> MediaViewerRoute(app, current.itemId, true, backStack)

            Route.About -> AboutRoute(app, backStack)

            Route.Licences -> LicencesRoute(app, backStack)

            Route.Limits -> TextPageScreen(
                titleId = org.ghost.ui.R.string.about_limits,
                bodyIds = listOf(org.ghost.ui.R.string.limits_body),
                onBack = { backStack.pop() },
            )

            Route.WhoSeesWhat -> WhoSeesWhatScreen(WhoSeesWhatModel())

            Route.Backup -> BackupReviewRoute(gateways, backStack)

            Route.Accessibility -> AccessibilityRoute(app, backStack)

            Route.Diagnostic -> DiagnosticRoute(app, backStack)

            Route.Crash -> CrashReportsRoute(app, backStack)

            Route.Update -> UpdateRoute(app, gateways, backStack)

            Route.Wipe -> WipeRoute(gateways)

            is Route.Settings -> when (current.section) {
                Route.SettingsSection.ACCESS -> AccessRoute(backStack, gateways, appScope)
                Route.SettingsSection.PRIVACY -> PrivacyRoute(gateways)
                Route.SettingsSection.SECURITY -> SecurityRoute(app, gateways, backStack)
                Route.SettingsSection.ABOUT -> AboutRoute(app, backStack)
                Route.SettingsSection.HELP -> TextPageScreen(
                    titleId = org.ghost.ui.R.string.help_title,
                    bodyIds = listOf(
                        org.ghost.ui.R.string.help_tor,
                        org.ghost.ui.R.string.help_phone,
                    ),
                    onBack = { backStack.pop() },
                )
                Route.SettingsSection.WIPE -> WipeRoute(gateways)
            }
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
    var names by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var requestCount by remember { mutableStateOf(0) }
    LaunchedEffect(tab) {
        if (tab == Route.HomeTab.CONVERSATIONS) {
            names = gateways.dm().contactNames()
            while (true) {
                summaries = gateways.dm().conversationSummaries()
                requestCount = gateways.dm().requests().size
                delay(2_000)
            }
        }
    }
    Column(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.weight(1f)) {
            when (tab) {
                Route.HomeTab.CONVERSATIONS -> ConversationListScreen(
                    summaries = summaries,
                    names = names,
                    onOpen = { backStack.push(Route.Conversation(it)) },
                    onAddContact = { backStack.push(Route.ContactAdd) },
                    onMyCard = { backStack.push(Route.MyCard) },
                    requestCount = requestCount,
                    onRequests = { backStack.push(Route.Requests) },
                )
                Route.HomeTab.CHANNELS -> ChannelListRoute(gateways, backStack)
                Route.HomeTab.SETTINGS -> SettingsScreen(
                    onAccess = { backStack.push(Route.Access) },
                    onPrivacy = { backStack.push(Route.Settings(Route.SettingsSection.PRIVACY)) },
                    onSecurity = { backStack.push(Route.Settings(Route.SettingsSection.SECURITY)) },
                    onAbout = { backStack.push(Route.About) },
                    onUpdate = { backStack.push(Route.Update) },
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
                label = { Text(stringResource(org.ghost.ui.R.string.home_tab_channels)) },
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
    backStack: BackStack,
) {
    var view by remember { mutableStateOf<ConversationView?>(null) }
    var names by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var trust by remember { mutableStateOf<String?>(null) }
    val mediaPicker = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        result.data?.data?.let { uri ->
            appScope.launch {
                gateways.media().sendMedia(contactId, uri.toString())
                view = gateways.dm().conversation(contactId)
            }
        }
    }
    LaunchedEffect(contactId) {
        gateways.dm().setConversationOnScreen(contactId)
        names = gateways.dm().contactNames()
        trust = gateways.contacts().trustState(contactId)
        view = gateways.dm().conversation(contactId)
    }
    DisposableEffect(contactId) {
        onDispose { appScope.launch { gateways.dm().setConversationOnScreen(null) } }
    }
    val v = view ?: return
    ConversationScreen(
        conversation = v,
        names = names,
        onSend = { body ->
            appScope.launch {
                gateways.dm().send(contactId, SensitiveText(body), null)
                trust = gateways.contacts().trustState(contactId)
                view = gateways.dm().conversation(contactId)
            }
        },
        onRetry = { messageId ->
            appScope.launch {
                gateways.dm().retry(messageId)
                view = gateways.dm().conversation(contactId)
            }
        },
        onAttach = { mediaPicker.launch(org.ghost.ui.platform.SystemIntents.pickMedia()) },
        onSafetyNumber = { backStack.push(Route.SafetyNumber(contactId)) },
        onOpenMedia = { itemId -> backStack.push(Route.MediaViewer(itemId)) },
        onContactInfo = { backStack.push(Route.ContactInfo(contactId)) },
        onKeyChange = if (trust == "CHANGED") {
            { backStack.push(Route.KeyChange(contactId)) }
        } else {
            null
        },
    )
}

@Composable
private fun ContactInfoRoute(contactId: String, gateways: GatewaySet, backStack: BackStack) {
    val scope = rememberCoroutineScope()
    var name by remember(contactId) { mutableStateOf<String?>(null) }
    var trust by remember(contactId) { mutableStateOf<String?>(null) }
    var resultId by remember(contactId) { mutableStateOf<Int?>(null) }
    var version by remember(contactId) { mutableStateOf(0) }
    LaunchedEffect(contactId, version) {
        name = gateways.dm().contactNames()[contactId]
        trust = gateways.contacts().trustState(contactId)
    }
    ContactInfoScreen(
        contactId = contactId,
        name = name,
        trust = trust,
        resultMessage = resultId?.let { stringResource(it) },
        onRename = { alias ->
            scope.launch {
                val ok = gateways.dm().rename(contactId, alias)
                resultId = if (ok) org.ghost.ui.R.string.contact_renamed else org.ghost.ui.R.string.contact_action_failed
                version++
            }
        },
        onBlock = {
            scope.launch {
                if (!gateways.contacts().block(contactId)) resultId = org.ghost.ui.R.string.contact_action_failed
                version++
            }
        },
        onUnblock = {
            scope.launch {
                if (!gateways.contacts().unblock(contactId)) resultId = org.ghost.ui.R.string.contact_action_failed
                version++
            }
        },
        onReset = {
            scope.launch {
                val ok = gateways.contacts().resetSession(contactId)
                resultId = if (ok) org.ghost.ui.R.string.contact_reset_done else org.ghost.ui.R.string.contact_action_failed
                version++
            }
        },
        onDelete = {
            scope.launch {
                if (gateways.contacts().deleteContact(contactId)) {
                    backStack.pop()
                } else {
                    resultId = org.ghost.ui.R.string.contact_action_failed
                }
            }
        },
        onBack = { backStack.pop() },
    )
}

@Composable
private fun ContactAddRoute(gateways: GatewaySet, backStack: BackStack) {
    val model = remember { ContactAddModel(gateways.dm()) }
    ContactAddScreen(
        model = model,
        onAdded = { backStack.pop() },
        onBack = { backStack.pop() },
    )
}

@Composable
private fun MyCardRoute(gateways: GatewaySet, backStack: BackStack) {
    var link by remember { mutableStateOf<SensitiveText?>(null) }
    LaunchedEffect(Unit) { link = gateways.dm().myCard() }
    MyCardScreen(link = link, onBack = { backStack.pop() })
}

@Composable
private fun RequestsRoute(gateways: GatewaySet, backStack: BackStack) {
    val scope = rememberCoroutineScope()
    var requests by remember { mutableStateOf<List<org.ghost.ui.gateway.RequestView>>(emptyList()) }
    var names by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var version by remember { mutableStateOf(0) }
    LaunchedEffect(version) {
        names = gateways.dm().contactNames()
        requests = gateways.dm().requests()
    }
    RequestsScreen(
        requests = requests,
        names = names,
        onAccept = { id -> scope.launch { if (gateways.contacts().acceptRequest(id)) version++ } },
        onReject = { id -> scope.launch { if (gateways.contacts().rejectRequest(id)) version++ } },
        onBlock = { id -> scope.launch { if (gateways.contacts().blockRequest(id)) version++ } },
        onBack = { backStack.pop() },
    )
}

@Composable
private fun SafetyNumberRoute(
    contactId: String,
    pending: Boolean,
    gateways: GatewaySet,
    backStack: BackStack,
) {
    val scope = rememberCoroutineScope()
    var data by remember(contactId, pending) { mutableStateOf<org.ghost.ui.gateway.SafetyNumberData?>(null) }
    var loaded by remember(contactId, pending) { mutableStateOf(false) }
    var resultId by remember(contactId, pending) { mutableStateOf<Int?>(null) }
    LaunchedEffect(contactId, pending) {
        data = gateways.contacts().safetyNumber(contactId, pending)
        loaded = true
    }
    if (!loaded) {
        ActivatingScreen()
        return
    }
    SafetyNumberScreen(
        data = data,
        pending = pending,
        resultMessage = resultId?.let { stringResource(it) },
        onVerify = { payload ->
            scope.launch {
                val ok = gateways.contacts().verify(contactId, pending, payload)
                resultId = if (ok) org.ghost.ui.R.string.dm_verify_success else org.ghost.ui.R.string.dm_verify_failed
            }
        },
        onVerifyManually = {
            scope.launch {
                val ok = gateways.contacts().verifyManually(contactId)
                resultId = if (ok) org.ghost.ui.R.string.dm_verify_success else org.ghost.ui.R.string.dm_verify_failed
            }
        },
        onAcknowledge = {
            scope.launch {
                val ok = gateways.contacts().acknowledgeKeyChange(contactId)
                if (ok) backStack.pop() else resultId = org.ghost.ui.R.string.dm_verify_failed
            }
        },
        onBack = { backStack.pop() },
    )
}

@Composable
private fun ChannelListRoute(gateways: GatewaySet, backStack: BackStack) {
    val model = remember { ChannelListModel(gateways.channel()) }
    var items by remember { mutableStateOf<List<org.ghost.ui.gateway.ChannelView>>(emptyList()) }
    LaunchedEffect(Unit) {
        model.load()
        items = model.items
    }
    ChannelListScreen(
        items = items,
        onOpen = { backStack.push(Route.Channel(it)) },
        onCreate = { backStack.push(Route.ChannelCreate) },
        onJoin = { backStack.push(Route.ChannelAccept("")) },
    )
}

@Composable
private fun ChannelCreateRoute(gateways: GatewaySet, backStack: BackStack) {
    val model = remember { ChannelCreateModel(gateways.channel(), gateways.identity()) }
    ChannelCreateScreen(model = model, onCreated = { backStack.pop() })
}

@Composable
private fun ChannelRoute(channelId: String, gateways: GatewaySet, backStack: BackStack) {
    val model = remember(channelId) { ChannelModel(gateways.channel(), channelId) }
    var channel by remember(channelId) { mutableStateOf<org.ghost.ui.gateway.ChannelView?>(null) }
    var posts by remember(channelId) { mutableStateOf<List<org.ghost.ui.gateway.ChannelPostView>>(emptyList()) }
    LaunchedEffect(channelId) {
        // Local reads only: outgoing states and received posts change at engine passes, so the
        // visible screen re-queries instead of freezing the state captured when it opened.
        while (true) {
            model.load()
            channel = model.channel
            posts = model.posts
            delay(2_000L)
        }
    }
    val current = channel
    if (current == null) {
        ActivatingScreen()
    } else {
        ChannelScreen(
            model = model,
            channel = current,
            onLeft = { backStack.pop() },
            onInvite = { backStack.push(Route.ChannelInvite(channelId)) },
            onMembers = { backStack.push(Route.Members(channelId)) },
            posts = posts,
            onPosted = { posts = model.posts },
        )
    }
}

@Composable
private fun ChannelAcceptRoute(link: String, gateways: GatewaySet, backStack: BackStack) {
    if (link.isEmpty()) {
        ChannelLinkScreen(
            onLink = { backStack.replace(Route.ChannelAccept(it)) },
            onBack = { backStack.pop() },
        )
        return
    }
    val model = remember(link) { ChannelAcceptModel(gateways.channel(), gateways.identity()) }
    var loaded by remember(link) { mutableStateOf(false) }
    var acceptedVersion by remember(link) { mutableStateOf(0) }
    LaunchedEffect(link) {
        model.onLoadWordList()
        model.onInspect(link)
        loaded = true
    }
    if (!loaded) {
        ActivatingScreen()
    } else {
        ChannelAcceptScreen(
            model = model,
            link = link,
            onAccepted = { acceptedVersion++ },
        )
    }
}

@Composable
private fun ChannelInviteRoute(channelId: String, gateways: GatewaySet, backStack: BackStack, app: GhostApp) {
    val model = remember(channelId) { ChannelInviteModel(gateways.channel(), gateways.identity()) }
    var link by remember(channelId) { mutableStateOf<SensitiveText?>(null) }
    val issued = link
    if (issued == null) {
        ChannelInviteRequestScreen(
            model = model,
            channelId = channelId,
            onIssued = { link = model.issuedLink },
            onBack = { backStack.pop() },
        )
    } else {
        DisposableEffect(channelId) {
            onDispose { model.onLinkDisplayed() }
        }
        ChannelInviteScreen(
            link = issued,
            onCopy = {
                app.clipboardOwner.copy(org.ghost.ui.protect.SensitiveClipboard.CopyKind.CHANNEL_INVITE_LINK, issued)
            },
            onBack = { backStack.pop() },
        )
    }
}

@Composable
private fun MembersRoute(channelId: String, gateways: GatewaySet, backStack: BackStack) {
    val scope = rememberCoroutineScope()
    var members by remember(channelId) { mutableStateOf<List<org.ghost.ui.gateway.ChannelMemberView>>(emptyList()) }
    var fingerprint by remember(channelId) { mutableStateOf<org.ghost.ui.gateway.ChannelFingerprintView?>(null) }
    var resultId by remember(channelId) { mutableStateOf<Int?>(null) }
    var version by remember(channelId) { mutableStateOf(0) }
    LaunchedEffect(channelId, version) {
        members = gateways.channel().members(channelId)
        fingerprint = gateways.channel().fingerprint(channelId)
    }
    MembersScreen(
        members = members,
        fingerprint = fingerprint,
        resultMessage = resultId?.let { stringResource(it) },
        onRemove = { memberId ->
            scope.launch {
                if (!gateways.channel().removeMember(channelId, memberId)) {
                    resultId = org.ghost.ui.R.string.ch_members_remove_failed
                }
                version++
            }
        },
        onReveal = { memberId -> backStack.push(Route.Reveal(channelId, memberId)) },
        onBack = { backStack.pop() },
    )
}

@Composable
private fun RevealRoute(channelId: String, memberId: String, gateways: GatewaySet, backStack: BackStack) {
    val scope = rememberCoroutineScope()
    var fingerprint by remember(channelId) { mutableStateOf<org.ghost.ui.gateway.ChannelFingerprintView?>(null) }
    var resultId by remember(channelId) { mutableStateOf<Int?>(null) }
    LaunchedEffect(channelId) { fingerprint = gateways.channel().fingerprint(channelId) }
    RevealScreen(
        memberId = memberId,
        fingerprint = fingerprint,
        resultMessage = resultId?.let { stringResource(it) },
        onReveal = {
            scope.launch {
                val ok = gateways.channel().reveal(channelId, memberId)
                resultId = if (ok) org.ghost.ui.R.string.ch_reveal_success else org.ghost.ui.R.string.ch_reveal_failed
            }
        },
        onBack = { backStack.pop() },
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
        onBuyXmr = { appScope.launch { startOrResumeXmrPurchase(access) } },
        onOpenPurchase = { backStack.push(Route.Purchase(it)) },
        onRevokeInvite = { index -> appScope.launch { access.revokeInvite(index) } },
        onInvites = { backStack.push(Route.Invites) },
        onPayout = { backStack.push(Route.Payout) },
    )
}

@Composable
private fun InvitesRoute(app: GhostApp, gateways: GatewaySet, backStack: BackStack) {
    val scope = rememberCoroutineScope()
    val access = gateways.access()
    var invites by remember { mutableStateOf<List<InviteView>>(emptyList()) }
    var created by remember { mutableStateOf<SensitiveText?>(null) }
    var version by remember { mutableStateOf(0) }
    LaunchedEffect(version) { invites = access.invites() }
    InvitesScreen(
        invites = invites,
        created = created,
        resultMessage = null,
        onCreate = {
            scope.launch {
                val day = (System.currentTimeMillis() / 86_400_000L).toInt() + 7
                created = access.createInvite(day)
            }
        },
        onRevoke = { index -> scope.launch { access.revokeInvite(index); version++ } },
        onCopy = {
            created?.let { link ->
                app.clipboardOwner.copy(org.ghost.ui.protect.SensitiveClipboard.CopyKind.INVITE_LINK, link)
            }
        },
        onBack = { backStack.pop() },
    )
}

@Composable
private fun PayoutRoute(gateways: GatewaySet, backStack: BackStack) {
    val scope = rememberCoroutineScope()
    var resultId by remember { mutableStateOf<Int?>(null) }
    PayoutScreen(
        resultMessage = resultId?.let { stringResource(it) },
        onClaim = { address ->
            scope.launch {
                val ok = gateways.access().claimPayout(address)
                resultId = if (ok) org.ghost.ui.R.string.access_payout_success else org.ghost.ui.R.string.access_payout_failed
            }
        },
        onBack = { backStack.pop() },
    )
}

/** A pending request must resend the identical invoice request; only an issued invoice has status. */
internal suspend fun startOrResumeXmrPurchase(access: org.ghost.ui.gateway.AccessGateway) {
    val open = access.purchases().firstOrNull {
        it.state in setOf(
            org.ghost.ui.gateway.PurchaseState.PREPARED,
            org.ghost.ui.gateway.PurchaseState.INVOICE_PENDING,
            org.ghost.ui.gateway.PurchaseState.READY,
            org.ghost.ui.gateway.PurchaseState.PAYMENT_UNVERIFIED,
            org.ghost.ui.gateway.PurchaseState.UNDERPAID,
            org.ghost.ui.gateway.PurchaseState.CONFIRMING,
        )
    }
    when (open?.state) {
        null -> {
            access.startPurchase("XMR")
            delay(1_000)
            access.purchases()
                .firstOrNull { it.state == org.ghost.ui.gateway.PurchaseState.PREPARED }
                ?.let { access.requestInvoiceNow(it.id) }
        }
        org.ghost.ui.gateway.PurchaseState.PREPARED,
        org.ghost.ui.gateway.PurchaseState.INVOICE_PENDING,
        -> access.requestInvoiceNow(open.id)
        else -> access.checkNow(open.id)
    }
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
        onCheckNow = { appScope.launch { paymentModel.onCheckNow(purchaseId) } },
        onCancel = {
            appScope.launch {
                if (gateways.access().cancelPurchase(purchaseId)) backStack.pop()
            }
        },
    )
}

/** Disclosures, then the instruction read; null and failed reads end in an explicit retry/back state. */
@Composable
private fun PaymentInstructionsRoute(
    app: GhostApp,
    purchaseId: String,
    backStack: BackStack,
    paymentModel: PaymentModel,
    appScope: kotlinx.coroutines.CoroutineScope,
) {
    var payment by remember { mutableStateOf<PaymentView?>(null) }
    var disclosures by remember { mutableStateOf<Set<org.ghost.ui.gateway.PaymentDisclosure>?>(null) }
    var failed by remember { mutableStateOf(false) }
    var attempt by remember { mutableStateOf(0) }
    val shown = remember { java.util.concurrent.atomic.AtomicBoolean(false) }
    LaunchedEffect(purchaseId, attempt) {
        payment = null
        failed = false
        disclosures = null
        var loadedDisclosures: Set<org.ghost.ui.gateway.PaymentDisclosure>? = null
        val loaded = kotlinx.coroutines.withTimeoutOrNull(PAYMENT_READ_TIMEOUT_MILLIS) {
            val required = paymentModel.requiredDisclosures(purchaseId)
            loadedDisclosures = required
            if (required.isEmpty()) {
                runCatching { paymentModel.onOpenInstructions(purchaseId) }.getOrNull()
            } else {
                null
            }
        }
        val required = loadedDisclosures
        disclosures = required
        when {
            required == null -> failed = true
            required.isNotEmpty() -> Unit
            loaded == null -> failed = true
            else -> {
                payment = loaded
                shown.set(true)
            }
        }
    }
    DisposableEffect(purchaseId) {
        onDispose {
            if (shown.getAndSet(false)) {
                // §3.3/§3.5: only a real instruction showing brackets the payment-screen hold.
                appScope.launch { paymentModel.onInstructionsClosed(purchaseId) }
            }
        }
    }
    val required = disclosures
    val p = payment
    when {
        required == null -> ActivatingScreen()
        required.isNotEmpty() -> org.ghost.ui.feature.access.PaymentDisclosuresScreen(
            disclosures = required,
            onConfirm = {
                appScope.launch {
                    paymentModel.onDisclosuresConfirmed(purchaseId)
                    disclosures = emptySet()
                    attempt++
                }
            },
        )
        failed -> org.ghost.ui.feature.access.PaymentInstructionsUnavailableScreen(
            onRetry = { attempt++ },
            onBack = { backStack.pop() },
        )
        p == null -> ActivatingScreen()
        else -> PaymentInstructionsScreen(
            payment = p,
            onCopyAddress = {
                app.clipboardOwner.copy(
                    org.ghost.ui.protect.SensitiveClipboard.CopyKind.PAYMENT_SUBADDRESS,
                    p.subaddress,
                )
            },
            onCopyAmount = {
                app.clipboardOwner.copy(
                    org.ghost.ui.protect.SensitiveClipboard.CopyKind.PAYMENT_AMOUNT,
                    p.amount,
                )
            },
        )
    }
}

internal fun sourceSummary(version: String, commit: String, dirty: Boolean): String =
    version + "\nsource=" + commit + (if (dirty) " (modified)" else "")

@androidx.media3.common.util.UnstableApi
@Composable
private fun MediaViewerRoute(app: GhostApp, itemId: String, viewOnce: Boolean, backStack: BackStack) {
    var handle by remember(itemId, viewOnce) { mutableStateOf<org.ghost.messaging.api.MediaHandle?>(null) }
    var loaded by remember(itemId, viewOnce) { mutableStateOf(false) }
    LaunchedEffect(itemId, viewOnce) {
        handle = kotlinx.coroutines.withContext(GhostUiIo.dispatcher) {
            val id = org.ghost.messaging.api.MessageId(
                ByteArray(itemId.length / 2) { itemId.substring(2 * it, 2 * it + 2).toInt(16).toByte() },
            )
            val messaging = app.messaging
            if (viewOnce) messaging?.openViewOnce(id) else messaging?.openMedia(id)
        }
        loaded = true
    }
    DisposableEffect(itemId, viewOnce) {
        onDispose { handle?.close() }
    }
    if (!loaded) {
        ActivatingScreen()
    } else {
        val opened = handle
        if (opened == null) {
            TextPageScreen(
                titleId = org.ghost.ui.R.string.media_open,
                bodyIds = listOf(org.ghost.ui.R.string.media_unavailable),
                onBack = { backStack.pop() },
            )
        } else {
            SecureMediaViewer(opened, onBack = { backStack.pop() })
        }
    }
}

@Composable
private fun WipeRoute(gateways: GatewaySet) {
    val scope = rememberCoroutineScope()
    var pinVerified by remember { mutableStateOf(false) }
    if (!pinVerified) {
        LockPad(gateways = gateways, onUnlocked = { pinVerified = true })
    } else {
        WipeScreen(onConfirmed = { scope.launch { gateways.wipe().wipe() } })
    }
}

@Composable
private fun PrivacyRoute(gateways: GatewaySet) {
    val model = remember { SettingsModel(gateways.settings()) }
    var loaded by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        model.load()
        loaded = true
    }
    if (loaded) PrivacyScreen(model = model, downloads = null) else ActivatingScreen()
}

@Composable
private fun SecurityRoute(app: GhostApp, gateways: GatewaySet, backStack: BackStack) {
    val model = remember { SecurityModel(gateways.lock()) }
    var loaded by remember { mutableStateOf(false) }
    var changingPin by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        model.load()
        loaded = true
    }
    when {
        !loaded -> ActivatingScreen()
        changingPin -> PinSetupScreen(
            onPinSet = { digits ->
                val ok = runCatching { model.onSetPin(digits) }.isSuccess
                if (ok) changingPin = false
                ok
            },
        )
        else -> SecurityScreen(
            model = model,
            onChangePin = { changingPin = true },
            onBackup = { backStack.push(Route.Backup) },
            onAccessibility = { backStack.push(Route.Accessibility) },
            onDiagnostic = { backStack.push(Route.Diagnostic) },
        )
    }
}

@Composable
private fun BackupReviewRoute(gateways: GatewaySet, backStack: BackStack) {
    var verified by remember { mutableStateOf(false) }
    var words by remember { mutableStateOf<List<String>?>(null) }
    var wordList by remember { mutableStateOf<List<String>?>(null) }
    var positions by remember { mutableStateOf<List<Int>?>(null) }
    var indices by remember { mutableStateOf<IntArray?>(null) }
    var checking by remember { mutableStateOf(false) }
    LaunchedEffect(verified) {
        if (verified && words == null) {
            val idx = gateways.identity().mnemonicIndices()
            val list = gateways.identity().wordList()
            indices = idx
            wordList = list
            words = idx.map { list[it] }
            positions = gateways.identity().backupChallenge(4, emptyList())
        }
    }
    when {
        !verified -> LockPad(gateways = gateways, onUnlocked = { verified = true })
        words == null || wordList == null || positions == null || indices == null -> ActivatingScreen()
        !checking -> WordsScreen(words = words!!, onShown = { checking = true })
        else -> BackupScreen(
            positions = positions!!,
            words = wordList!!,
            onVerify = { answers -> gateways.identity().verifyBackup(indices!!, positions!!, answers) },
            onDone = { backStack.pop() },
        )
    }
}

@Composable
private fun AccessibilityRoute(app: GhostApp, backStack: BackStack) {
    var services by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        services = kotlinx.coroutines.withContext(GhostUiIo.dispatcher) {
            android.provider.Settings.Secure.getString(
                app.contentResolver,
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            ) ?: ""
        }
    }
    val current = services
    if (current == null) ActivatingScreen() else AccessibilityScreen(services = current, onBack = { backStack.pop() })
}

@Composable
private fun DiagnosticRoute(app: GhostApp, backStack: BackStack) {
    var rows by remember { mutableStateOf<List<Pair<Int, String>>?>(null) }
    LaunchedEffect(Unit) {
        rows = kotlinx.coroutines.withContext(GhostUiIo.dispatcher) {
            val diagnostic = app.syncController.diagnostics()
            val messaging = app.messaging?.status()
            listOf(
                org.ghost.ui.R.string.diagnostic_sync_stage to diagnostic.stage.name,
                org.ghost.ui.R.string.diagnostic_last_error to (diagnostic.lastError ?: "none"),
                org.ghost.ui.R.string.diagnostic_pending_sends to (messaging?.pendingSends ?: 0).toString(),
                org.ghost.ui.R.string.diagnostic_establishing to (messaging?.establishing ?: 0).toString(),
                org.ghost.ui.R.string.diagnostic_poisoned to (messaging?.poisoned ?: 0).toString(),
                org.ghost.ui.R.string.diagnostic_drops to (messaging?.drops?.values?.sum() ?: 0).toString(),
            )
        }
    }
    val current = rows
    if (current == null) {
        ActivatingScreen()
    } else {
        DiagnosticScreen(
            rows = current,
            onCrashReports = { backStack.push(Route.Crash) },
            onBack = { backStack.pop() },
        )
    }
}

@Composable
private fun CrashReportsRoute(app: GhostApp, backStack: BackStack) {
    val scope = rememberCoroutineScope()
    var reports by remember { mutableStateOf<List<String>?>(null) }
    var version by remember { mutableStateOf(0) }
    LaunchedEffect(version) {
        reports = kotlinx.coroutines.withContext(GhostUiIo.dispatcher) {
            val dir = java.io.File(app.noBackupFilesDir, "crash")
            dir.listFiles()?.filter { it.isFile }?.sortedBy { it.name }?.take(10)?.map { file ->
                file.inputStream().use { input ->
                    val bytes = ByteArray(65_536)
                    val count = input.read(bytes)
                    String(bytes, 0, count.coerceAtLeast(0), Charsets.UTF_8)
                }
            } ?: emptyList()
        }
    }
    val current = reports
    if (current == null) {
        ActivatingScreen()
    } else {
        CrashReportsScreen(
            reports = current,
            onDelete = {
                scope.launch {
                    kotlinx.coroutines.withContext(GhostUiIo.dispatcher) {
                        java.io.File(app.noBackupFilesDir, "crash").listFiles()?.forEach { it.delete() }
                    }
                    version++
                }
            },
            onBack = { backStack.pop() },
        )
    }
}

@Composable
private fun LicencesRoute(app: GhostApp, backStack: BackStack) {
    var notices by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        notices = runCatching {
            app.assets.open("THIRD_PARTY_NOTICES.txt").bufferedReader().use { it.readText() }
        }.getOrElse { app.resources.getString(org.ghost.ui.R.string.state_unavailable) }
    }
    val text = notices
    if (text == null) ActivatingScreen() else LicencesScreen(notices = text, onBack = { backStack.pop() })
}

@Composable
private fun UpdateRoute(app: GhostApp, gateways: GatewaySet, backStack: BackStack) {
    val updater = gateways.update()
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf(org.ghost.ui.gateway.UpdateStatusView("NO_UPDATER", null)) }
    var version by remember { mutableStateOf(0) }
    LaunchedEffect(version) {
        if (updater == null) {
            status = org.ghost.ui.gateway.UpdateStatusView("NO_UPDATER", null)
        } else {
            while (true) {
                status = updater.status()
                delay(2_000)
            }
        }
    }
    val installed = remember {
        val packageVersion = runCatching {
            app.packageManager.getPackageInfo(app.packageName, 0).versionName ?: ""
        }.getOrDefault("")
        app.resources.getString(org.ghost.ui.R.string.about_version_label) + " " + packageVersion
    }
    UpdateScreen(
        status = status,
        installedVersion = installed,
        onCheck = { scope.launch { updater?.requestCheck(); version++ } },
        onDownload = { scope.launch { updater?.requestDownload(); version++ } },
        onInstall = { scope.launch { updater?.install() } },
        onBack = { backStack.pop() },
    )
}

/** ABOUT: version and provenance plus the local reference pages. */
@Composable
private fun AboutRoute(app: GhostApp, backStack: BackStack) {
    val version = remember {
        val packageVersion = runCatching {
            app.packageManager.getPackageInfo(app.packageName, 0).versionName ?: ""
        }.getOrDefault("")
        sourceSummary(packageVersion, org.ghost.app.BuildConfig.SOURCE_COMMIT, org.ghost.app.BuildConfig.SOURCE_DIRTY)
    }
    AboutScreen(
        version = version,
        securityContact = "",
        onWhoSeesWhat = { backStack.push(Route.WhoSeesWhat) },
        onLimits = { backStack.push(Route.Limits) },
        onLicences = { backStack.push(Route.Licences) },
    )
}
