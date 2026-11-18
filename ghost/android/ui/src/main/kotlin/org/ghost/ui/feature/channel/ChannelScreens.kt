package org.ghost.ui.feature.channel

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.ghost.ui.R
import org.ghost.ui.design.HoldToConfirm
import org.ghost.ui.design.TextButton
import org.ghost.ui.gateway.ChannelView
import org.ghost.ui.protect.GhostTextField
import org.ghost.ui.protect.SensitiveText
import org.ghost.ui.protect.SensitiveTextView
import org.ghost.ui.protect.WordKeyboard
import org.ghost.ui.qr.QrImage

/**
 * Phase 13 design §6.5 (J4): the channel screens. The list is name and unread count only — never
 * a post preview (Q14, T33). The create flow draws the §6.5.1 passphrase and shows it once. The
 * invite flow retypes a password channel's five words, then shows the link once as QR and
 * copyable text through SensitiveClipboard (§4.4). The accept flow previews
 * locally before anything is written (FE-6). The channel screen posts and leaves; its rejoin
 * action stays hidden until the read model carries `resync_needed` — §6.5 offers it on that flag
 * only, and a button that always shows would be a control that lies.
 */
@Composable
fun ChannelListScreen(
    items: List<ChannelView>,
    onOpen: (String) -> Unit,
    onCreate: () -> Unit,
    modifier: Modifier = Modifier,
    onJoin: (() -> Unit)? = null,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp)) {
        Text(
            text = stringResource(R.string.ch_list_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (items.isEmpty()) {
            Text(text = stringResource(R.string.ch_list_empty), style = MaterialTheme.typography.bodyMedium)
        }
        LazyColumn(modifier = Modifier.weight(1f)) {
            items(items, key = { it.id }) { c ->
                Row(
                    modifier = Modifier.fillMaxWidth().clickable { onOpen(c.id) }.padding(vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(text = c.name, style = MaterialTheme.typography.titleMedium)
                        if (c.passwordProtected) {
                            Text(text = stringResource(R.string.ch_list_protected), style = MaterialTheme.typography.titleMedium)
                        }
                    }
                    if (c.unread > 0) Text(text = c.unread.toString(), style = MaterialTheme.typography.labelLarge)
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TextButton(onClick = onCreate, labelId = R.string.ch_list_create)
            if (onJoin != null) TextButton(onClick = onJoin, labelId = R.string.ch_list_join)
        }
    }
}

/** The create flow: name, the optional one-time passphrase, the create. */
@Composable
fun ChannelCreateScreen(
    model: ChannelCreateModel,
    onCreated: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val name = remember { TextFieldState() }
    var withPassword by remember { mutableStateOf(false) }
    var words by remember { mutableStateOf<List<String>?>(null) }
    var written by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<String?>(null) }
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = stringResource(R.string.ch_create_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.ch_create_name_label), style = MaterialTheme.typography.labelLarge)
        GhostTextField(state = name, modifier = Modifier.fillMaxWidth())
        TextButton(
            onClick = {
                withPassword = !withPassword
                written = false
                words = null
                if (withPassword) {
                    scope.launch { model.onDrawPassphrase(); words = model.passphrase }
                } else {
                    model.onPassphraseDiscarded()
                }
            },
            labelId = R.string.ch_create_password,
        )
        val shownWords = words
        if (withPassword && shownWords != null) {
            Text(text = stringResource(R.string.ch_create_passphrase_title), style = MaterialTheme.typography.titleMedium)
            SensitiveTextView(text = SensitiveText(shownWords.joinToString(" ")), style = MaterialTheme.typography.bodyLarge)
            Text(text = stringResource(R.string.ch_create_passphrase_write), style = MaterialTheme.typography.bodyMedium)
            if (!written) {
                TextButton(
                    onClick = { model.onPassphraseWritten(); written = true },
                    labelId = R.string.ch_create_passphrase_written,
                )
            }
        }
        Text(text = stringResource(R.string.ch_create_hint), style = MaterialTheme.typography.bodyMedium)
        if (failed) {
            Text(
                text = stringResource(channelCreateFailureLabel(result)),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Button(
            onClick = {
                failed = false
                scope.launch {
                    val ok = runCatching { model.onCreate(name.text.toString()) }.isSuccess && model.result == "CREATED"
                    result = model.result
                    if (ok) onCreated() else failed = true
                }
            },
            enabled = name.text.isNotEmpty() && (!withPassword || written),
        ) {
            Text(text = stringResource(R.string.ch_create_button))
        }
    }
}

/** Loads the channel and, for a password channel, collects the sponsor's five retyped words. */
@Composable
fun ChannelInviteRequestScreen(
    model: ChannelInviteModel,
    channelId: String,
    onIssued: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val typed = remember { mutableStateListOf<String>() }
    var prefix by remember { mutableStateOf("") }
    var loaded by remember(channelId) { mutableStateOf(false) }
    var busy by remember(channelId) { mutableStateOf(false) }
    LaunchedEffect(channelId) {
        model.onLoad(channelId)
        if (!model.passwordProtected && !model.failed) model.onCreateInvite(channelId)
        loaded = true
        onIssued()
    }
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = stringResource(R.string.ch_invite_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (loaded && model.passwordProtected) {
            Text(text = stringResource(R.string.ch_invite_retype), style = MaterialTheme.typography.bodyMedium)
            Column { typed.forEach { word -> Text(text = word, style = MaterialTheme.typography.bodyLarge) } }
            WordKeyboard(
                suggestions = model.wordList.filter { it.startsWith(prefix) }.take(4),
                onLetter = { if (prefix.length < 4) prefix += it },
                onDelete = {
                    if (prefix.isNotEmpty()) prefix = prefix.dropLast(1) else if (typed.isNotEmpty()) typed.removeAt(typed.lastIndex)
                },
                onPick = { word ->
                    if (typed.size < ChannelCreateModel.PASSPHRASE_WORDS) typed.add(word)
                    prefix = ""
                },
            )
            Button(
                onClick = {
                    scope.launch {
                        busy = true
                        try {
                            model.onCreateInvite(channelId, model.indicesForPassphrase(typed.toList()))
                            onIssued()
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && typed.size == ChannelCreateModel.PASSPHRASE_WORDS,
            ) {
                Text(text = stringResource(R.string.access_invite_create))
            }
        }
        if (loaded && model.failed) {
            Text(
                text = stringResource(R.string.ch_invite_failed),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        TextButton(onClick = onBack, labelId = R.string.payment_back)
    }
}

/** The one-time invite display: QR, sensitive copy plus the warning that it will not come back. */
@Composable
fun ChannelInviteScreen(
    link: SensitiveText,
    modifier: Modifier = Modifier,
    onCopy: (() -> Unit)? = null,
    onBack: (() -> Unit)? = null,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.ch_invite_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        QrImage(payload = link)
        Text(text = stringResource(R.string.ch_invite_once), style = MaterialTheme.typography.bodyMedium)
        SensitiveTextView(text = link, style = MaterialTheme.typography.bodyMedium)
        if (onCopy != null) TextButton(onClick = onCopy, labelId = R.string.access_invite_copy)
        if (onBack != null) TextButton(onClick = onBack, labelId = R.string.payment_back)
    }
}

/** The join flow: the local preview, the optional passphrase on the WordKeyboard, the request. */
@Composable
fun ChannelAcceptScreen(
    model: ChannelAcceptModel,
    link: String,
    onAccepted: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val typed = remember { mutableStateListOf<String>() }
    var prefix by remember { mutableStateOf("") }
    var accepted by remember { mutableStateOf(model.accepted) }
    var result by remember { mutableStateOf(model.result) }
    Column(modifier = modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = stringResource(R.string.ch_accept_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        val preview = model.preview
        if (preview == null) {
            Text(text = stringResource(R.string.ch_accept_unreadable), style = MaterialTheme.typography.bodyMedium)
        } else {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(text = stringResource(R.string.ch_accept_channel), style = MaterialTheme.typography.labelLarge)
                Text(
                    text = preview.channelName.ifEmpty { stringResource(R.string.ch_accept_channel_generic) },
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            if (preview.alreadyMember) {
                Text(text = stringResource(R.string.ch_accept_already_member), style = MaterialTheme.typography.bodyMedium)
            }
            if (preview.passwordRequired && !accepted) {
                Text(text = stringResource(R.string.ch_accept_password_required), style = MaterialTheme.typography.bodyMedium)
                Column { typed.forEach { word -> Text(text = word, style = MaterialTheme.typography.bodyLarge) } }
                WordKeyboard(
                    suggestions = model.wordList.filter { it.startsWith(prefix) }.take(4),
                    onLetter = { if (prefix.length < 4) prefix += it },
                    onDelete = {
                        if (prefix.isNotEmpty()) prefix = prefix.dropLast(1) else if (typed.isNotEmpty()) typed.removeAt(typed.lastIndex)
                    },
                    onPick = { word ->
                        if (typed.size < ChannelCreateModel.PASSPHRASE_WORDS) typed.add(word)
                        prefix = ""
                    },
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            if (!accepted) {
                Button(
                    onClick = {
                        scope.launch {
                            val indices = if (preview.passwordRequired) model.indicesForPassphrase(typed.toList()) else null
                            model.onAccept(link, indices)
                            accepted = model.accepted
                            result = model.result
                            onAccepted()
                        }
                    },
                    enabled = !preview.alreadyMember && (!preview.passwordRequired || typed.size >= ChannelCreateModel.PASSPHRASE_WORDS),
                ) {
                    Text(text = stringResource(R.string.ch_accept_button))
                }
                if (result != null) {
                    Text(
                        text = stringResource(R.string.ch_accept_failed),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            } else {
                Text(text = stringResource(R.string.ch_accept_wait), style = MaterialTheme.typography.bodyMedium)
            }
            Text(text = stringResource(R.string.ch_accept_pseudonym), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/** One channel: protected composer, invite entry and the destructive leave confirmation. */
@Composable
fun ChannelScreen(
    model: ChannelModel,
    channel: ChannelView,
    onLeft: () -> Unit,
    modifier: Modifier = Modifier,
    onInvite: (() -> Unit)? = null,
    onMembers: (() -> Unit)? = null,
    posts: List<org.ghost.ui.gateway.ChannelPostView> = emptyList(),
    onPosted: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()
    val draft = remember { TextFieldState() }
    val bytes = draft.text.toString().toByteArray(Charsets.UTF_8).size
    Column(modifier = modifier.fillMaxSize().padding(24.dp)) {
        Text(
            text = channel.name,
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            if (posts.isEmpty()) {
                item { Text(text = stringResource(R.string.ch_detail_posts_empty), style = MaterialTheme.typography.bodyMedium) }
            }
            items(posts, key = { it.id }) { post ->
                Column(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    if (post.isText) {
                        SensitiveTextView(text = post.body, style = MaterialTheme.typography.bodyLarge)
                    } else {
                        Text(text = stringResource(channelPostKindLabel(post.kind)), style = MaterialTheme.typography.bodyLarge)
                    }
                    Text(
                        text = formatChannelMinute(post.minute) + stringResource(R.string.dm_metadata_separator) +
                            stringResource(channelPostStateLabel(post.state)),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
        }
        if (bytes > 16_000) {
            Text(
                text = stringResource(R.string.ch_detail_too_large),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            GhostTextField(state = draft, modifier = Modifier.weight(1f))
            Button(
                onClick = {
                    val body = draft.text.toString()
                    draft.edit { replace(0, length, "") }
                    scope.launch { model.onPost(SensitiveText(body)); onPosted() }
                },
                enabled = draft.text.isNotBlank() && bytes <= 16_000,
            ) {
                Text(text = stringResource(R.string.ch_detail_send))
            }
        }
        if (onInvite != null) TextButton(onClick = onInvite, labelId = R.string.ch_detail_invite)
        if (onMembers != null) TextButton(onClick = onMembers, labelId = R.string.ch_members_open)
        HoldToConfirm(
            onConfirmed = { scope.launch { model.onLeave(); onLeft() } },
            holdLabelId = R.string.ch_detail_leave_hold,
            alternativeLabelId = R.string.confirm_alternative,
        )
    }
}
