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
 * invite screen shows the link once, as QR (the copyable-text half waits for the SensitiveClipboard
 * wiring of §4.4; the QR is the in-person path ADR-57 recommends). The accept flow previews
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
                            // The marker is the padlock glyph from the resource; the row names
                            // the protection, never the passphrase.
                            Text(
                                text = stringResource(R.string.ch_list_protected),
                                style = MaterialTheme.typography.titleMedium,
                            )
                        }
                    }
                    if (c.unread > 0) Text(text = c.unread.toString(), style = MaterialTheme.typography.labelLarge)
                }
            }
        }
        TextButton(onClick = onCreate, labelId = R.string.ch_list_create)
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
                if (withPassword) scope.launch { model.onDrawPassphrase() } else model.onPassphraseDiscarded()
            },
            labelId = R.string.ch_create_password,
        )
        val words = model.passphrase
        if (withPassword && words != null) {
            Text(
                text = stringResource(R.string.ch_create_passphrase_title),
                style = MaterialTheme.typography.titleMedium,
            )
            // The one-time display: §6.5.1's frame is the channel's, never the seed's.
            SensitiveTextView(text = SensitiveText(words.joinToString(" ")), style = MaterialTheme.typography.bodyLarge)
            Text(text = stringResource(R.string.ch_create_passphrase_write), style = MaterialTheme.typography.bodyMedium)
            if (!model.passphraseWritten) {
                TextButton(onClick = { model.onPassphraseWritten() }, labelId = R.string.ch_create_passphrase_written)
            }
        }
        Text(text = stringResource(R.string.ch_create_hint), style = MaterialTheme.typography.bodyMedium)
        Button(
            onClick = { scope.launch { model.onCreate(name.text.toString()); onCreated() } },
            enabled = name.text.isNotEmpty() && (!withPassword || model.passphraseWritten),
        ) {
            Text(text = stringResource(R.string.ch_create_button))
        }
    }
}

/** The one-time invite display: QR plus the warning that it will not come back. */
@Composable
fun ChannelInviteScreen(
    link: SensitiveText,
    modifier: Modifier = Modifier,
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
                Text(text = preview.channelName, style = MaterialTheme.typography.titleMedium)
            }
            if (preview.alreadyMember) {
                Text(text = stringResource(R.string.ch_accept_already_member), style = MaterialTheme.typography.bodyMedium)
            }
            if (preview.passwordRequired && !model.accepted) {
                Text(
                    text = stringResource(R.string.ch_accept_password_required),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(text = typed.joinToString(" "), style = MaterialTheme.typography.bodyLarge)
                WordKeyboard(
                    suggestions = model.wordList.filter { it.startsWith(prefix) }.take(4),
                    onLetter = { prefix += it },
                    onDelete = { prefix = prefix.dropLast(1) },
                    onPick = { word ->
                        typed.add(word)
                        prefix = ""
                    },
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            if (!model.accepted) {
                Button(
                    onClick = {
                        scope.launch {
                            val indices = if (preview.passwordRequired) model.indicesForPassphrase(typed.toList()) else null
                            model.onAccept(link, indices)
                            onAccepted()
                        }
                    },
                    enabled = !preview.alreadyMember && (!preview.passwordRequired || typed.size >= ChannelCreateModel.PASSPHRASE_WORDS),
                ) {
                    Text(text = stringResource(R.string.ch_accept_button))
                }
            } else {
                Text(text = stringResource(R.string.ch_accept_wait), style = MaterialTheme.typography.bodyMedium)
            }
            Text(text = stringResource(R.string.ch_accept_pseudonym), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/** One channel: the composer and the posts' honest empty state until the coordination items. */
@Composable
fun ChannelScreen(
    model: ChannelModel,
    channel: ChannelView,
    onLeft: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val draft = remember { TextFieldState() }
    Column(modifier = modifier.fillMaxSize().padding(24.dp)) {
        Text(
            text = channel.name,
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        // The posts land with Phase 10's coordination items (§3.6); until then the state is
        // honestly empty. The rejoin action stays hidden for the same reason: §6.5 offers it on
        // `resync_needed` only, and the read model does not carry the flag yet.
        LazyColumn(modifier = Modifier.weight(1f)) {
            item {
                Text(text = stringResource(R.string.ch_detail_posts_empty), style = MaterialTheme.typography.bodyMedium)
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            GhostTextField(state = draft, modifier = Modifier.weight(1f))
            Button(onClick = {
                val body = draft.text.toString()
                draft.edit { replace(0, length, "") }
                scope.launch { model.onPost(SensitiveText(body)) }
            }) {
                Text(text = stringResource(R.string.ch_detail_send))
            }
        }
        HoldToConfirm(
            onConfirmed = { scope.launch { model.onLeave(); onLeft() } },
            holdLabelId = R.string.ch_detail_leave_hold,
            alternativeLabelId = R.string.confirm_alternative,
        )
    }
}
