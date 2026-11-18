package org.ghost.ui.feature.dm

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.ghost.ui.R
import org.ghost.ui.design.TextButton
import org.ghost.ui.gateway.ConversationSummary
import org.ghost.ui.gateway.ConversationView
import org.ghost.ui.gateway.MessageState
import org.ghost.ui.gateway.MessageView
import org.ghost.ui.protect.GhostTextField
import org.ghost.ui.protect.SensitiveText
import org.ghost.ui.protect.SensitiveTextView
import org.ghost.ui.qr.QrImage

/** J3: names and unread counts only; message previews never reach this screen. */
@Composable
fun ConversationListScreen(
    summaries: List<ConversationSummary>,
    names: Map<String, String>,
    onOpen: (String) -> Unit,
    onAddContact: () -> Unit,
    modifier: Modifier = Modifier,
    onMyCard: (() -> Unit)? = null,
    requestCount: Int = 0,
    onRequests: (() -> Unit)? = null,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.dm_list_title),
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.semantics { heading() },
        )
        if (summaries.isEmpty()) {
            Surface(tonalElevation = 1.dp, shape = MaterialTheme.shapes.large) {
                Text(
                    text = stringResource(R.string.dm_list_empty),
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(20.dp),
                )
            }
        }
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(summaries, key = { it.contactId }) { summary ->
                Surface(
                    modifier = Modifier.fillMaxWidth().clickable { onOpen(summary.contactId) },
                    shape = MaterialTheme.shapes.large,
                    tonalElevation = if (summary.unread > 0) 3.dp else 1.dp,
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 18.dp, vertical = 16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = names[summary.contactId] ?: stringResource(R.string.dm_contact_unnamed),
                            style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.weight(1f),
                        )
                        if (summary.unread > 0) {
                            Surface(
                                color = MaterialTheme.colorScheme.primary,
                                contentColor = MaterialTheme.colorScheme.onPrimary,
                                shape = MaterialTheme.shapes.small,
                            ) {
                                Text(
                                    text = summary.unread.toString(),
                                    style = MaterialTheme.typography.labelLarge,
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                )
                            }
                        }
                    }
                }
            }
        }
        if (onRequests != null) {
            TextButton(onClick = onRequests, labelId = R.string.dm_requests_title)
            if (requestCount > 0) {
                Text(text = requestCount.toString(), style = MaterialTheme.typography.labelLarge)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onAddContact, modifier = Modifier.weight(1f)) {
                Text(text = stringResource(R.string.dm_contact_add))
            }
            if (onMyCard != null) {
                OutlinedButton(onClick = onMyCard, modifier = Modifier.weight(1f)) {
                    Text(text = stringResource(R.string.dm_my_card))
                }
            }
        }
    }
}

/** A single protected bubble with delivery state, reactions and an honest retry action. */
@Composable
fun MessageBubble(
    message: MessageView,
    modifier: Modifier = Modifier,
    onRetry: (() -> Unit)? = null,
    onOpenMedia: (() -> Unit)? = null,
) {
    Row(
        modifier = modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = if (message.mine) Arrangement.End else Arrangement.Start,
    ) {
        Surface(
            modifier = Modifier.widthIn(max = 340.dp),
            shape = MaterialTheme.shapes.large,
            color = if (message.mine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
            contentColor = if (message.mine) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant,
        ) {
            Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                if (message.mediaKind > 0 && onOpenMedia != null) {
                    TextButton(onClick = onOpenMedia, labelId = R.string.media_open)
                } else {
                    SensitiveTextView(text = message.body, style = MaterialTheme.typography.bodyLarge)
                }
                Spacer(modifier = Modifier.height(5.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = formatMinute(message.minute),
                        style = MaterialTheme.typography.labelSmall,
                    )
                    if (message.mine) {
                        Text(
                            text = stringResource(R.string.dm_metadata_separator) + stringResource(message.state.labelId),
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }
                }
                val reaction = message.myReaction ?: message.peerReaction
                if (!reaction.isNullOrEmpty()) {
                    Text(text = reaction, style = MaterialTheme.typography.bodyMedium)
                }
                if (message.state == MessageState.FAILED && onRetry != null) {
                    TextButton(onClick = onRetry, labelId = R.string.dm_menu_retry)
                }
            }
        }
    }
}

/** J3 composer: the typed body is sent through the gateway and never persisted as a draft. */
@Composable
fun ConversationScreen(
    conversation: ConversationView,
    names: Map<String, String>,
    onSend: (String) -> Unit,
    modifier: Modifier = Modifier,
    onRetry: (String) -> Unit = {},
    onAttach: (() -> Unit)? = null,
    onSafetyNumber: (() -> Unit)? = null,
    onKeyChange: (() -> Unit)? = null,
    onContactInfo: (() -> Unit)? = null,
    onOpenMedia: (String) -> Unit = {},
) {
    val draft = remember { TextFieldState() }
    val body = draft.text.toString()
    val valid = body.isNotBlank() && body.toByteArray(Charsets.UTF_8).size <= 61_440
    Column(modifier = modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 12.dp)) {
        Text(
            text = names[conversation.contactId] ?: stringResource(R.string.dm_conversation_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        conversation.timerMinutes?.let { timer ->
            Text(
                text = stringResource(timer.labelId),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(vertical = 4.dp),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (onSafetyNumber != null) TextButton(onClick = onSafetyNumber, labelId = R.string.dm_safety_open)
            if (onKeyChange != null) TextButton(onClick = onKeyChange, labelId = R.string.dm_key_change_open)
            if (onContactInfo != null) TextButton(onClick = onContactInfo, labelId = R.string.contact_info_title)
        }
        LazyColumn(
            modifier = Modifier.weight(1f),
            reverseLayout = true,
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            items(conversation.items, key = { it.id }) { message ->
                MessageBubble(
                    message = message,
                    onRetry = { onRetry(message.id) },
                    onOpenMedia = { onOpenMedia(message.id) },
                )
            }
        }
        if (body.toByteArray(Charsets.UTF_8).size > 61_440) {
            Text(
                text = stringResource(R.string.dm_message_too_large),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        if (onAttach != null) {
            TextButton(onClick = onAttach, labelId = R.string.media_attach)
            Text(text = stringResource(R.string.media_attach_note), style = MaterialTheme.typography.bodySmall)
        }
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            GhostTextField(state = draft, modifier = Modifier.weight(1f))
            Button(
                onClick = {
                    val sent = draft.text.toString()
                    onSend(sent)
                    draft.edit { replace(0, length, "") }
                },
                enabled = valid,
            ) {
                Text(text = stringResource(R.string.dm_send))
            }
        }
    }
}

/** Contact-card paste flow; QR builds can feed the same model without changing the trust decision. */
@Composable
fun ContactAddScreen(
    model: ContactAddModel,
    onAdded: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val card = remember { TextFieldState() }
    var answer by remember { mutableStateOf(ContactAddModel.Answer.DONT_KNOW) }
    var submitting by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.dm_contact_add_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(text = stringResource(R.string.dm_contact_add_body), style = MaterialTheme.typography.bodyMedium)
        GhostTextField(state = card, modifier = Modifier.fillMaxWidth())
        if (card.text.isNotBlank()) {
            Text(
                text = stringResource(R.string.dm_provenance_question),
                style = MaterialTheme.typography.titleMedium,
            )
            ProvenanceChoice(R.string.dm_provenance_in_person, ContactAddModel.Answer.IN_FRONT_OF_ME, answer) { answer = it }
            ProvenanceChoice(R.string.dm_provenance_elsewhere, ContactAddModel.Answer.ELSEWHERE_ON_A_SCREEN, answer) { answer = it }
            ProvenanceChoice(R.string.dm_provenance_dont_know, ContactAddModel.Answer.DONT_KNOW, answer) { answer = it }
            Text(text = stringResource(R.string.dm_provenance_warning), style = MaterialTheme.typography.bodySmall)
        }
        if (failed) {
            Text(
                text = stringResource(R.string.dm_contact_add_failed),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onBack, enabled = !submitting, modifier = Modifier.weight(1f)) {
                Text(text = stringResource(R.string.payment_back))
            }
            Button(
                onClick = {
                    submitting = true
                    failed = false
                    scope.launch {
                        val ok = runCatching { model.onScanned(card.text.toString(), answer) }.isSuccess
                        submitting = false
                        if (ok) onAdded() else failed = true
                    }
                },
                enabled = card.text.isNotBlank() && !submitting,
                modifier = Modifier.weight(1f),
            ) {
                Text(text = stringResource(if (submitting) R.string.state_unavailable else R.string.dm_contact_add_confirm))
            }
        }
    }
}

/** The in-person card: QR first, with the bearer-card consequence stated next to it. */
@Composable
fun MyCardScreen(
    link: SensitiveText?,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = stringResource(R.string.dm_my_card_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (link == null) {
            Text(text = stringResource(R.string.state_unavailable), style = MaterialTheme.typography.bodyLarge)
        } else {
            QrImage(payload = link)
            Text(text = stringResource(R.string.dm_my_card_body), style = MaterialTheme.typography.bodyMedium)
        }
        OutlinedButton(onClick = onBack) { Text(text = stringResource(R.string.payment_back)) }
    }
}

@Composable
private fun ProvenanceChoice(
    labelId: Int,
    value: ContactAddModel.Answer,
    selected: ContactAddModel.Answer,
    onSelect: (ContactAddModel.Answer) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable { onSelect(value) },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected == value, onClick = { onSelect(value) })
        Text(text = stringResource(labelId), style = MaterialTheme.typography.bodyMedium)
    }
}

private val MessageState.labelId: Int
    get() = when (this) {
        MessageState.SENDING -> R.string.dm_state_sending
        MessageState.SENT -> R.string.dm_state_sent
        MessageState.DELIVERED -> R.string.dm_state_delivered
        MessageState.READ -> R.string.dm_state_read
        MessageState.FAILED -> R.string.dm_state_failed
        MessageState.HELD -> R.string.dm_state_held
    }

private val Int.labelId: Int
    get() = when (this) {
        0 -> R.string.dm_timer_off
        5 -> R.string.dm_timer_5m
        60 -> R.string.dm_timer_1h
        1440 -> R.string.dm_timer_1d
        43_200 -> R.string.dm_timer_30d
        else -> R.string.dm_timer_7d
    }

private fun formatMinute(minute: Long): String = java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT)
    .format(java.util.Date(minute * 60_000L))
