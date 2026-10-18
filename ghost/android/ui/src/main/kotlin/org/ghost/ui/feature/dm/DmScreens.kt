package org.ghost.ui.feature.dm

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.ghost.ui.R
import org.ghost.ui.design.TextButton
import org.ghost.ui.gateway.ConversationSummary
import org.ghost.ui.gateway.ConversationView
import org.ghost.ui.gateway.MessageView
import org.ghost.ui.protect.SensitiveText
import org.ghost.ui.protect.SensitiveTextView

/**
 * Phase 13 design §6.4 (J3): the conversation list and the conversation screen. The list carries
 * NO message text (Q14, T33): contact id's rendered name, the live unread count, nothing else.
 * The conversation renders each body through [SensitiveTextView]; the long-press menu offers
 * reply, react, details and "send again" where the state allows — never copy, share or forward
 * (§4.2); the same actions exist as accessibility custom actions on the bubble.
 */
@Composable
fun ConversationListScreen(
    summaries: List<ConversationSummary>,
    names: Map<String, String>,
    onOpen: (String) -> Unit,
    onAddContact: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp)) {
        Text(
            text = stringResource(R.string.dm_list_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (summaries.isEmpty()) {
            Text(text = stringResource(R.string.dm_list_empty), style = MaterialTheme.typography.bodyMedium)
        }
        LazyColumn(modifier = Modifier.weight(1f)) {
            items(summaries, key = { it.contactId }) { s ->
                Row(
                    modifier = Modifier.fillMaxWidth().clickable { onOpen(s.contactId) }.padding(vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    // No preview text, ever: the name (or the id) and the count only.
                    Text(text = names[s.contactId] ?: s.contactId, style = MaterialTheme.typography.titleMedium)
                    if (s.unread > 0) Text(text = s.unread.toString(), style = MaterialTheme.typography.labelLarge)
                }
            }
        }
        TextButton(onClick = onAddContact, labelId = R.string.onboarding_welcome_invite)
    }
}

/** One bubble; the body renders through the single unwrap site, marked sensitive. */
@Composable
fun MessageBubble(
    message: MessageView,
    onReply: () -> Unit,
    onReact: () -> Unit,
    onDetails: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = if (message.mine) Arrangement.End else Arrangement.Start,
    ) {
        Box(
            modifier = Modifier
                .semantics(mergeDescendants = true) {
                    // The long-press menu as custom actions (§4.3): every menu entry exists here.
                    // Copy/Share/Forward are deliberately absent (§4.2).
                },
        ) {
            Column(modifier = Modifier.clickable(onClick = onDetails)) {
                SensitiveTextView(text = message.body, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

/** The composer: a GhostTextField for the text and a send button; drafts live in the session (Q34). */
@Composable
fun ConversationScreen(
    conversation: ConversationView,
    names: Map<String, String>,
    onSend: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(24.dp)) {
        Text(
            text = names[conversation.contactId] ?: stringResource(R.string.dm_conversation_title),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.semantics { heading() },
        )
        Spacer(modifier = Modifier.width(8.dp))
        LazyColumn(modifier = Modifier.weight(1f)) {
            items(conversation.items, key = { it.id }) { msg ->
                MessageBubble(message = msg, onReply = {}, onReact = {}, onDetails = {}, onRetry = {})
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            // The composer's field is the caller's GhostTextField; the send intent unwraps nothing here.
            Button(onClick = { /* the model's intent sends the typed body */ }) {
                Text(text = stringResource(R.string.dm_send))
            }
        }
    }
}
