// Two-way reply handling for inbound WhatsApp messages — extracted so the
// rules are unit-testable without the Baileys socket.
//
// The rules:
//   1. Only authorized numbers may command the system at all — everyone else
//      is dropped before any routing (silence, not even an error reply).
//   2. A message quoting a tracked outbound message (contextInfo.stanzaId)
//      is a directed reply: decision words resolve the pending item, other
//      text is forwarded to the agent/item that sent the original.
//   3. A reaction (👍/👎) on a tracked message is a decision.
//   4. `pending` / `help` in a DM lists open items without spending an LLM.

const DECISION_WORDS_APPROVE = new Set([
  'yes', 'yeah', 'yep', 'yup', 'ya', 'yea', 'sure', 'cool', 'ok', 'okay',
  'approve', 'approved', 'lgtm', 'go', 'do it', 'send it', 'confirm',
  '👍', '✅',
]);
const DECISION_WORDS_REJECT = new Set([
  'no', 'nope', 'nah', 'reject', 'rejected', 'deny', 'denied', 'cancel',
  'stop', '👎', '❌',
]);

/** Normalize a decision text to 'approve' | 'reject' | null. */
export function classifyDecision(text) {
  const t = String(text || '').trim().toLowerCase().replace(/[.!]+$/, '');
  if (!t) return null;
  if (DECISION_WORDS_APPROVE.has(t)) return 'approve';
  if (DECISION_WORDS_REJECT.has(t)) return 'reject';
  // "approve P-103", "yes approve", "reject it" — leading decision word wins.
  const first = t.split(/\s+/)[0].replace(/[^a-z👍👎✅❌]/g, '');
  if (DECISION_WORDS_APPROVE.has(first)) return 'approve';
  if (DECISION_WORDS_REJECT.has(first)) return 'reject';
  return null;
}

/** Extract the quoted message id from a Baileys message, if any. */
export function quotedMessageId(msg) {
  const m = msg?.message || {};
  const ctx = m.extendedTextMessage?.contextInfo
    || m.imageMessage?.contextInfo
    || m.videoMessage?.contextInfo
    || m.documentMessage?.contextInfo
    || m.audioMessage?.contextInfo
    || m.stickerMessage?.contextInfo;
  return ctx?.stanzaId || null;
}

/**
 * Extract an inbound reaction: { targetId, emoji } or null.
 * Baileys delivers reactions as a message.reactionMessage whose `key` is the
 * message being reacted to and `text` is the emoji.
 */
export function extractReaction(msg) {
  const r = msg?.message?.reactionMessage;
  if (!r) return null;
  const targetId = r.key?.id;
  const emoji = String(r.text || '').trim();
  if (!targetId || !emoji) return null;
  return { targetId, emoji };
}

/** Map a reaction emoji to a decision, or null for non-decision reactions. */
export function reactionDecision(emoji) {
  if (['👍', '❤️', '✅', '👌', '🎉'].includes(emoji)) return 'approve';
  if (['👎', '❌', '🚫'].includes(emoji)) return 'reject';
  return null;
}

/**
 * The JID to reply to. Groups reply to the group; DMs reply to the sender.
 * Critical: WhatsApp now addresses DM senders as privacy @lid JIDs. Appending
 * '@s.whatsapp.net' to lid digits builds a JID that does not exist — the reply
 * is sent but never delivered. Resolve lid→phone via the learned map when
 * possible; otherwise keep the original @lid JID (Baileys routes it).
 */
export function dmReplyJid(senderJid, remoteJid, isGroup, lidToPhone) {
  if (isGroup) return remoteJid;
  const jid = String(senderJid || '');
  if (jid.endsWith('@lid')) {
    const digits = jid.replace(/@.*$/, '').replace(/\D/g, '');
    const pn = lidToPhone?.get?.(digits);
    return pn ? `${pn}@s.whatsapp.net` : jid;
  }
  return jid.replace(/@.*$/, '') + '@s.whatsapp.net';
}

/** Commands answered locally by the gateway (no LLM). */
export function localCommand(text) {
  const t = String(text || '').trim().toLowerCase();
  if (t === 'pending' || t === 'approvals' || t === 'open') return 'pending';
  if (t === 'help' || t === 'commands' || t === '?') return 'help';
  return null;
}
