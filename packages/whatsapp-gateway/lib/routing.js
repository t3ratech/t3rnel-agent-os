// Routing decisions for inbound WhatsApp messages, extracted so they are
// unit-testable without booting the Baileys socket or the HTTP listener.
//
// The rules, in order:
//   1. A message starting with the prefix (@t3rnel) is addressed to the
//      orchestrator — in groups AND DMs, from anyone.
//   2. In a DM, an allow-listed sender is always addressing the system — a
//      private chat with the linked number is the command channel, so
//      instructions go to the orchestrator with no prefix required.
//   3. Everything else goes to the default assistant — ambient group chatter
//      must not wake the swarm.
//   4. A message that is only links is owned by the video-watch worker
//      (isLinkOnly); forwarding a bare URL would spend an agent turn on a
//      message the link pipeline already answers.

export function daemonUrl(env = process.env) {
  return (env.T3RNEL_URL || env.T3RNEL_API || 'http://127.0.0.1:4200').replace(/\/+$/, '');
}

const URL_RE = /https?:\/\/[^\s<>"')\]]+/g;

export function isLinkOnly(text) {
  return (text.match(URL_RE) || []).length > 0
    && text.replace(URL_RE, '').trim().length < 2;
}

export function routeMessage(text, { isGroup = false, isOperator = false, prefix = '@t3rnel', orchestratorAgent = 't3rnel', defaultAgent = 'assistant' } = {}) {
  const trimmed = text.trimStart();
  if (trimmed.toLowerCase().startsWith(prefix.toLowerCase())) {
    return {
      agent: orchestratorAgent,
      text: trimmed.slice(prefix.length).trim() || trimmed,
      addressed: true,
    };
  }
  if (!isGroup && isOperator) {
    return { agent: orchestratorAgent, text, addressed: true };
  }
  return { agent: defaultAgent, text, addressed: false };
}

// Sitesmith operator commands, sent by an allow-listed sender in a DM:
//   hold <lead>              stop everything queued for that lead (pitch and replies)
//   send <lead>              release queued replies now (a pitch still waits its 16 hours)
//   sitesmith status [lead]  pipeline summary, answered by the next Sitesmith tick
// hold/send only count when <lead> is a real lead (`isLead`), so ordinary chat
// such as "hold on" still reaches the orchestrator. Commands are written to
// $SITESMITH_HOME/commands/ for the tick, never forwarded to an agent.
const LEAD_RE = /^\s*(hold|send)\s+([a-z0-9][a-z0-9-]{1,62})\s*$/i;
const STATUS_RE = /^\s*sitesmith\s+status(?:\s+([a-z0-9][a-z0-9-]{1,62}))?\s*$/i;

export function sitesmithCommand(text, isLead = () => false) {
  const t = String(text || '');
  const s = STATUS_RE.exec(t);
  if (s) return { verb: 'status', slug: s[1] ? s[1].toLowerCase() : null };
  const m = LEAD_RE.exec(t);
  if (!m || !isLead(m[2].toLowerCase())) return null;
  return { verb: m[1].toLowerCase(), slug: m[2].toLowerCase() };
}
