#!/usr/bin/env node

import http from 'node:http';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion, downloadMediaMessage } from '@whiskeysockets/baileys';
import QRCode from 'qrcode';
import pino from 'pino';
import { daemonUrl, isLinkOnly, routeMessage, sitesmithCommand } from './lib/routing.js';
import { classifyDecision, quotedMessageId, extractReaction, reactionDecision, localCommand, dmReplyJid } from './lib/replies.js';
import { guardConsole } from './lib/console-guard.js';

// libsignal prints session objects (private keys included) through console; drop them before they reach the journal.
guardConsole();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------------------------
// Config from environment
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.WHATSAPP_GATEWAY_PORT || '8765', 10);
// Plain HTTP, bound to loopback only.
//
// This served HTTPS from `dev-cert.pem`/`dev-key.pem`, but nothing ever
// created those files, so the gateway crashed on startup before it could
// listen — in every daemon home, every time. The daemon also probes
// `http://127.0.0.1:<port>/health`, so even a valid certificate would have
// failed the health check against an HTTPS listener. TLS buys nothing on a
// socket that never leaves the host.
// T3RNEL_URL names the daemon's HTTP API; T3RNEL_API (the name the rest of
// the toolchain uses, e.g. .env) is accepted as an alias so a deployment that
// sets one doesn't strand the gateway on a dead default port.
const T3RNEL_URL = daemonUrl();
const DEFAULT_AGENT = process.env.T3RNEL_DEFAULT_AGENT || 'assistant';

// Messages addressed to the system go to the orchestrator, which can reach every
// team; anything else keeps going to the ordinary assistant. Without a prefix
// every passing remark in a group would be work for the orchestrator, and the
// operator could not tell which messages the system was actually acting on.
// In a DM the allow-listed operator is by definition addressing the system —
// the prefix is only required in groups.
const ORCHESTRATOR_PREFIX = (process.env.T3RNEL_WHATSAPP_PREFIX || '@t3rnel').toLowerCase();
// Sitesmith pipeline state (lead directories and the operator command queue).
const SITESMITH_HOME = process.env.SITESMITH_HOME || path.join(process.env.HOME || '', '.t3rnel', 'sitesmith');
const ORCHESTRATOR_AGENT = process.env.T3RNEL_ORCHESTRATOR_AGENT || 't3rnel';

// Where outbound notifications go. Without it the system has somewhere to send
// but no-one to send to, so notify reports that rather than silently dropping.
const OWNER_JID = (process.env.T3RNEL_WHATSAPP_OWNER || '').trim();

// Command authority: only these numbers may drive the system over WhatsApp —
// messages, links, statuses, approvals, everything. Everyone else is dropped
// silently before any routing. The master number is fixed; the linked number
// (the account the gateway itself speaks as) is always allowed; extra numbers
// come from T3RNEL_WHATSAPP_ALLOWED (comma-separated, digits only).
const MASTER_NUMBER = (process.env.T3RNEL_WHATSAPP_MASTER || '263785107830').replace(/\D/g, '');
const EXTRA_ALLOWED = (process.env.T3RNEL_WHATSAPP_ALLOWED || '263773412752,263711715703')
  .split(/[;,]/).map((s) => s.replace(/\D/g, '')).filter(Boolean);

/** Digits-only phone number for a JID ('263…@s.whatsapp.net' or '…@lid' resolved). */
function senderDigits(senderJid) {
  return String(senderJid || '').replace(/@.*$/, '').replace(/\D/g, '');
}

/** The phone number this gateway account is linked as (from creds.me.id). */
function linkedNumber() {
  try {
    const creds = JSON.parse(fs.readFileSync(path.join(__dirname, 'auth_store', 'creds.json'), 'utf8'));
    return String(creds?.me?.id || '').split(':')[0].replace(/\D/g, '');
  } catch { return ''; }
}

/**
 * May this sender command the system at all? Master number, the linked
 * number, or an explicit extra. Lids resolve through the learned map first.
 */
function isAuthorizedSender(senderJid) {
  const digits = senderDigits(senderJid);
  if (!digits) return false;
  if (digits === MASTER_NUMBER) return true;
  if (digits === linkedNumber()) return true;
  if (EXTRA_ALLOWED.includes(digits)) return true;
  if (senderJid.endsWith('@lid')) {
    const pn = lidToPhone.get(digits);
    return Boolean(pn && (pn === MASTER_NUMBER || pn === linkedNumber() || EXTRA_ALLOWED.includes(pn)));
  }
  return false;
}

// Video-watch worker: links sent by allow-listed senders get captured,
// analyzed, researched and reported back. Empty allow-list disables the hook.
const VIDEO_WATCH_URL = (process.env.VIDEO_WATCH_URL || 'http://127.0.0.1:3011').replace(/\/+$/, '');
const VIDEO_WATCH_FROM = (process.env.VIDEO_WATCH_FROM || '')
  .split(/[;,]/)
  .map((s) => s.trim().replace(/\D/g, ''))
  .filter(Boolean);
// Any http(s) link from an allowed sender is a link-watch job — the worker's
// handler registry decides whether it is video, text, a repo, or something new.
const VIDEO_WATCH_URL_RE = /https?:\/\/[^\s<>"')\]]+/g;

// WhatsApp migrated DM sender addressing to privacy lids: the same account
// that used to arrive as 263785107830@s.whatsapp.net can arrive as
// <lid>@lid. The allow-list holds phone numbers; lids resolve through an
// explicit env map plus pairs learned from contact syncs, so a new device
// surfaces as "unknown lid" in the log rather than silently failing open.
const LID_MAP_PATH = path.join(__dirname, 'auth_store', 'lid-map.json');
const lidToPhone = new Map(
  (process.env.VIDEO_WATCH_LID_MAP || '')
    .split(/[;,]/)
    .map((pair) => pair.split(':').map((s) => s.trim().replace(/\D/g, '')))
    .filter(([lid, pn]) => lid && pn),
);
try {
  const saved = JSON.parse(fs.readFileSync(LID_MAP_PATH, 'utf8'));
  for (const [lid, pn] of Object.entries(saved)) {
    if (!lidToPhone.has(lid)) lidToPhone.set(lid, String(pn).replace(/\D/g, ''));
  }
} catch { /* no learned map yet — env map may still carry the aliases */ }

function persistLidMap() {
  try {
    fs.writeFileSync(LID_MAP_PATH, JSON.stringify(Object.fromEntries(lidToPhone), null, 2));
  } catch (err) {
    console.error('[gateway] lid map persist failed:', err.message);
  }
}

/** Record a lid↔phone pair learned from contacts/history sync. */
function learnLidMapping(lid, phoneNumber) {
  const l = String(lid || '').replace(/\D/g, '');
  const p = String(phoneNumber || '').replace(/\D/g, '');
  if (l && p && lidToPhone.get(l) !== p) {
    lidToPhone.set(l, p);
    persistLidMap();
    console.log(`[gateway] learned lid mapping: ${l} -> ${p}`);
  }
}

/**
 * Resolve a sender JID to an allow-listed phone number, or null when the
 * sender is not on the list. Phone JIDs match directly; lid JIDs resolve
 * through the learned/env map.
 */
function resolveAllowedSender(senderJid) {
  const digits = senderJid.replace(/@.*$/, '').replace(/\D/g, '');
  if (!senderJid.endsWith('@lid') && VIDEO_WATCH_FROM.includes(digits)) return digits;
  if (senderJid.endsWith('@lid')) {
    const pn = lidToPhone.get(digits);
    if (pn && VIDEO_WATCH_FROM.includes(pn)) return pn;
    console.log(`[gateway] video-watch: message from unknown lid ${digits} — ignored (add to VIDEO_WATCH_LID_MAP if trusted)`);
  }
  return null;
}

/**
 * Hand a message's video links to the video-watch worker when the sender is
 * allowed. Fire-and-forget: a dead worker must not stall message forwarding,
 * and the worker reports its own failures back over WhatsApp.
 */
function maybeEnqueueVideoJobs(text, senderJid) {
  if (!VIDEO_WATCH_FROM.length || !text) return;
  const senderDigits = resolveAllowedSender(senderJid);
  if (!senderDigits) return;
  const urls = text.match(VIDEO_WATCH_URL_RE);
  if (!urls || !urls.length) return;
  const payload = JSON.stringify({ text, from: senderDigits, senderJid });
  const target = new URL(`${VIDEO_WATCH_URL}/enqueue`);
  const req = http.request(
    {
      hostname: target.hostname,
      port: target.port,
      path: target.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
      timeout: 5000,
    },
    (res) => {
      res.resume();
      console.log(`[gateway] video-watch enqueue for ${urls.length} link(s): HTTP ${res.statusCode}`);
    },
  );
  req.on('error', (err) => console.error(`[gateway] video-watch enqueue failed: ${err.message}`));
  req.on('timeout', () => req.destroy());
  req.write(payload);
  req.end();
}

/**
 * Route a message by whether it addresses the system — the rules live in
 * lib/routing.js so they are testable; this binds the process's config.
 * An allow-listed sender in a DM is always addressing the system — a private
 * chat with the linked number is the command channel, so instructions go to
 * the orchestrator without needing the prefix. Groups still require it, so
 * ambient chatter doesn't wake the swarm.
 */
function route(text, { isGroup, senderJid }) {
  return routeMessage(text, {
    isGroup,
    isOperator: Boolean(senderJid && resolveAllowedSender(senderJid)),
    prefix: ORCHESTRATOR_PREFIX,
    orchestratorAgent: ORCHESTRATOR_AGENT,
    defaultAgent: DEFAULT_AGENT,
  });
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let sock = null;          // Baileys socket
let sessionId = '';       // current session identifier
let qrDataUrl = '';       // latest QR code as data:image/png;base64,...
let connStatus = 'disconnected'; // disconnected | qr_ready | connected
let qrExpired = false;
let statusMessage = 'Not started';
let reconnectAttempt = 0; // exponential backoff counter
let pendingReconnect = null; // scheduled reconnect timer, if any
let connectGeneration = 0; // bumps on every start; stale sockets bail out
const MAX_RECONNECT_DELAY = 60_000; // cap at 60s
// Bounded store of messages WE sent, keyed by message id — feeds getMessage
// so a recipient's retry request can re-encrypt instead of stalling on
// "waiting for this message".
const recentSent = new Map();

// ---------------------------------------------------------------------------
// Outbound message registry — every message we send is recorded by its Baileys
// message id so a quoted reply or reaction can be routed back to whatever
// produced it (a pending approval, an agent, a job). Persisted to disk so the
// mapping survives gateway restarts; bounded ring.
// ---------------------------------------------------------------------------
const OUTBOUND_MAP_PATH = path.join(__dirname, 'auth_store', 'outbound-map.json');
const outboundMap = new Map(); // msgId -> { kind, ref, agent, summary, ledger_id, ts }
try {
  const saved = JSON.parse(fs.readFileSync(OUTBOUND_MAP_PATH, 'utf8'));
  for (const [id, rec] of Object.entries(saved)) outboundMap.set(id, rec);
} catch { /* no registry yet */ }

function persistOutboundMap() {
  try {
    // Keep the file bounded: drop oldest entries beyond 2000.
    if (outboundMap.size > 2000) {
      const oldest = [...outboundMap.entries()].sort((a, b) => a[1].ts - b[1].ts).slice(0, outboundMap.size - 2000);
      for (const [id] of oldest) outboundMap.delete(id);
    }
    fs.writeFileSync(OUTBOUND_MAP_PATH, JSON.stringify(Object.fromEntries(outboundMap)));
  } catch (err) {
    console.error('[gateway] outbound map persist failed:', err.message);
  }
}

/** Record an outbound message id → routing metadata. */
function registerOutbound(msgId, meta = {}) {
  if (!msgId) return;
  outboundMap.set(msgId, { ...meta, ts: Date.now() });
  persistOutboundMap();
}

/** Look up what an inbound quoted/reaction target refers to. */
function lookupOutbound(msgId) {
  return msgId ? outboundMap.get(msgId) || null : null;
}

// ---------------------------------------------------------------------------
// Inbound event buffer — the conversation service's channel adapter polls
// GET /inbound/events?since=<seq> for normalized inbound messages
// (docs/sections/18 §3). Bounded ring; `seq` is seeded from the clock at
// startup so it stays monotonic across gateway restarts (a restarted
// gateway simply has a fresh, higher seq space — the adapter's `since`
// cursor keeps working).
// ---------------------------------------------------------------------------
const INBOUND_BUFFER_MAX = 500;
const inboundEvents = [];
let inboundSeq = Date.now();

/** Record one normalized inbound message for adapter polling. */
function recordInboundEvent(evt) {
  inboundSeq += 1;
  inboundEvents.push({ seq: inboundSeq, ts: Math.floor(Date.now() / 1000), ...evt });
  if (inboundEvents.length > INBOUND_BUFFER_MAX) {
    inboundEvents.splice(0, inboundEvents.length - INBOUND_BUFFER_MAX);
  }
}

// ---------------------------------------------------------------------------
// Inbound media store — Baileys media is end-to-end encrypted and can only be
// downloaded against the original message object, so authorized inbound
// media messages are kept in a bounded map keyed by message id. The
// conversation adapter resolves an AttachmentRef (the message id) via
// GET /media/:id.
// ---------------------------------------------------------------------------
const MEDIA_STORE_MAX = 300;
const recentMedia = new Map(); // msg.key.id -> { msg, mime, fileName }

/** Extract media metadata (unwrapping view-once/ephemeral envelopes). */
function mediaInfoOf(msg) {
  const m = msg?.message;
  const inner = m?.ephemeralMessage?.message
    || m?.viewOnceMessage?.message
    || m?.viewOnceMessageV2?.message
    || m;
  for (const k of ['imageMessage', 'audioMessage', 'videoMessage', 'documentMessage', 'stickerMessage']) {
    const mm = inner?.[k];
    if (mm) {
      return {
        mime: mm.mimetype || 'application/octet-stream',
        fileName: mm.fileName || null,
      };
    }
  }
  return null;
}

/** Keep an authorized inbound media message retrievable via /media/:id. */
function rememberMedia(msg) {
  const id = msg?.key?.id;
  if (!id) return;
  const info = mediaInfoOf(msg);
  if (!info) return;
  recentMedia.set(id, { msg, mime: info.mime, fileName: info.fileName });
  if (recentMedia.size > MEDIA_STORE_MAX) {
    recentMedia.delete(recentMedia.keys().next().value);
  }
}

// ---------------------------------------------------------------------------
// Baileys connection
// ---------------------------------------------------------------------------
async function startConnection() {
  // Only one socket may hold the linked-device session at a time. A manual
  // /login/start racing a pending reconnect timer (or a live socket) leaves
  // two sessions with the same credentials — WhatsApp then alternately kills
  // each with stream conflict 440 "replaced", which is the flapping loop.
  const generation = ++connectGeneration;
  if (pendingReconnect) {
    clearTimeout(pendingReconnect);
    pendingReconnect = null;
  }
  if (sock) {
    try { sock.ev.removeAllListeners(); } catch { /* listener teardown best-effort */ }
    try { sock.end(undefined); } catch { /* stale socket close best-effort */ }
    sock = null;
  }

  const logger = pino({ level: 'warn' });
  const authDir = path.join(__dirname, 'auth_store');

  const { state, saveCreds } = await useMultiFileAuthState(authDir);
  const { version } = await fetchLatestBaileysVersion();

  sessionId = randomUUID();
  qrDataUrl = '';
  qrExpired = false;
  connStatus = 'disconnected';
  statusMessage = 'Connecting...';

  sock = makeWASocket({
    version,
    auth: state,
    logger,
    browser: ['T3rnel', 'Desktop', '1.0.0'],
    // Companion-device hygiene — the documented causes of the phone-side
    // "Waiting for this message" state: presence assertion, history storms
    // and duplicate processing each nudge the account's key state.
    // NOTE: must NOT blanket-disable history sync — Baileys needs the initial
    // LID-mapping app-state, and blocking it causes session errors.
    markOnlineOnConnect: false,
    syncFullHistory: false,
    generateHighQualityLinkPreview: false,
    msgRetryCounterCache: new Map(),
    // rc14 retry-path caches: recent-message cache + placeholder resend both
    // target the same "waiting for this message" placeholder family.
    enableRecentMessageCache: true,
    placeholderResendCache: new Map(),
    // Message-retry requests resolve against our recent-send store — Baileys
    // documents getMessage as the fix for "waiting for this message" on the
    // recipient's side when our outbound send needs re-encrypting.
    getMessage: async (key) => recentSent.get(key?.id)?.message || undefined,
  });

  // Save credentials whenever they update
  sock.ev.on('creds.update', saveCreds);

  // Learn lid↔phone pairs whenever contact data syncs — contact records carry
  // both addressing modes, and the video-watch allow-list is phone-numbered.
  const learnFromContacts = (contacts) => {
    for (const c of contacts || []) {
      if (c?.lid && c?.id) learnLidMapping(c.lid, c.id);
    }
  };
  sock.ev.on('contacts.upsert', learnFromContacts);
  sock.ev.on('contacts.update', learnFromContacts);
  sock.ev.on('messaging-history.set', ({ contacts }) => learnFromContacts(contacts));

  // Connection state changes (QR code, connected, disconnected)
  sock.ev.on('connection.update', async (update) => {
    // A newer startConnection call owns the session now — this socket is
    // already torn down; its events must not touch shared state.
    if (generation !== connectGeneration) return;
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      // New QR code generated — convert to data URL
      try {
        qrDataUrl = await QRCode.toDataURL(qr, { width: 256, margin: 2 });
        connStatus = 'qr_ready';
        qrExpired = false;
        statusMessage = 'Scan this QR code with WhatsApp → Linked Devices';
        console.log('[gateway] QR code ready — waiting for scan');
      } catch (err) {
        console.error('[gateway] QR generation failed:', err.message);
      }
    }

    if (connection === 'close') {
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const reason = lastDisconnect?.error?.output?.payload?.message || 'unknown';
      console.log(`[gateway] Connection closed: ${reason} (${statusCode})`);

      if (statusCode === DisconnectReason.loggedOut) {
        // User logged out from phone — clear auth and stop (truly non-recoverable)
        connStatus = 'disconnected';
        statusMessage = 'Logged out. Generate a new QR code to reconnect.';
        qrDataUrl = '';
        sock = null;
        reconnectAttempt = 0;
        // Remove auth store so next connect gets a fresh QR
        const authPath = path.join(__dirname, 'auth_store');
        if (fs.existsSync(authPath)) {
          fs.rmSync(authPath, { recursive: true, force: true });
        }
      } else {
        // All other disconnect reasons are recoverable — reconnect with backoff
        // Covers: restartRequired(515), timedOut(408), connectionClosed(428),
        // connectionLost(408), connectionReplaced(440), badSession(500), etc.
        reconnectAttempt++;
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempt - 1), MAX_RECONNECT_DELAY);
        console.log(`[gateway] Reconnecting in ${delay}ms (attempt ${reconnectAttempt})...`);
        statusMessage = `Reconnecting (attempt ${reconnectAttempt})...`;
        connStatus = 'disconnected';
        pendingReconnect = setTimeout(() => {
          pendingReconnect = null;
          startConnection();
        }, delay);
      }
    }

    if (connection === 'open') {
      connStatus = 'connected';
      qrExpired = false;
      qrDataUrl = '';
      reconnectAttempt = 0;
      statusMessage = 'Connected to WhatsApp';
      console.log('[gateway] Connected to WhatsApp!');
    }
  });

  // Incoming messages → forward to T3rnel. Dedupe on message id: the relay
  // re-delivers `notify` events around retries, and double-processing both
  // wastes agent turns and double-acks the sender's session.
  const seen = new Map(); // key.id -> ts (bounded ring)
  sock.ev.on('messages.upsert', async ({ messages, type }) => {
    if (type !== 'notify') return;

    for (const msg of messages) {
      const id = msg?.key?.id;
      if (id) {
        if (seen.has(id)) continue;
        seen.set(id, Date.now());
        if (seen.size > 2000) {
          const oldest = seen.keys().next().value;
          seen.delete(oldest);
        }
      }
      // Skip messages from self and status broadcasts
      if (msg.key.fromMe) continue;
      if (msg.key.remoteJid === 'status@broadcast') continue;

      const remoteJid = msg.key.remoteJid || '';
      const isGroup = remoteJid.endsWith('@g.us');

      let text = msg.message?.conversation
        || msg.message?.extendedTextMessage?.text
        || msg.message?.imageMessage?.caption
        || '';

      // Detect media type if no text
      if (!text) {
        const m = msg.message;
        if (m?.imageMessage) text = '[Image received]' + (m.imageMessage.caption ? ': ' + m.imageMessage.caption : '');
        else if (m?.audioMessage) text = '[Voice note received]';
        else if (m?.videoMessage) text = '[Video received]' + (m.videoMessage.caption ? ': ' + m.videoMessage.caption : '');
        else if (m?.documentMessage) text = '[Document received: ' + (m.documentMessage.fileName || 'file') + ']';
        else if (m?.stickerMessage) text = '[Sticker received]';
        else continue; // Only skip truly empty messages
      }

      // For groups: real sender is in participant; for DMs: it's remoteJid
      const senderJid = isGroup ? (msg.key.participant || '') : remoteJid;
      const phone = '+' + senderDigits(senderJid);

      // Command authority gate — ONLY the master number, the linked number and
      // the explicit whitelist may drive the system. Everyone else gets total
      // silence: no reply, no link-watch, no agent turn, nothing logged beyond
      // this line.
      if (!isAuthorizedSender(senderJid)) {
        continue;
      }
      const pushName = msg.pushName || phone;
      const replyJid = dmReplyJid(senderJid, remoteJid, isGroup, lidToPhone);

      // Media: keep the message retrievable via GET /media/:id and surface
      // its MIME type on the inbound event so the adapter can type the
      // AttachmentRef without a second round-trip.
      const mediaInfo = mediaInfoOf(msg);
      if (mediaInfo) rememberMedia(msg);

      // Buffer for the conversation-service channel adapter (18 §3). Every
      // authorized inbound message is recorded — including link-only and
      // sitesmith-command texts — so threads/approvals see the full stream.
      recordInboundEvent({
        id: msg.key?.id || null,
        chat: remoteJid,
        sender: senderJid,
        phone,
        push_name: pushName,
        media_mime: mediaInfo ? mediaInfo.mime : null,
        text,
        is_group: isGroup,
        ts: Number(msg.messageTimestamp) || Math.floor(Date.now() / 1000),
      });

      // Reactions on tracked outbound messages are decisions (👍 approve,
      // 👎 reject). Handled before text extraction — reactions carry no text.
      const reaction = extractReaction(msg);
      if (reaction) {
        const decision = reactionDecision(reaction.emoji);
        const rec = lookupOutbound(reaction.targetId);
        if (decision && rec) {
          console.log(`[gateway] reaction ${reaction.emoji} on ${reaction.targetId} -> ${decision} (${rec.kind}:${rec.ledger_id || rec.ref || '-'})`);
          await resolveDirected(rec, decision, `reaction ${reaction.emoji}`, replyJid);
        }
        continue;
      }

      // Detect media type if no text
      if (!text) {
        const m = msg.message;
        if (m?.imageMessage) text = '[Image received]' + (m.imageMessage.caption ? ': ' + m.imageMessage.caption : '');
        else if (m?.audioMessage) text = '[Voice note received]';
        else if (m?.videoMessage) text = '[Video received]' + (m.videoMessage.caption ? ': ' + m.videoMessage.caption : '');
        else if (m?.documentMessage) text = '[Document received: ' + (m.documentMessage.fileName || 'file') + ']';
        else if (m?.stickerMessage) text = '[Sticker received]';
        else continue; // Only skip truly empty messages
      }

      // Video links from authorized senders get watched/analyzed asynchronously by
      // the video-watch worker — independent of the daemon-forward path.
      const linkOnly = VIDEO_WATCH_FROM.length
        && Boolean(resolveAllowedSender(senderJid)) && isLinkOnly(text);
      maybeEnqueueVideoJobs(text, senderJid);

      // Directed reply: the message quotes a tracked outbound message.
      // Decision words resolve the pending item; anything else is forwarded
      // to the agent/item that sent the original.
      const quotedId = quotedMessageId(msg);
      const quotedRec = quotedId ? lookupOutbound(quotedId) : null;
      if (quotedRec) {
        const decision = classifyDecision(text);
        if (decision) {
          console.log(`[gateway] quoted ${decision} on ${quotedId} -> ${quotedRec.kind}:${quotedRec.ledger_id || quotedRec.ref || '-'}`);
          await resolveDirected(quotedRec, decision, text, replyJid);
          continue;
        }
        console.log(`[gateway] directed reply to ${quotedRec.kind}:${quotedRec.ledger_id || quotedRec.ref || '-'} from ${pushName}`);
        await forwardDirected(quotedRec, text, phone, pushName, replyJid);
        continue;
      }

      // Local commands — answered by the gateway/daemon directly, no LLM.
      const cmd = !isGroup ? localCommand(text) : null;
      if (cmd === 'pending') {
        try { await sendAndRemember(replyJid, { text: await pendingListReply() }, { kind: 'ack' }); }
        catch (err) { console.error('[gateway] pending reply failed:', err.message); }
        continue;
      }
      if (cmd === 'help') {
        await sendAndRemember(replyJid, {
          text: 'Commands: pending · APPROVE/REJECT <id> · quote a notification and reply yes/no · @t3rnel <task> · send links to watch them',
        }, { kind: 'ack' });
        continue;
      }

      const metadata = {
        channel: 'whatsapp',
        sender: phone,
        sender_name: pushName,
      };
      if (isGroup) {
        metadata.group_jid = remoteJid;
        metadata.is_group = true;
        console.log(`[gateway] Group msg from ${pushName} (${phone}) in ${remoteJid}: ${text.substring(0, 80)}`);
      } else {
        console.log(`[gateway] Incoming from ${pushName} (${phone}): ${text.substring(0, 80)}`);
      }

      // Forward to T3rnel agent — but a message that is only links is already
      // owned by the video-watch worker (it replies itself when the analysis
      // lands); forwarding it too would just spend an LLM call on a bare URL.
      if (linkOnly) continue;
      // Sitesmith operator commands (hold/send/status) go to the pipeline's queue, not an agent.
      const ssCmd = !isGroup && isAuthorizedSender(senderJid)
        ? sitesmithCommand(text, (slug) => fs.existsSync(path.join(SITESMITH_HOME, 'leads', slug, 'lead.json')))
        : null;
      if (ssCmd) {
        try {
          const dir = path.join(SITESMITH_HOME, 'commands');
          fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(path.join(dir, `${Date.now()}-${randomUUID().slice(0, 8)}.json`), JSON.stringify({ ...ssCmd, from: phone, at: new Date().toISOString() }));
          await sendAndRemember(senderJid.replace(/@.*$/, '') + '@s.whatsapp.net', { text: `Sitesmith: "${ssCmd.verb}${ssCmd.slug ? ` ${ssCmd.slug}` : ''}" received; it takes effect on the next tick (within 15 minutes).` });
        } catch (err) {
          console.error('[gateway] sitesmith command failed:', err.message);
        }
        continue;
      }
      const routed = route(text, { isGroup, senderJid });
      metadata.addressed_to_system = routed.addressed;
      if (routed.addressed) {
        console.log(`[gateway] Addressed to system -> ${routed.agent}`);
      }
      try {
        const response = await forwardToT3rnel(
          routed.text, phone, pushName, metadata, routed.agent);
        if (response && sock) {
          // Reply in the same context: group → group, DM → DM. Register the
          // outbound id so a quoted reply routes back to this agent.
          await sendAndRemember(replyJid, { text: response }, {
            kind: 'agent', agent: routed.agent, summary: text.substring(0, 200),
          });
          console.log(`[gateway] Replied to ${pushName}${isGroup ? ' in group ' + remoteJid : ''}`);
        }
      } catch (err) {
        console.error(`[gateway] Forward/reply failed:`, err.message);
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Daorchestrator API helper — pending-actions ledger + approvals live on the
// daemon; the gateway is a thin client.
// ---------------------------------------------------------------------------
function daemonCall(method, apiPath, body) {
  return new Promise((resolve) => {
    const payload = body ? JSON.stringify(body) : null;
    const url = new URL(`${T3RNEL_URL}${apiPath}`);
    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || 4200,
        path: url.pathname + url.search,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        },
        timeout: 15_000,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try { resolve({ ok: res.statusCode < 400, status: res.statusCode, data: JSON.parse(data) }); }
          catch { resolve({ ok: res.statusCode < 400, status: res.statusCode, data }); }
        });
      },
    );
    req.on('error', () => resolve({ ok: false, status: 0, data: null }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 0, data: null }); });
    if (payload) req.write(payload);
    req.end();
  });
}

/**
 * Resolve a directed decision (quoted reply or reaction) against the pending
 * ledger / approvals API, then confirm on WhatsApp. Returns true when the
 * daemon accepted the decision.
 */
async function resolveDirected(rec, decision, note, replyJid) {
  const verb = decision === 'approve' ? 'approved' : 'rejected';
  let result;
  if (rec.ledger_id) {
    result = await daemonCall('POST', `/api/pending-actions/${encodeURIComponent(rec.ledger_id)}/resolve`, {
      decision, note: note || '', via: 'whatsapp',
    });
  } else if (rec.kind === 'approval' && rec.ref) {
    result = await daemonCall('POST', `/api/approvals/${encodeURIComponent(rec.ref)}/${decision === 'approve' ? 'approve' : 'reject'}`, {});
  } else {
    result = { ok: false, status: 0, data: null };
  }
  const label = rec.summary || rec.ledger_id || rec.ref || 'item';
  const text = result.ok
    ? `✅ ${verb === 'approved' ? 'Approved' : 'Rejected'}: ${String(label).slice(0, 120)}`
    : `⚠️ Could not record ${decision} for "${String(label).slice(0, 80)}" — it may already be resolved.`;
  try {
    await sendAndRemember(replyJid, { text }, { kind: 'ack', ref: rec.ledger_id || rec.ref });
  } catch (err) {
    console.error('[gateway] decision ack failed:', err.message);
  }
  return result.ok;
}

/**
 * A quoted reply that isn't a decision word is a message *to* whatever sent
 * the original — forward it to that agent with the original as context.
 */
async function forwardDirected(rec, text, phone, pushName, replyJid) {
  const agent = rec.agent || ORCHESTRATOR_AGENT;
  const context = `[Reply to your earlier WhatsApp message: "${String(rec.summary || '').slice(0, 200)}"]\n\n${text}`;
  const metadata = { channel: 'whatsapp', sender: phone, sender_name: pushName, reply_to: rec.ref || rec.ledger_id || null };
  try {
    const response = await forwardToT3rnel(context, phone, pushName, metadata, agent);
    if (response && sock) {
      await sendAndRemember(replyJid, { text: response }, { kind: 'agent', agent, ref: rec.ledger_id || rec.ref });
    }
  } catch (err) {
    console.error('[gateway] directed forward failed:', err.message);
  }
}

/** Format the live pending-items list for a `pending` command reply. */
async function pendingListReply() {
  const res = await daemonCall('GET', '/api/pending-actions');
  const items = res.data?.items || res.data?.pending || (Array.isArray(res.data) ? res.data : []);
  if (!items.length) return '✅ Nothing pending — no approvals or open asks.';
  const lines = [`📋 ${items.length} pending item(s):`];
  for (const it of items.slice(0, 20)) {
    const age = it.created_at ? Math.round((Date.now() - new Date(it.created_at).getTime()) / 60000) : null;
    lines.push(`• ${it.id} [${it.kind}] ${String(it.summary || '').slice(0, 90)}${age != null ? ` (${age}m ago)` : ''}`);
  }
  lines.push('Reply APPROVE <id> / REJECT <id>, or quote the ask and reply yes/no.');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Forward incoming message to T3rnel API, return agent response
// ---------------------------------------------------------------------------
function forwardToT3rnel(text, phone, pushName, metadata, agent) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      message: text,
      metadata: metadata || {
        channel: 'whatsapp',
        sender: phone,
        sender_name: pushName,
      },
    });

    const url = new URL(
      `${T3RNEL_URL}/api/agents/${encodeURIComponent(agent || DEFAULT_AGENT)}/message`);

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || 4200,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
        timeout: 300_000, // agent loops routinely take 80-150s; 120s dropped real replies
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          try {
            const data = JSON.parse(body);
            // The /api/agents/{id}/message endpoint returns { response: "..." }
            resolve(data.response || data.message || data.text || '');
          } catch {
            resolve(body.trim() || '');
          }
        });
      },
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('T3rnel API timeout'));
    });
    req.write(payload);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Send a message via Baileys (called by T3rnel for outgoing)
// ---------------------------------------------------------------------------
async function sendMessage(to, text) {
  if (!sock || connStatus !== 'connected') {
    throw new Error('WhatsApp not connected');
  }

  // If already a full JID (group or user), use as-is; otherwise normalize phone → JID
  const jid = to.includes('@') ? to : to.replace(/^\+/, '') + '@s.whatsapp.net';

  await sendAndRemember(jid, { text });
}

/** Send and keep the proto message for retry replays (bounded). */
async function sendAndRemember(jid, content, meta = {}) {
  const sent = await sock.sendMessage(jid, content);
  if (sent?.key?.id) {
    recentSent.set(sent.key.id, sent);
    if (recentSent.size > 500) {
      recentSent.delete(recentSent.keys().next().value);
    }
    registerOutbound(sent.key.id, { ...meta, to: jid });
  }
  return sent;
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function jsonResponse(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': '*',
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  // SECURITY: defense-in-depth — reject non-loopback connections
  const clientIp = req.socket.remoteAddress;
  if (clientIp !== '127.0.0.1' && clientIp !== '::1' && clientIp !== '::ffff:127.0.0.1') {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    return res.end();
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;

  try {
    // POST /login/start — start Baileys connection, return QR
    if (req.method === 'POST' && pathname === '/login/start') {
      // If already connected, just return success
      if (connStatus === 'connected') {
        return jsonResponse(res, 200, {
          qr_data_url: '',
          session_id: sessionId,
          message: 'Already connected to WhatsApp',
          connected: true,
        });
      }

      // Start a new connection (resets any existing)
      await startConnection();

      // Wait briefly for QR to generate (Baileys emits it quickly)
      let waited = 0;
      while (!qrDataUrl && connStatus !== 'connected' && waited < 15_000) {
        await new Promise((r) => setTimeout(r, 300));
        waited += 300;
      }

      return jsonResponse(res, 200, {
        qr_data_url: qrDataUrl,
        session_id: sessionId,
        message: statusMessage,
        connected: connStatus === 'connected',
      });
    }

    // POST /logout — unlink the connected number.
    //
    // Deleting the stored credentials is the part that actually unlinks; the
    // socket logout is best-effort, because a session that WhatsApp already
    // invalidated still leaves credentials on disk that auto-reconnect on the
    // next boot. Removing them last means a failed logout does not strand a
    // half-linked state.
    if (req.method === 'POST' && pathname === '/logout') {
      let socketMessage = 'no active socket';
      if (sock) {
        try {
          await sock.logout();
          socketMessage = 'logged out';
        } catch (err) {
          socketMessage = `socket logout failed: ${err.message}`;
        }
        try { sock.end(); } catch { /* already closed */ }
        sock = null;
      }

      const authPath = path.join(__dirname, 'auth_store');
      let removed = false;
      try {
        if (fs.existsSync(authPath)) {
          fs.rmSync(authPath, { recursive: true, force: true });
          removed = true;
        }
      } catch (err) {
        return jsonResponse(res, 500, {
          error: `credentials could not be removed: ${err.message}. ` +
                 'The number is still linked.',
        });
      }

      connStatus = 'disconnected';
      qrDataUrl = '';
      statusMessage = 'Unlinked. POST /login/start to link a number.';
      console.log(`[gateway] Unlinked (${socketMessage}, credentials removed: ${removed})`);
      return jsonResponse(res, 200, {
        ok: true,
        unlinked: true,
        credentials_removed: removed,
        socket: socketMessage,
      });
    }

    // GET /linked — which number this gateway currently speaks as.
    //
    // Distinct from /login/status, which reports the connection. A gateway can
    // be linked to a number it is not presently connected to, and confusing the
    // two is what makes a dashboard disagree with itself.
    if (req.method === 'GET' && pathname === '/linked') {
      const credsPath = path.join(__dirname, 'auth_store', 'creds.json');
      let number = '';
      let linked = false;
      try {
        if (fs.existsSync(credsPath)) {
          linked = true;
          const creds = JSON.parse(fs.readFileSync(credsPath, 'utf8'));
          number = (creds?.me?.id || '').split(':')[0].replace(/@.*$/, '');
        }
      } catch { /* unreadable credentials count as not linked */ }

      return jsonResponse(res, 200, {
        linked,
        number,
        connected: connStatus === 'connected',
        owner_configured: Boolean(OWNER_JID),
        owner: OWNER_JID,
        message: statusMessage,
      });
    }

    // POST /notify — push an important event to the owner.
    //
    // Only the system calls this, and only for things worth interrupting a
    // person over: a post that went out, a security finding, a sale. A channel
    // that also carries routine chatter gets muted, and then the one message
    // that mattered is missed too.
    if (req.method === 'POST' && pathname === '/notify') {
      const body = await parseBody(req);
      const text = (body.text || '').trim();
      if (!text) {
        return jsonResponse(res, 400, { error: 'text is required' });
      }

      const target = (body.to || OWNER_JID).trim();
      if (!target) {
        // Reported, never silently dropped: a notification with nowhere to go
        // is a failure the caller must see.
        return jsonResponse(res, 400, {
          error: 'no recipient. Set T3RNEL_WHATSAPP_OWNER to the owner number, ' +
                 'or pass "to" in the request.',
        });
      }
      if (connStatus !== 'connected' || !sock) {
        return jsonResponse(res, 503, {
          error: `WhatsApp is not connected (${statusMessage}). Scan the QR to reconnect.`,
        });
      }

      const jid = target.includes('@')
        ? target
        : target.replace(/[^0-9]/g, '') + '@s.whatsapp.net';

      // Routing metadata callers may attach so a quoted reply or reaction on
      // this notification reaches the right place: ledger_id for pending
      // items, kind/ref/agent for agent- or approval-originated asks.
      const meta = {
        kind: body.kind || 'notify',
        ref: body.ref || null,
        agent: body.agent || null,
        summary: String(text).slice(0, 200),
        ledger_id: body.ledger_id || null,
      };

      try {
        // Optional image (e.g. a rendered-site screenshot for an approval).
        // Only files under ~/.t3rnel may be attached — never arbitrary paths.
        if (body.image) {
          const allowed = path.join(process.env.HOME || '', '.t3rnel') + path.sep;
          const file = path.resolve(String(body.image));
          if (!file.startsWith(allowed) || !fs.existsSync(file)) {
            return jsonResponse(res, 400, { error: 'image must be an existing file under ~/.t3rnel' });
          }
          await sendAndRemember(jid, { image: fs.readFileSync(file), caption: text }, meta);
        } else {
          await sendAndRemember(jid, { text }, meta);
        }
        console.log(`[gateway] Notified ${jid}${body.image ? ' (+image)' : ''}: ${text.substring(0, 60)}`);
        return jsonResponse(res, 200, { ok: true, to: jid });
      } catch (err) {
        return jsonResponse(res, 502, { error: `send failed: ${err.message}` });
      }
    }

    // GET /login/status — poll for connection status
    if (req.method === 'GET' && pathname === '/login/status') {
      return jsonResponse(res, 200, {
        connected: connStatus === 'connected',
        message: statusMessage,
        expired: qrExpired,
      });
    }

    // POST /message/send — send outgoing message via Baileys
    if (req.method === 'POST' && pathname === '/message/send') {
      const body = await parseBody(req);
      const { to, text } = body;

      if (!to || !text) {
        return jsonResponse(res, 400, { error: 'Missing "to" or "text" field' });
      }

      const jid = to.includes('@') ? to : to.replace(/^\+/, '') + '@s.whatsapp.net';
      await sendAndRemember(jid, { text }, {
        kind: body.kind || 'message',
        ref: body.ref || null,
        agent: body.agent || null,
        summary: String(text).slice(0, 200),
        ledger_id: body.ledger_id || null,
      });
      return jsonResponse(res, 200, { success: true, message: 'Sent' });
    }

    // POST /file — send a document. Same guard as /notify's image: only files
    // under ~/.t3rnel may leave the machine, never arbitrary paths.
    if (req.method === 'POST' && pathname === '/file') {
      const body = await parseBody(req);
      const { to, path: filePath, caption, filename } = body;
      if (!to || !filePath) {
        return jsonResponse(res, 400, { error: 'Missing "to" or "path" field' });
      }
      if (connStatus !== 'connected' || !sock) {
        return jsonResponse(res, 503, { error: `WhatsApp is not connected (${statusMessage})` });
      }
      const allowed = path.join(process.env.HOME || '', '.t3rnel') + path.sep;
      const file = path.resolve(String(filePath));
      if (!file.startsWith(allowed) || !fs.existsSync(file)) {
        return jsonResponse(res, 400, { error: 'path must be an existing file under ~/.t3rnel' });
      }
      const jid = to.includes('@') ? to : to.replace(/[^0-9]/g, '') + '@s.whatsapp.net';
      try {
        await sendAndRemember(jid, {
          document: fs.readFileSync(file),
          fileName: filename || path.basename(file),
          caption: caption || undefined,
          mimetype: 'application/octet-stream',
        }, {
          kind: body.kind || 'file',
          ref: body.ref || null,
          agent: body.agent || null,
          summary: String(caption || filename || filePath).slice(0, 200),
          ledger_id: body.ledger_id || null,
        });
        return jsonResponse(res, 200, { ok: true, to: jid, file: path.basename(file) });
      } catch (err) {
        return jsonResponse(res, 502, { error: `send failed: ${err.message}` });
      }
    }

    // GET /inbound/events — normalized inbound feed for the conversation
    // service's WhatsApp channel adapter (docs/sections/18 §3).
    // `since` is the last seq the caller consumed; `latest` is the newest
    // seq issued (callers jump their cursor to it when a page is short).
    if (req.method === 'GET' && pathname === '/inbound/events') {
      const since = parseInt(url.searchParams.get('since') || '0', 10) || 0;
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '200', 10) || 200, 500);
      const events = inboundEvents.filter((e) => e.seq > since).slice(0, limit);
      const credsExists = fs.existsSync(path.join(__dirname, 'auth_store', 'creds.json'));
      return jsonResponse(res, 200, {
        events,
        latest: inboundSeq,
        linked: credsExists,
        connected: connStatus === 'connected',
        number: credsExists ? linkedNumber() : '',
      });
    }

    // GET /media/:id — download an inbound media message's bytes.
    //
    // Baileys media is E2E-encrypted and only decryptable against the
    // original message object, so authorized inbound media messages are
    // kept in `recentMedia` (bounded) keyed by `msg.key.id` — the same id
    // the /inbound/events feed puts in `id` and the adapter puts in
    // `AttachmentRef.reference`. Unknown/expired ids 404; a disconnected
    // socket 503s (media keys rotate with the session).
    if (req.method === 'GET' && pathname.startsWith('/media/')) {
      const id = decodeURIComponent(pathname.slice('/media/'.length));
      const entry = recentMedia.get(id);
      if (!entry) {
        return jsonResponse(res, 404, { error: 'unknown or expired media id' });
      }
      if (connStatus !== 'connected' || !sock) {
        return jsonResponse(res, 503, {
          error: `WhatsApp is not connected (${statusMessage})`,
        });
      }
      try {
        const buffer = await downloadMediaMessage(
          entry.msg,
          'buffer',
          {},
          {
            logger: pino({ level: 'warn' }),
            reuploadRequest: sock.updateMediaMessage,
          },
        );
        const headers = {
          'Content-Type': entry.mime,
          'Content-Length': buffer.length,
          'Access-Control-Allow-Origin': '*',
        };
        if (entry.fileName) {
          const safe = String(entry.fileName).replace(/["\r\n]/g, '_');
          headers['Content-Disposition'] = `inline; filename="${safe}"`;
        }
        res.writeHead(200, headers);
        res.end(buffer);
        console.log(`[gateway] media ${id.slice(0, 24)} served (${buffer.length} bytes, ${entry.mime})`);
      } catch (err) {
        return jsonResponse(res, 502, { error: `media download failed: ${err.message}` });
      }
      return;
    }

    // GET /health — health check
    if (req.method === 'GET' && pathname === '/health') {
      return jsonResponse(res, 200, {
        status: 'ok',
        connected: connStatus === 'connected',
        session_id: sessionId || null,
      });
    }

    // 404
    jsonResponse(res, 404, { error: 'Not found' });
  } catch (err) {
    // Sanitize user-controlled inputs before logging to prevent format-string issues
    const safeMethod = String(req.method || 'UNKNOWN').replace(/[^\w-]/g, '');
    const safePath = String(pathname || '/').replace(/[^\w\-/._]/g, '');
    console.error(`[gateway] ${safeMethod} ${safePath} error: ${String(err.message || '').replace(/[\x00-\x1f]/g, '')}`);
    jsonResponse(res, 500, { error: err.message });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[gateway] WhatsApp Web gateway listening on http://127.0.0.1:${PORT}`);
  console.log(`[gateway] T3rnel URL: ${T3RNEL_URL}`);
  console.log(`[gateway] Default agent: ${DEFAULT_AGENT}`);

  // Auto-connect if credentials already exist from a previous session
  const credsPath = path.join(__dirname, 'auth_store', 'creds.json');
  if (fs.existsSync(credsPath)) {
    console.log('[gateway] Found existing credentials — auto-connecting...');
    startConnection().catch((err) => {
      console.error('[gateway] Auto-connect failed:', err.message);
      statusMessage = 'Auto-connect failed. Use POST /login/start to retry.';
    });
  } else {
    console.log('[gateway] No credentials found. Waiting for POST /login/start to begin QR flow...');
  }
});

// Catch background Baileys app state sync timeouts/errors without terminating process
process.on('unhandledRejection', (reason, promise) => {
  console.warn('[gateway] Unhandled Rejection at:', promise, 'reason:', reason?.message || reason);
});

process.on('uncaughtException', (err) => {
  console.error('[gateway] Uncaught Exception:', err?.message || err);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[gateway] Shutting down...');
  if (sock) sock.end();
  server.close(() => process.exit(0));
});

process.on('SIGTERM', () => {
  if (sock) sock.end();
  server.close(() => process.exit(0));
});
