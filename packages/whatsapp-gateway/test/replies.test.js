// Two-way reply handling — lib/replies.js decision words, quoted-message
// extraction, reaction mapping and local commands.

import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyDecision, quotedMessageId, extractReaction, reactionDecision, localCommand, dmReplyJid } from '../lib/replies.js';

test('classifyDecision: bare approval words approve', () => {
  for (const w of ['yes', 'yeah', 'yep', 'sure', 'cool', 'ok', 'okay', 'approve', 'lgtm', 'go', 'do it', '👍', '✅']) {
    assert.equal(classifyDecision(w), 'approve', w);
  }
});

test('classifyDecision: rejection words reject', () => {
  for (const w of ['no', 'nope', 'nah', 'reject', 'deny', 'cancel', 'stop', '👎', '❌']) {
    assert.equal(classifyDecision(w), 'reject', w);
  }
});

test('classifyDecision: leading decision word wins with trailing text', () => {
  assert.equal(classifyDecision('approve P-103'), 'approve');
  assert.equal(classifyDecision('yes but shorten it'), 'approve');
  assert.equal(classifyDecision('reject it'), 'reject');
});

test('classifyDecision: non-decision text returns null', () => {
  for (const t of ['tell me more', 'what is this?', 'send me the file', 'P-103', '']) {
    assert.equal(classifyDecision(t), null, t);
  }
});

test('quotedMessageId reads contextInfo across message types', () => {
  const ext = { message: { extendedTextMessage: { text: 'hi', contextInfo: { stanzaId: 'ABC123' } } } };
  assert.equal(quotedMessageId(ext), 'ABC123');
  const img = { message: { imageMessage: { contextInfo: { stanzaId: 'IMG9' } } } };
  assert.equal(quotedMessageId(img), 'IMG9');
  assert.equal(quotedMessageId({ message: { conversation: 'plain' } }), null);
  assert.equal(quotedMessageId(null), null);
});

test('extractReaction + reactionDecision map emoji to decisions', () => {
  const msg = { message: { reactionMessage: { key: { id: 'TARGET1' }, text: '👍' } } };
  const r = extractReaction(msg);
  assert.equal(r.targetId, 'TARGET1');
  assert.equal(reactionDecision(r.emoji), 'approve');
  assert.equal(reactionDecision('👎'), 'reject');
  assert.equal(reactionDecision('😂'), null);
  assert.equal(extractReaction({ message: { conversation: 'x' } }), null);
});

test('localCommand recognizes pending/help only', () => {
  assert.equal(localCommand('pending'), 'pending');
  assert.equal(localCommand('Pending'), 'pending');
  assert.equal(localCommand('approvals'), 'pending');
  assert.equal(localCommand('help'), 'help');
  assert.equal(localCommand('approve P-1'), null);
  assert.equal(localCommand('hello'), null);
});

test('dmReplyJid: phone sender gets @s.whatsapp.net', () => {
  assert.equal(dmReplyJid('263785107830@s.whatsapp.net', '263785107830@s.whatsapp.net', false, new Map()),
    '263785107830@s.whatsapp.net');
});

test('dmReplyJid: @lid sender resolves via lid map to real phone', () => {
  const map = new Map([['230240446091399', '263785107830']]);
  assert.equal(dmReplyJid('230240446091399@lid', '230240446091399@lid', false, map),
    '263785107830@s.whatsapp.net');
});

test('dmReplyJid: unknown @lid keeps the @lid JID (never builds a fake phone JID)', () => {
  assert.equal(dmReplyJid('999888777@lid', '999888777@lid', false, new Map()),
    '999888777@lid');
});

test('dmReplyJid: group replies to the group JID', () => {
  assert.equal(dmReplyJid('263785107830@s.whatsapp.net', '120363@g.us', true, new Map()),
    '120363@g.us');
});
