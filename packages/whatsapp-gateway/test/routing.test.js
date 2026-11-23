// Routing rules for inbound WhatsApp messages — lib/routing.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { daemonUrl, isLinkOnly, routeMessage, sitesmithCommand } from '../lib/routing.js';

test('daemonUrl prefers T3RNEL_URL, falls back to T3RNEL_API, then the legacy default', () => {
  assert.equal(daemonUrl({ T3RNEL_URL: 'http://a:1/' }), 'http://a:1', 'explicit URL wins and trailing slash is stripped');
  assert.equal(daemonUrl({ T3RNEL_API: 'http://127.0.0.1:50051' }), 'http://127.0.0.1:50051',
    '.env sets T3RNEL_API — a gateway that ignores it dies on the dead :4200 default');
  assert.equal(daemonUrl({}), 'http://127.0.0.1:4200');
});

test('prefixed messages reach the orchestrator with the prefix stripped', () => {
  const r = routeMessage('@t3rnel ship the drop', {});
  assert.equal(r.agent, 't3rnel');
  assert.equal(r.text, 'ship the drop');
  assert.equal(r.addressed, true);
});

test('operator DMs are addressed to the orchestrator without a prefix', () => {
  // A DM to the linked number IS the command channel — "what is the state of
  // the system" is an instruction, not chatter.
  const r = routeMessage('what is the state of the system', { isGroup: false, isOperator: true });
  assert.equal(r.agent, 't3rnel');
  assert.equal(r.addressed, true);
  assert.equal(r.text, 'what is the state of the system');
});

test('group messages without the prefix stay with the default agent', () => {
  const r = routeMessage('what is the state of the system', { isGroup: true, isOperator: true });
  assert.equal(r.agent, 'assistant');
  assert.equal(r.addressed, false, 'ambient group chatter must not wake the orchestrator');
});

test('non-operator DMs stay with the default agent', () => {
  const r = routeMessage('hello', { isGroup: false, isOperator: false });
  assert.equal(r.agent, 'assistant');
  assert.equal(r.addressed, false);
});

test('isLinkOnly: bare URLs are link-watch jobs, prose is not', () => {
  assert.equal(isLinkOnly('https://news.example/story'), true);
  assert.equal(isLinkOnly(' https://a.example/x  https://b.example/y '), true);
  assert.equal(isLinkOnly('watch this https://a.example/x'), false);
  assert.equal(isLinkOnly('what is the state of the system'), false);
});

test('sitesmith hold/send only intercept real leads, so chat like "hold on" still reaches the orchestrator', () => {
  const leads = new Set(['kaviya-attorneys']);
  const isLead = (s) => leads.has(s);
  assert.deepEqual(sitesmithCommand('hold kaviya-attorneys', isLead), { verb: 'hold', slug: 'kaviya-attorneys' });
  assert.deepEqual(sitesmithCommand('  SEND Kaviya-Attorneys ', isLead), { verb: 'send', slug: 'kaviya-attorneys' });
  assert.equal(sitesmithCommand('hold on', isLead), null);
  assert.equal(sitesmithCommand('send it now', isLead), null);
  assert.equal(sitesmithCommand('hold kaviya-attorneys please', isLead), null, 'extra words: not a command');
  assert.deepEqual(sitesmithCommand('sitesmith status', isLead), { verb: 'status', slug: null });
  assert.deepEqual(sitesmithCommand('sitesmith status kaviya-attorneys', isLead), { verb: 'status', slug: 'kaviya-attorneys' });
  assert.equal(sitesmithCommand('status', isLead), null, 'a bare "status" is ordinary chat');
});
