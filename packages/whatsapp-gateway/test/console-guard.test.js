import test from 'node:test';
import assert from 'node:assert/strict';
import { guardConsole, isKeyMaterial } from '../lib/console-guard.js';

function fakeConsole() {
  const out = [];
  const c = {};
  for (const m of ['log', 'info', 'warn', 'error', 'debug']) c[m] = (...a) => out.push([m, ...a]);
  return { c, out };
}

test('a libsignal session dump never reaches the console', () => {
  const { c, out } = fakeConsole();
  guardConsole(c);
  const session = { registrationId: 1234, currentRatchet: { rootKey: Buffer.from('aa'), ephemeralKeyPair: { privKey: Buffer.from('bb'), pubKey: Buffer.from('cc') } } };
  c.info('Closing session:', session);
  c.warn('Removing old closed session:', session);
  c.log({ privKey: Buffer.from('dd') });
  assert.deepEqual(out, []);
});

test('the session chatter lines are dropped even without an object', () => {
  const { c, out } = fakeConsole();
  guardConsole(c);
  for (const s of ['Closing session: SessionEntry {', 'Opening session', 'Migrating session to:', 'Session already closed', 'No matching sessions found for message']) c.info(s);
  assert.deepEqual(out, []);
});

test('the gateway\'s own messages and errors pass through unchanged', () => {
  const { c, out } = fakeConsole();
  guardConsole(c);
  c.log('[gateway] Connected to WhatsApp!');
  c.error('[gateway] Forward/reply failed:', 'boom');
  c.warn('something else', { a: 1 });
  assert.deepEqual(out, [['log', '[gateway] Connected to WhatsApp!'], ['error', '[gateway] Forward/reply failed:', 'boom'], ['warn', 'something else', { a: 1 }]]);
});

test('buffers of key bytes are caught even inside a string', () => {
  assert.equal(isKeyMaterial(['privKey: <Buffer 50 6d a0>']), true);
  assert.equal(isKeyMaterial(['a message about a buffer']), false);
});

test('a circular object does not crash the guard', () => {
  const a = { name: 'x' };
  a.self = a;
  assert.equal(isKeyMaterial([a]), false);
});
