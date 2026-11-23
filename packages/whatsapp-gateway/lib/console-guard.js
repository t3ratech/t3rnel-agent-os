// libsignal (inside Baileys) prints whole session objects with console.info/warn: "Closing session: SessionEntry { ... privKey:
// <Buffer ...> ... }". That is key material in the journal, and a log shipper would copy it off the host. Anything that looks like it is
// dropped before it reaches the console; every other call passes through untouched.

const KEY_MATERIAL = /privKey|pubKey|rootKey|chainKey|baseKey|SessionEntry|registrationId|previousCounter|<Buffer [0-9a-f]{2} /;
const SESSION_CHATTER = /^(Closing|Opening|Removing old closed|Migrating) session|^Session already (closed|open)|^Decrypted message with closed session|^No matching sessions found/;

function stringify(arg) {
  if (typeof arg === 'string') return arg;
  try {
    return JSON.stringify(arg) ?? '';
  } catch {
    return String(arg);
  }
}

export function isKeyMaterial(args) {
  const first = typeof args[0] === 'string' ? args[0] : '';
  if (SESSION_CHATTER.test(first)) return true;
  return args.some((a) => KEY_MATERIAL.test(stringify(a)) || (a && typeof a === 'object' && ('privKey' in a || 'rootKey' in a || 'chainKey' in a)));
}

// Install once at startup. `target` is injectable for tests.
export function guardConsole(target = console, methods = ['log', 'info', 'warn', 'error', 'debug']) {
  for (const m of methods) {
    const original = target[m].bind(target);
    target[m] = (...args) => {
      if (!isKeyMaterial(args)) original(...args);
    };
  }
  return target;
}
