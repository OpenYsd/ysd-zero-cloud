/**
 * Envelope encryption for stored secrets.
 *
 * Runs on the WebCrypto API only, so the same code path works in workerd and
 * in the Node test runner. HKDF derives the per-record key: the master secret
 * is already high-entropy, so a password-stretching KDF would only burn
 * Worker CPU time without adding strength.
 */

const VERSION = 'v1';
const KEY_INFO = 'ysd-zero-cloud/secret';

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

async function deriveKey(masterSecret: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(masterSecret),
    'HKDF',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: new TextEncoder().encode(KEY_INFO) },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypts a secret value.
 *
 * @returns `v1.<salt>.<iv>.<ciphertext>`, all base64. Every field is needed to
 * decrypt, and nothing in it reveals the plaintext length beyond the usual
 * AES-GCM padding-free bound.
 */
export async function encryptSecret(plaintext: string, masterSecret: string): Promise<string> {
  if (!masterSecret) throw new Error('A master secret is required to encrypt values.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(masterSecret, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );
  return [VERSION, toBase64(salt), toBase64(iv), toBase64(ciphertext)].join('.');
}

/** Reverses {@link encryptSecret}. Throws when the payload or key is wrong. */
export async function decryptSecret(payload: string, masterSecret: string): Promise<string> {
  const [version, saltPart, ivPart, cipherPart] = payload.split('.');
  if (version !== VERSION || !saltPart || !ivPart || !cipherPart) {
    throw new Error('Unrecognised secret envelope.');
  }
  const key = await deriveKey(masterSecret, fromBase64(saltPart));
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(ivPart) as BufferSource },
    key,
    fromBase64(cipherPart) as BufferSource,
  );
  return new TextDecoder().decode(plaintext);
}

/**
 * A stable, non-reversible fingerprint of a secret value.
 *
 * Stored alongside the ciphertext so YSD Shield can spot the same credential
 * reused across environments without ever decrypting it.
 */
export async function fingerprint(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return toBase64(new Uint8Array(digest)).slice(0, 22);
}

/** Generates a URL-safe identifier with the given prefix. */
export function createId(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return `${prefix}_${out}`;
}
