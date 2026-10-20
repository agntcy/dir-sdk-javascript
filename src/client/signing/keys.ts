// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import {
  createPrivateKey,
  createPublicKey,
  scryptSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { readFileSync } from 'node:fs';

import { xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { ed25519ph } from '@noble/curves/ed25519.js';

const COSIGN_PRIVATE_KEY_PEM_TYPE = 'ENCRYPTED COSIGN PRIVATE KEY';
const SIGSTORE_PRIVATE_KEY_PEM_TYPE = 'ENCRYPTED SIGSTORE PRIVATE KEY';
const PLAIN_PRIVATE_KEY_PEM_TYPES = ['PRIVATE KEY', 'EC PRIVATE KEY', 'RSA PRIVATE KEY'];

// scrypt parameter sets accepted by go-securesystemslib/encrypted (legacy, standard, OWASP).
const SCRYPT_PARAMS = [
  { N: 32768, r: 8, p: 1 },
  { N: 65536, r: 8, p: 1 },
  { N: 131072, r: 8, p: 1 },
];
const SCRYPT_KEY_SIZE = 32;
const SECRETBOX_NONCE_SIZE = 24;

/** Signs a message with a loaded private key. */
export interface BlobSigner {
  /** Signs the message (cosign defaults: ECDSA/RSA with SHA-256, Ed25519 as Ed25519ph). */
  // eslint-disable-next-line no-unused-vars
  signMessage(message: Uint8Array): Buffer;
  /** PEM (PKIX) encoded public key. */
  publicKeyPem(): string;
}

interface EncryptedKeyData {
  kdf?: { name?: string; params?: { N?: number; r?: number; p?: number }; salt?: string };
  cipher?: { name?: string; nonce?: string };
  ciphertext?: string;
}

function parsePemBlock(pem: string): { type: string; body: Buffer } {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(pem);
  if (match === null) {
    throw new Error('invalid pem block');
  }
  return { type: match[1], body: Buffer.from(match[2].replace(/\s+/g, ''), 'base64') };
}

/** Decrypts a go-securesystemslib `encrypted` payload (scrypt + nacl/secretbox). */
function decryptKeyData(encoded: Buffer, password: Uint8Array): Buffer {
  let data: EncryptedKeyData;
  try {
    data = JSON.parse(encoded.toString('utf8')) as EncryptedKeyData;
  } catch (e) {
    throw new Error('decrypt: invalid encrypted key payload', { cause: e });
  }

  if (data.kdf?.name !== 'scrypt') {
    throw new Error('decrypt: unsupported KDF');
  }
  if (data.cipher?.name !== 'nacl/secretbox') {
    throw new Error('decrypt: unsupported cipher');
  }
  const params = data.kdf.params;
  if (!SCRYPT_PARAMS.some((p) => p.N === params?.N && p.r === params.r && p.p === params.p)) {
    throw new Error('decrypt: unsupported scrypt parameters');
  }

  const salt = Buffer.from(data.kdf.salt ?? '', 'base64');
  const nonce = Buffer.from(data.cipher.nonce ?? '', 'base64');
  const ciphertext = Buffer.from(data.ciphertext ?? '', 'base64');
  if (nonce.length !== SECRETBOX_NONCE_SIZE) {
    throw new Error('decrypt: incorrect nonce size');
  }

  const key = scryptSync(password, salt, SCRYPT_KEY_SIZE, {
    N: params!.N,
    r: params!.r,
    p: params!.p,
    maxmem: 512 * 1024 * 1024,
  });

  try {
    return Buffer.from(xsalsa20poly1305(key, nonce).decrypt(ciphertext));
  } catch (e) {
    throw new Error('decrypt: wrong password for private key', { cause: e });
  }
}

function exportPublicKeyPem(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'pem' }).toString();
}

class KeyObjectSigner implements BlobSigner {
  private readonly privateKey: KeyObject;

  constructor(privateKey: KeyObject) {
    this.privateKey = privateKey;
  }

  signMessage(message: Uint8Array): Buffer {
    switch (this.privateKey.asymmetricKeyType) {
      case 'ed25519': {
        // cosign signs Ed25519 keys as Ed25519ph, the only variant usable with hashedrekord.
        const seed = Buffer.from(this.privateKey.export({ format: 'jwk' }).d ?? '', 'base64url');
        return Buffer.from(ed25519ph.sign(message, seed));
      }
      case 'ec':
      case 'rsa':
        return cryptoSign('sha256', message, this.privateKey);
      default:
        throw new Error('unsupported public key type');
    }
  }

  publicKeyPem(): string {
    return exportPublicKeyPem(createPublicKey(this.privateKey));
  }
}

/**
 * Loads a private key from PEM content. Cosign encrypted keys
 * (`ENCRYPTED COSIGN PRIVATE KEY` / `ENCRYPTED SIGSTORE PRIVATE KEY`) are decrypted with the
 * password; plain PKCS#8 / SEC1 / PKCS#1 PEM keys are loaded as is.
 */
export function loadPrivateKey(pem: string, password: Uint8Array = new Uint8Array()): BlobSigner {
  const { type, body } = parsePemBlock(pem);

  if (type === COSIGN_PRIVATE_KEY_PEM_TYPE || type === SIGSTORE_PRIVATE_KEY_PEM_TYPE) {
    const der = decryptKeyData(body, password);
    return new KeyObjectSigner(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }));
  }
  if (type === 'ENCRYPTED PRIVATE KEY') {
    return new KeyObjectSigner(createPrivateKey({ key: pem, passphrase: Buffer.from(password) }));
  }
  if (PLAIN_PRIVATE_KEY_PEM_TYPES.includes(type)) {
    return new KeyObjectSigner(createPrivateKey(pem));
  }
  throw new Error(`unsupported pem type: ${type}`);
}

async function loadKeyReference(ref: string): Promise<string> {
  if (/^https?:\/\//.test(ref)) {
    const response = await fetch(ref);
    if (!response.ok) {
      throw new Error(`fetching ${ref}: ${response.status} ${response.statusText}`);
    }
    return await response.text();
  }
  if (ref.includes('://')) {
    throw new Error(`unsupported key reference scheme: ${ref}`);
  }
  return readFileSync(ref, 'utf8');
}

/**
 * Loads a signer from raw PEM content, falling back to a key reference (file path or
 * HTTP(S) URL). KMS/PKCS11/Kubernetes references are not supported.
 */
export async function loadSigner(privateKey: string, password?: Uint8Array): Promise<BlobSigner> {
  try {
    return loadPrivateKey(privateKey, password);
  } catch (rawErr) {
    if (privateKey.includes('-----BEGIN')) {
      throw new Error(`loading private key from reference: ${rawErr}`, { cause: rawErr });
    }
    try {
      return loadPrivateKey(await loadKeyReference(privateKey), password);
    } catch (e) {
      throw new Error(`loading private key from reference: ${e}`, { cause: e });
    }
  }
}

/** Loads a public key from PEM content, falling back to a key reference (file path or URL). */
export async function loadPublicKey(publicKey: string): Promise<KeyObject> {
  try {
    return createPublicKey(publicKey);
  } catch (rawErr) {
    if (publicKey.includes('-----BEGIN')) {
      throw new Error(`failed to load public key: ${rawErr}`, { cause: rawErr });
    }
    try {
      return createPublicKey(await loadKeyReference(publicKey));
    } catch (e) {
      throw new Error(`failed to load public key: ${e}`, { cause: e });
    }
  }
}

function decodeSignature(sig: string): Buffer {
  // Mirror Go: strict base64 decoding, otherwise assume the value is already raw bytes.
  if (sig.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(sig)) {
    return Buffer.from(sig, 'base64');
  }
  return Buffer.from(sig, 'utf8');
}

/**
 * Verifies a signature over the payload with a public key (PEM or key reference).
 * Ed25519 keys accept both pure Ed25519 and Ed25519ph signatures.
 * Returns the PEM-encoded public key on success.
 */
export async function verifySignatureWithKey(
  publicKey: string,
  sig: string,
  payload: Uint8Array,
): Promise<string> {
  const key = await loadPublicKey(publicKey);
  const signature = decodeSignature(sig);

  let valid: boolean;
  switch (key.asymmetricKeyType) {
    case 'ed25519': {
      valid = cryptoVerify(null, payload, key, signature);
      if (!valid) {
        const raw = Buffer.from(key.export({ format: 'jwk' }).x ?? '', 'base64url');
        try {
          valid = ed25519ph.verify(signature, payload, raw);
        } catch {
          valid = false;
        }
      }
      break;
    }
    case 'ec':
    case 'rsa':
      try {
        valid = cryptoVerify('sha256', payload, key, signature);
      } catch {
        valid = false;
      }
      break;
    default:
      throw new Error('unsupported public key type');
  }

  if (!valid) {
    throw new Error('signature verification failed');
  }
  return exportPublicKeyPem(key);
}

/** Detects the algorithm of a PEM public key, e.g. "ECDSA-P-256", "Ed25519", "RSA-2048". */
export function detectKeyAlgorithm(publicKeyPem: string): string {
  let key: KeyObject;
  try {
    parsePemBlock(publicKeyPem);
    key = createPublicKey(publicKeyPem);
  } catch {
    return 'unknown';
  }

  switch (key.asymmetricKeyType) {
    case 'ec': {
      const crv = key.export({ format: 'jwk' }).crv;
      return crv ? `ECDSA-${crv.toUpperCase()}` : 'ECDSA';
    }
    case 'ed25519':
      return 'Ed25519';
    case 'rsa':
      return `RSA-${Math.ceil((key.asymmetricKeyDetails?.modulusLength ?? 0) / 8) * 8}`;
    default:
      return 'unknown';
  }
}
