// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import {
  createPrivateKey,
  createPublicKey,
  createSign,
  createVerify,
  scryptSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { env } from 'node:process';

import nacl from 'tweetnacl';

const ECDSA_CURVE_ALGORITHM_NAMES: Record<string, string> = {
  prime256v1: 'P-256',
  secp256r1: 'P-256',
  secp384r1: 'P-384',
  secp521r1: 'P-521',
  secp256k1: 'SECP256K1',
};

function readKeyMaterial(keyRef: string): Buffer {
  if (keyRef.startsWith('-----BEGIN')) {
    return Buffer.from(keyRef, 'utf8');
  }
  return readFileSync(keyRef);
}

function decryptCosignEnvelope(envelopeBytes: Buffer, password: Buffer): Buffer {
  const envelope = JSON.parse(envelopeBytes.toString('utf8')) as {
    kdf: { name: string; params: { N: number; r: number; p: number }; salt: string };
    cipher: { name: string; nonce: string };
    ciphertext: string;
  };

  if (envelope.kdf.name !== 'scrypt' || envelope.cipher.name !== 'nacl/secretbox') {
    throw new Error('unsupported encrypted cosign key format');
  }

  const salt = Buffer.from(envelope.kdf.salt, 'base64');
  const nonce = Buffer.from(envelope.cipher.nonce, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const { N, r, p } = envelope.kdf.params;
  const key = scryptSync(password, salt, 32, {
    N,
    r,
    p,
    maxmem: 128 * N * r * (p + 1) * 2,
  });
  const opened = nacl.secretbox.open(ciphertext, nonce, key);
  if (opened === null) {
    throw new Error('failed to decrypt cosign private key');
  }
  return Buffer.from(opened);
}

export function loadPrivateKey(
  keyRef: string,
  password?: Uint8Array,
): ReturnType<typeof createPrivateKey> {
  const keyBytes = readKeyMaterial(keyRef);
  const passwordBuffer = password
    ? Buffer.from(password)
    : Buffer.from(env.COSIGN_PASSWORD ?? '', 'utf8');

  try {
    return createPrivateKey({
      key: keyBytes,
      passphrase: passwordBuffer.length > 0 ? passwordBuffer : undefined,
    });
  } catch {
    const pem = keyBytes.toString('utf8');
    const encryptedKeyPattern =
      /-----BEGIN (?:ENCRYPTED SIGSTORE|ENCRYPTED COSIGN) PRIVATE KEY-----\s*([\s\S]+?)\s*-----END/;
    const match = encryptedKeyPattern.exec(pem);
    if (match === null) {
      throw new Error(`failed to load private key from reference: ${keyRef}`);
    }
    const envelope = Buffer.from(match[1].replace(/\s+/g, ''), 'base64');
    const decrypted = decryptCosignEnvelope(envelope, passwordBuffer);
    if (decrypted.toString('utf8').startsWith('-----BEGIN')) {
      return createPrivateKey({ key: decrypted });
    }
    return createPrivateKey({ key: decrypted, format: 'der', type: 'pkcs8' });
  }
}

export function loadPublicKey(keyRef: string): string {
  const keyBytes = readKeyMaterial(keyRef);
  const publicKey = createPublicKey({ key: keyBytes });
  return publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

export function detectKeyAlgorithm(publicKeyPem: string): string {
  const publicKey = createPublicKey(publicKeyPem);
  switch (publicKey.asymmetricKeyType) {
    case 'ec': {
      const namedCurve = publicKey.asymmetricKeyDetails?.namedCurve ?? '';
      const curveName = ECDSA_CURVE_ALGORITHM_NAMES[namedCurve] ?? namedCurve.toUpperCase();
      return curveName === '' ? 'ECDSA' : `ECDSA-${curveName}`;
    }
    case 'ed25519':
      return 'Ed25519';
    case 'rsa':
      return `RSA-${publicKey.asymmetricKeyDetails?.modulusLength ?? 0}`;
    default:
      return 'unknown';
  }
}

export function signPayload(
  privateKey: ReturnType<typeof createPrivateKey>,
  payload: Buffer,
): Buffer {
  const keyType = privateKey.asymmetricKeyType;
  if (keyType === 'ed25519' || keyType === 'ed448') {
    return cryptoSign(null, payload, privateKey);
  }
  const signer = createSign(keyType === 'rsa' || keyType === 'rsa-pss' ? 'RSA-SHA256' : 'SHA256');
  signer.update(payload);
  signer.end();
  return signer.sign(privateKey);
}

export function verifyPayload(publicKeyPem: string, signature: Buffer, payload: Buffer): void {
  const publicKey = createPublicKey(publicKeyPem);
  const keyType = publicKey.asymmetricKeyType;
  if (keyType === 'ed25519' || keyType === 'ed448') {
    if (!cryptoVerify(null, payload, publicKey, signature)) {
      throw new Error('signature verification failed');
    }
    return;
  }
  const verifier = createVerify(keyType === 'rsa' ? 'RSA-SHA256' : 'SHA256');
  verifier.update(payload);
  verifier.end();
  if (!verifier.verify(publicKey, signature)) {
    throw new Error('signature verification failed');
  }
}
