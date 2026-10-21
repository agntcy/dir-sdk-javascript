// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { randomBytes, scryptSync } from 'node:crypto';

import { xsalsa20poly1305 } from '@noble/ciphers/salsa.js';

/** Builds a cosign `ENCRYPTED SIGSTORE PRIVATE KEY` PEM (scrypt + nacl/secretbox). */
export function encryptCosignKey(der: Buffer, password: string): string {
  const salt = randomBytes(32);
  const nonce = randomBytes(24);
  const params = { N: 32768, r: 8, p: 1 };
  const key = scryptSync(password, salt, 32, { ...params, maxmem: 128 * 1024 * 1024 });
  const payload = {
    kdf: { name: 'scrypt', params, salt: salt.toString('base64') },
    cipher: { name: 'nacl/secretbox', nonce: nonce.toString('base64') },
    ciphertext: Buffer.from(xsalsa20poly1305(key, nonce).encrypt(der)).toString('base64'),
  };
  const body = Buffer.from(JSON.stringify(payload))
    .toString('base64')
    .replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n${body}\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n`;
}
