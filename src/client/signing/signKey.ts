// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { createPublicKey } from 'node:crypto';
import { create } from '@bufbuild/protobuf';

import { detectKeyAlgorithm, loadPrivateKey, signPayload } from './cosignKeys.js';
import * as models from '../../models/index.js';

export function signWithKey(
  cid: string,
  req: models.sign_v1.SignWithKey,
): { signature: models.sign_v1.Signature; publicKey: models.sign_v1.PublicKey } {
  const password = req.password !== undefined && req.password.length > 0 ? req.password : undefined;
  const privateKey = loadPrivateKey(req.privateKey, password);
  const payload = Buffer.from(cid, 'utf8');
  const signatureBytes = signPayload(privateKey, payload);
  const publicKeyPem = createPublicKey(privateKey)
    .export({ type: 'spki', format: 'pem' })
    .toString();

  return {
    signature: create(models.sign_v1.SignatureSchema, {
      signedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      signature: signatureBytes.toString('base64'),
      algorithm: detectKeyAlgorithm(publicKeyPem),
    }),
    publicKey: create(models.sign_v1.PublicKeySchema, {
      key: publicKeyPem,
    }),
  };
}
