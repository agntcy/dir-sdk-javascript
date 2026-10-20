// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create } from '@bufbuild/protobuf';

import * as models from '../../models/index.js';
import { detectKeyAlgorithm, loadSigner } from './keys.js';
import { signBlobWithOidc, toRfc3339 } from './oidc.js';

export interface SignResult {
  signature: models.sign_v1.Signature;
  publicKey: models.sign_v1.PublicKey;
}

/**
 * Signs a blob using a private key. Supports inline PEM content and key references
 * (file paths, URLs).
 */
export async function signBlobWithKey(
  payload: Uint8Array,
  req: models.sign_v1.SignWithKey,
): Promise<SignResult> {
  if (req.privateKey === '') {
    throw new Error('private_key is required');
  }

  const signer = await loadSigner(req.privateKey, req.password);

  let sig: Buffer;
  try {
    sig = signer.signMessage(payload);
  } catch (e) {
    throw new Error(`signing blob: ${e}`, { cause: e });
  }
  const publicKeyPem = signer.publicKeyPem();

  return {
    signature: create(models.sign_v1.SignatureSchema, {
      signedAt: toRfc3339(new Date()),
      signature: sig.toString('base64'),
      algorithm: detectKeyAlgorithm(publicKeyPem),
    }),
    publicKey: create(models.sign_v1.PublicKeySchema, { key: publicKeyPem }),
  };
}

export { signBlobWithOidc };
