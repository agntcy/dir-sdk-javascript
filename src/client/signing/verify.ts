// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create } from '@bufbuild/protobuf';

import * as models from '../../models/index.js';
import { detectKeyAlgorithm, verifySignatureWithKey } from './keys.js';
import { verifyWithOidc } from './oidc.js';
import { getDefaultVerifyOptions } from './options.js';

/** Supplies signatures and public keys for a record. */
export interface Fetcher {
  // eslint-disable-next-line no-unused-vars
  pullSignatures(recordRef: models.core_v1.RecordRef): Promise<models.sign_v1.Signature[]>;
  // eslint-disable-next-line no-unused-vars
  pullPublicKeys(recordRef: models.core_v1.RecordRef): Promise<string[]>;
}

/**
 * Verifies a signature against public keys (PEM content or key references). Returns the signer
 * info of the first public key that verifies the signature.
 */
export async function verifyWithKeys(
  payload: Uint8Array,
  publicKeys: string[],
  signature: models.sign_v1.Signature,
): Promise<models.sign_v1.SignerInfo> {
  for (const publicKey of publicKeys) {
    let pem: string;
    try {
      pem = await verifySignatureWithKey(publicKey, signature.signature, payload);
    } catch {
      continue; // Try the next public key
    }

    return create(models.sign_v1.SignerInfoSchema, {
      type: {
        case: 'key',
        value: create(models.sign_v1.SignerInfoKeySchema, {
          publicKey: pem,
          algorithm: detectKeyAlgorithm(pem),
        }),
      },
    });
  }

  throw new Error('no valid signature found for the provided public keys');
}

async function verifyWithAny(
  payload: Uint8Array,
  publicKeys: string[],
  signature: models.sign_v1.Signature,
  oidcOptions: models.sign_v1.VerifyOptionsOIDC | undefined,
): Promise<models.sign_v1.SignerInfo> {
  if (signature.contentBundle.length === 0) {
    try {
      return await verifyWithKeys(payload, publicKeys, signature);
    } catch (e) {
      throw new Error(`failed to verify signature with keys: ${e}`, { cause: e });
    }
  }

  try {
    return await verifyWithOidc(
      payload,
      create(models.sign_v1.VerifyWithOIDCSchema, {
        options: getDefaultVerifyOptions(oidcOptions),
      }),
      signature,
    );
  } catch (e) {
    throw new Error(`failed to verify signature with OIDC: ${e}`, { cause: e });
  }
}

function getSignerKey(signer: models.sign_v1.SignerInfo): string {
  switch (signer.type.case) {
    case 'key':
      return `key:${signer.type.value.publicKey}|${signer.type.value.algorithm}`;
    case 'oidc':
      return `oidc:${signer.type.value.issuer}|${signer.type.value.subject}|${signer.type.value.certificateIssuer}`;
    default:
      return '';
  }
}

function failure(message: string): models.sign_v1.VerifyResponse {
  return create(models.sign_v1.VerifyResponseSchema, { success: false, errorMessage: message });
}

/** Runs signature verification using the given fetcher (Go `VerifyWithFetcher`). */
export async function verifyWithFetcher(
  req: models.sign_v1.VerifyRequest,
  fetcher: Fetcher,
): Promise<models.sign_v1.VerifyResponse> {
  const recordRef = req.recordRef;
  if (!recordRef?.cid) {
    throw new Error('record ref is required');
  }

  // Default to the "any" provider with default OIDC options.
  const provider: models.sign_v1.VerifyRequestProvider =
    req.provider?.request.case !== undefined
      ? req.provider
      : create(models.sign_v1.VerifyRequestProviderSchema, {
          request: {
            case: 'any',
            value: create(models.sign_v1.VerifyWithAnySchema, {
              oidcOptions: getDefaultVerifyOptions(),
            }),
          },
        });

  let signatures: models.sign_v1.Signature[];
  try {
    signatures = await fetcher.pullSignatures(recordRef);
  } catch (e) {
    throw new Error(`pull signatures: ${e}`, { cause: e });
  }

  if (signatures.length === 0) {
    return failure('no signatures found');
  }

  let publicKeys: string[] = [];
  const request = provider.request;
  if (request.case === 'key') {
    publicKeys = [request.value.publicKey];
  } else if (request.case === 'any') {
    try {
      publicKeys = await fetcher.pullPublicKeys(recordRef);
    } catch (e) {
      throw new Error(`pull public keys: ${e}`, { cause: e });
    }
  }

  const payload = Buffer.from(recordRef.cid);
  const seenKeys = new Set<string>();
  const signers: models.sign_v1.SignerInfo[] = [];

  for (const sig of signatures) {
    let signerInfo: models.sign_v1.SignerInfo;
    try {
      switch (request.case) {
        case 'oidc':
          signerInfo = await verifyWithOidc(payload, request.value, sig);
          break;
        case 'key':
          signerInfo = await verifyWithKeys(payload, publicKeys, sig);
          break;
        case 'any':
          signerInfo = await verifyWithAny(payload, publicKeys, sig, request.value.oidcOptions);
          break;
        default:
          throw new Error('unsupported verification provider type');
      }
    } catch {
      continue; // Failed verifications have no SignerInfo; only verified signers are reported
    }

    const signerKey = getSignerKey(signerInfo);
    if (seenKeys.has(signerKey)) {
      continue; // Only report one result per signer
    }
    seenKeys.add(signerKey);
    signers.push(signerInfo);
  }

  if (signers.length === 0) {
    return failure('no valid signatures found matching verification criteria');
  }

  return create(models.sign_v1.VerifyResponseSchema, { success: true, signers });
}
