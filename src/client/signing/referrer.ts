// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create, fromJson, toJson, type JsonObject } from '@bufbuild/protobuf';

import * as models from '../../models/index.js';

/** Referrer type of public key referrers (matches the Go `PublicKeyReferrerType`). */
export const PUBLIC_KEY_REFERRER_TYPE = models.sign_v1.PublicKeySchema.typeName;

/** Referrer type of signature referrers (matches the Go `SignatureReferrerType`). */
export const SIGNATURE_REFERRER_TYPE = models.sign_v1.SignatureSchema.typeName;

/**
 * Exports a Signature into a RecordReferrer (Go: `Signature.MarshalReferrer`).
 * The data is the protojson representation of the message.
 */
export function marshalSignatureReferrer(
  signature: models.sign_v1.Signature,
): models.core_v1.RecordReferrer {
  return create(models.core_v1.RecordReferrerSchema, {
    type: SIGNATURE_REFERRER_TYPE,
    data: toJson(models.sign_v1.SignatureSchema, signature) as JsonObject,
  });
}

/** Loads a Signature from a RecordReferrer (Go: `Signature.UnmarshalReferrer`). */
export function unmarshalSignatureReferrer(
  referrer: models.core_v1.RecordReferrer | undefined,
): models.sign_v1.Signature {
  if (referrer?.data === undefined) {
    throw new Error('referrer or data is nil');
  }
  return fromJson(models.sign_v1.SignatureSchema, referrer.data as JsonObject);
}

/** Exports a PublicKey into a RecordReferrer (Go: `PublicKey.MarshalReferrer`). */
export function marshalPublicKeyReferrer(
  publicKey: models.sign_v1.PublicKey,
): models.core_v1.RecordReferrer {
  return create(models.core_v1.RecordReferrerSchema, {
    type: PUBLIC_KEY_REFERRER_TYPE,
    data: toJson(models.sign_v1.PublicKeySchema, publicKey) as JsonObject,
  });
}

/** Loads a PublicKey from a RecordReferrer (Go: `PublicKey.UnmarshalReferrer`). */
export function unmarshalPublicKeyReferrer(
  referrer: models.core_v1.RecordReferrer | undefined,
): models.sign_v1.PublicKey {
  if (referrer?.data === undefined) {
    throw new Error('referrer or data is nil');
  }
  return fromJson(models.sign_v1.PublicKeySchema, referrer.data as JsonObject, {
    ignoreUnknownFields: true,
  });
}
