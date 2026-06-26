// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create, toJson, fromJson, type JsonObject } from '@bufbuild/protobuf';

import * as models from '../../models/index.js';

export function marshalSignatureReferrer(
  signature: models.sign_v1.Signature,
): models.core_v1.RecordReferrer {
  const data = toJson(models.sign_v1.SignatureSchema, signature) as JsonObject;
  return create(models.core_v1.RecordReferrerSchema, {
    type: 'agntcy.dir.sign.v1.Signature',
    data,
  });
}

export function marshalPublicKeyReferrer(
  publicKey: models.sign_v1.PublicKey,
): models.core_v1.RecordReferrer {
  const data = toJson(models.sign_v1.PublicKeySchema, publicKey) as JsonObject;
  return create(models.core_v1.RecordReferrerSchema, {
    type: 'agntcy.dir.sign.v1.PublicKey',
    data,
  });
}

export function unmarshalSignatureReferrer(
  referrer: models.core_v1.RecordReferrer,
): models.sign_v1.Signature {
  if (referrer.data === undefined) {
    throw new Error('referrer data is nil');
  }
  return fromJson(models.sign_v1.SignatureSchema, referrer.data);
}

export function unmarshalPublicKeyReferrer(
  referrer: models.core_v1.RecordReferrer,
): models.sign_v1.PublicKey {
  if (referrer.data === undefined) {
    throw new Error('referrer data is nil');
  }
  return fromJson(models.sign_v1.PublicKeySchema, referrer.data);
}
