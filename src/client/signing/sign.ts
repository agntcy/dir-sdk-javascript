// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create } from '@bufbuild/protobuf';

import type { StoreService } from '../services/store.js';
import { StoreFetcher } from './fetcher.js';
import { marshalPublicKeyReferrer, marshalSignatureReferrer } from './referrers.js';
import { signWithKey } from './signKey.js';
import { signWithOidc } from './signOidc.js';
import * as models from '../../models/index.js';

async function pushReferrers(
  storeService: StoreService,
  recordRef: models.core_v1.RecordRef,
  signature: models.sign_v1.Signature,
  publicKey: models.sign_v1.PublicKey,
): Promise<void> {
  const publicKeyReferrer = marshalPublicKeyReferrer(publicKey);
  const signatureReferrer = marshalSignatureReferrer(signature);

  await storeService.push_referrer([
    create(models.store_v1.PushReferrerRequestSchema, {
      recordRef,
      type: publicKeyReferrer.type,
      annotations: publicKeyReferrer.annotations,
      createdAt: publicKeyReferrer.createdAt,
      data: publicKeyReferrer.data,
    }),
    create(models.store_v1.PushReferrerRequestSchema, {
      recordRef,
      type: signatureReferrer.type,
      annotations: signatureReferrer.annotations,
      createdAt: signatureReferrer.createdAt,
      data: signatureReferrer.data,
    }),
  ]);
}

export async function signRecord(
  storeService: StoreService,
  request: models.sign_v1.SignRequest,
): Promise<void> {
  if (request.recordRef?.cid === undefined || request.recordRef.cid === '') {
    throw new Error('record ref must be specified');
  }
  if (request.provider === undefined) {
    throw new Error('signature provider must be specified');
  }

  await new StoreFetcher(storeService).lookup(request.recordRef);

  let signed: { signature: models.sign_v1.Signature; publicKey: models.sign_v1.PublicKey };
  switch (request.provider.request.case) {
    case 'key':
      signed = signWithKey(request.recordRef.cid, request.provider.request.value);
      break;
    case 'oidc':
      signed = await signWithOidc(request.recordRef.cid, request.provider.request.value);
      break;
    default:
      throw new Error('unsupported signature provider type');
  }

  await pushReferrers(storeService, request.recordRef, signed.signature, signed.publicKey);
}
