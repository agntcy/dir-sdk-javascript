// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create } from '@bufbuild/protobuf';

import type { StoreService } from '../services/store.js';
import { unmarshalPublicKeyReferrer, unmarshalSignatureReferrer } from './referrers.js';
import * as models from '../../models/index.js';

export class StoreFetcher {
  private readonly storeService: StoreService;

  constructor(storeService: StoreService) {
    this.storeService = storeService;
  }

  async lookup(recordRef: models.core_v1.RecordRef): Promise<void> {
    const results = await this.storeService.lookup([recordRef]);
    if (results.length === 0) {
      throw new Error('record not found');
    }
  }

  async pullSignatures(recordRef: models.core_v1.RecordRef): Promise<models.sign_v1.Signature[]> {
    const responses = await this.storeService.pull_referrer([
      create(models.store_v1.PullReferrerRequestSchema, {
        recordRef,
        referrerType: 'agntcy.dir.sign.v1.Signature',
      }),
    ]);

    const signatures: models.sign_v1.Signature[] = [];
    for (const response of responses) {
      if (response.referrer === undefined) {
        continue;
      }
      try {
        signatures.push(unmarshalSignatureReferrer(response.referrer));
      } catch {
        continue;
      }
    }
    return signatures;
  }

  async pullPublicKeys(recordRef: models.core_v1.RecordRef): Promise<string[]> {
    const responses = await this.storeService.pull_referrer([
      create(models.store_v1.PullReferrerRequestSchema, {
        recordRef,
        referrerType: 'agntcy.dir.sign.v1.PublicKey',
      }),
    ]);

    const publicKeys: string[] = [];
    for (const response of responses) {
      if (response.referrer === undefined) {
        continue;
      }
      try {
        const publicKey = unmarshalPublicKeyReferrer(response.referrer);
        if (publicKey.key !== '') {
          publicKeys.push(publicKey.key);
        }
      } catch {
        continue;
      }
    }
    return publicKeys;
  }
}
