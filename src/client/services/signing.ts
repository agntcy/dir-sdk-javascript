// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import type { StoreService } from '../services/store.js';
import { signRecord } from '../signing/sign.js';
import { verifyRecord } from '../signing/verify.js';
import * as models from '../../models/index.js';

export class SignService {
  private readonly storeService: StoreService;
  private readonly signClient: Client<typeof models.sign_v1.SignService>;

  constructor(storeService: StoreService, signClient: Client<typeof models.sign_v1.SignService>) {
    this.storeService = storeService;
    this.signClient = signClient;
  }

  async sign(req: models.sign_v1.SignRequest): Promise<void> {
    try {
      await signRecord(this.storeService, req);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to sign the object: ${message}`);
    }
  }

  async verify(request: models.sign_v1.VerifyRequest): Promise<models.sign_v1.VerifyResponse> {
    if (request.fromServer) {
      if (!request.recordRef?.cid) {
        throw new Error('VerifyRequest.recordRef with cid is required');
      }
      return await this.signClient.verify(request);
    }
    return verifyRecord(this.storeService, request);
  }
}
