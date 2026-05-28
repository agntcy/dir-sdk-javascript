// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import type { Config } from '../config.js';
import { signRecord } from '../dirctl/signing.js';
import { verifyRecord } from '../dirctl/verification.js';
import * as models from '../../models/index.js';

export class SignService {
  constructor(
    private readonly config: Config,
    private readonly signClient: Client<typeof models.sign_v1.SignService>,
  ) {}

  sign(req: models.sign_v1.SignRequest): void {
    signRecord(this.config, req);
  }

  async verify(
    request: models.sign_v1.VerifyRequest,
  ): Promise<models.sign_v1.VerifyResponse> {
    if (request.fromServer) {
      if (!request.recordRef?.cid) {
        throw new Error('VerifyRequest.recordRef with cid is required');
      }
      return await this.signClient.verify(request);
    }
    return verifyRecord(this.config, request);
  }
}
