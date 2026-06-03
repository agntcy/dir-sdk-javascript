// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';

export class NamingService {
  private readonly namingClient: Client<typeof models.naming_v1.NamingService>;

  constructor(namingClient: Client<typeof models.naming_v1.NamingService>) {
    this.namingClient = namingClient;
  }

  async resolve(
    request: models.naming_v1.ResolveRequest,
  ): Promise<models.naming_v1.ResolveResponse> {
    return await this.namingClient.resolve(request);
  }

  async getVerificationInfo(
    request: models.naming_v1.GetVerificationInfoRequest,
  ): Promise<models.naming_v1.GetVerificationInfoResponse> {
    return await this.namingClient.getVerificationInfo(request);
  }
}
