// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';
import { collectStream, invoke } from './base.js';

export class RuntimeService {
  private readonly discoveryClient: Client<typeof models.runtime_v1.DiscoveryService>;

  constructor(discoveryClient: Client<typeof models.runtime_v1.DiscoveryService>) {
    this.discoveryClient = discoveryClient;
  }

  async getWorkload(
    request: models.runtime_v1.GetWorkloadRequest,
  ): Promise<models.runtime_v1.Workload> {
    return invoke('getWorkload', () => this.discoveryClient.getWorkload(request));
  }

  async listWorkloads(
    request: models.runtime_v1.ListWorkloadsRequest,
  ): Promise<models.runtime_v1.Workload[]> {
    return invoke('listWorkloads', () =>
      collectStream(this.discoveryClient.listWorkloads(request)),
    );
  }
}
