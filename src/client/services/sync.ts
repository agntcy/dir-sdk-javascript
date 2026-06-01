// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';
import { collectStream } from './base.js';

export class SyncService {
  constructor(private readonly syncClient: Client<typeof models.store_v1.SyncService>) {}

  async create_sync(
    request: models.store_v1.CreateSyncRequest,
  ): Promise<models.store_v1.CreateSyncResponse> {
    return await this.syncClient.createSync(request);
  }

  async list_syncs(
    request: models.store_v1.ListSyncsRequest,
  ): Promise<models.store_v1.ListSyncsItem[]> {
    return collectStream(this.syncClient.listSyncs(request));
  }

  async get_sync(
    request: models.store_v1.GetSyncRequest,
  ): Promise<models.store_v1.GetSyncResponse> {
    return await this.syncClient.getSync(request);
  }

  async delete_sync(
    request: models.store_v1.DeleteSyncRequest,
  ): Promise<models.store_v1.DeleteSyncResponse> {
    return await this.syncClient.deleteSync(request);
  }
}
