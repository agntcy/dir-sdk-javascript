// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';
import { collectStream, requestGenerator } from './base.js';

export class StoreService {
  constructor(private readonly storeClient: Client<typeof models.store_v1.StoreService>) {}

  async push(records: models.core_v1.Record[]): Promise<models.core_v1.RecordRef[]> {
    return collectStream(this.storeClient.push(requestGenerator(records)));
  }

  async push_referrer(
    requests: models.store_v1.PushReferrerRequest[],
  ): Promise<models.store_v1.PushReferrerResponse[]> {
    return collectStream(this.storeClient.pushReferrer(requestGenerator(requests)));
  }

  async pull(refs: models.core_v1.RecordRef[]): Promise<models.core_v1.Record[]> {
    return collectStream(this.storeClient.pull(requestGenerator(refs)));
  }

  async pull_referrer(
    requests: models.store_v1.PullReferrerRequest[],
  ): Promise<models.store_v1.PullReferrerResponse[]> {
    return collectStream(this.storeClient.pullReferrer(requestGenerator(requests)));
  }

  async lookup(refs: models.core_v1.RecordRef[]): Promise<models.core_v1.RecordMeta[]> {
    return collectStream(this.storeClient.lookup(requestGenerator(refs)));
  }

  async delete(refs: models.core_v1.RecordRef[]): Promise<void> {
    await this.storeClient.delete(requestGenerator(refs));
  }
}
