// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';
import { collectStream } from './base.js';

export class SearchService {
  private readonly searchClient: Client<typeof models.search_v1.SearchService>;

  constructor(searchClient: Client<typeof models.search_v1.SearchService>) {
    this.searchClient = searchClient;
  }

  async searchCIDs(
    request: models.search_v1.SearchCIDsRequest,
  ): Promise<models.search_v1.SearchCIDsResponse[]> {
    return collectStream(this.searchClient.searchCIDs(request));
  }

  async searchRecords(
    request: models.search_v1.SearchRecordsRequest,
  ): Promise<models.search_v1.SearchRecordsResponse[]> {
    return collectStream(this.searchClient.searchRecords(request));
  }
}
