// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';
import { invoke } from './base.js';

export class AIFinderService {
  private readonly aiFinderClient: Client<typeof models.catalog_v1.AIFinderService>;

  constructor(aiFinderClient: Client<typeof models.catalog_v1.AIFinderService>) {
    this.aiFinderClient = aiFinderClient;
  }

  async listAgents(
    request: models.catalog_v1.ListAgentsRequest,
  ): Promise<models.catalog_v1.ListAgentsResponse> {
    return invoke('listAgents', () => this.aiFinderClient.listAgents(request));
  }

  async getAgent(
    request: models.catalog_v1.GetAgentRequest,
  ): Promise<models.catalog_v1.GetAgentResponse> {
    return invoke('getAgent', () => this.aiFinderClient.getAgent(request));
  }

  async exportAgent(
    request: models.catalog_v1.ExportAgentRequest,
  ): Promise<models.catalog_v1.HttpBody> {
    return invoke('exportAgent', () => this.aiFinderClient.exportAgent(request));
  }

  async getWellKnownCatalog(
    request: models.catalog_v1.GetWellKnownCatalogRequest,
  ): Promise<models.catalog_v1.GetWellKnownCatalogResponse> {
    return invoke('getWellKnownCatalog', () => this.aiFinderClient.getWellKnownCatalog(request));
  }
}
