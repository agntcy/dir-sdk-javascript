// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';
import { collectStream } from './base.js';

export class PublicationService {
  private readonly publicationClient: Client<
    typeof models.routing_v1.PublicationService
  >;

  constructor(
    publicationClient: Client<typeof models.routing_v1.PublicationService>,
  ) {
    this.publicationClient = publicationClient;
  }

  async create_publication(
    request: models.routing_v1.PublishRequest,
  ): Promise<models.routing_v1.CreatePublicationResponse> {
    return await this.publicationClient.createPublication(request);
  }

  async list_publication(
    request: models.routing_v1.ListPublicationsRequest,
  ): Promise<models.routing_v1.ListPublicationsItem[]> {
    return collectStream(this.publicationClient.listPublications(request));
  }

  async get_publication(
    request: models.routing_v1.GetPublicationRequest,
  ): Promise<models.routing_v1.GetPublicationResponse> {
    return await this.publicationClient.getPublication(request);
  }
}
