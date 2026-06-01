// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';
import { collectStream } from './base.js';

export class RoutingService {
  constructor(
    private readonly routingClient: Client<typeof models.routing_v1.RoutingService>,
  ) {}

  async publish(request: models.routing_v1.PublishRequest): Promise<void> {
    await this.routingClient.publish(request);
  }

  async list(
    request: models.routing_v1.ListRequest,
  ): Promise<models.routing_v1.ListResponse[]> {
    return collectStream(this.routingClient.list(request));
  }

  async unpublish(request: models.routing_v1.UnpublishRequest): Promise<void> {
    await this.routingClient.unpublish(request);
  }
}
