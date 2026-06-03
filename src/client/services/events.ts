// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';

export class EventService {
  private readonly eventClient: Client<typeof models.events_v1.EventService>;

  constructor(eventClient: Client<typeof models.events_v1.EventService>) {
    this.eventClient = eventClient;
  }

  listen(
    request: models.events_v1.ListenRequest,
  ): AsyncIterable<models.events_v1.ListenResponse> {
    return this.eventClient.listen(request);
  }
}
