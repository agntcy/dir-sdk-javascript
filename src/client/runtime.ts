// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { createClient, type Transport } from '@connectrpc/connect';
import { createGrpcTransport } from '@connectrpc/connect-node';

import type { GetWorkloadRequest, ListWorkloadsRequest, Workload } from '../models/runtime_v1';
import * as runtime_v1 from '../models/runtime_v1';
import { RuntimeService } from './services/runtime.js';

/**
 * Client for the runtime discovery API (`agntcy.dir.runtime.v1.DiscoveryService`)
 * served by dir-runtime and `dirctl daemon`.
 *
 * dir-runtime runs at its own address (`localhost:8888` by default in
 * `dirctl daemon`), so this is separate from {@link Client}: the Directory's
 * credentials, such as the OIDC token, are never sent to it.
 *
 * @public
 */
export class RuntimeClient {
  readonly serverAddress: string;

  /** @internal */
  runtimeService: RuntimeService;

  /**
   * @param serverAddress - dir-runtime base URL, e.g. `http://localhost:8888`.
   * @param grpcTransport - optional transport override.
   */
  constructor(
    serverAddress: string = RuntimeClient.DEFAULT_SERVER_ADDRESS,
    grpcTransport?: Transport,
  ) {
    this.serverAddress = serverAddress;
    const transport = grpcTransport ?? createGrpcTransport({ baseUrl: serverAddress });
    this.runtimeService = new RuntimeService(createClient(runtime_v1.DiscoveryService, transport));
  }

  static readonly DEFAULT_SERVER_ADDRESS = 'http://localhost:8888';

  async getWorkload(request: GetWorkloadRequest): Promise<Workload> {
    return this.runtimeService.getWorkload(request);
  }

  async listWorkloads(request: ListWorkloadsRequest): Promise<Workload[]> {
    return this.runtimeService.listWorkloads(request);
  }
}
