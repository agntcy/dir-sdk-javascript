// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import {
  Client as GrpcClient,
  createClient,
  type Transport,
} from '@connectrpc/connect';
import { createGrpcTransport as createConnectGrpcTransport } from '@connectrpc/connect-node';

import * as models from '../models/index.js';
import { OAuthSessionManager } from './auth/session.js';
import { Config } from './config.js';
import {
  EventService,
  NamingService,
  PublicationService,
  RoutingService,
  SearchService,
  SignService,
  StoreService,
  SyncService,
} from './services/index.js';
import { createGrpcTransport, createOidcTransport } from './transport/channels.js';
import type { OAuthTokenHolder } from './auth/oauthPkce.js';

/**
 * High-level client for interacting with AGNTCY Directory services.
 */
export class Client {
  config: Config;
  readonly oauthSession: OAuthSessionManager;

  storeClient: GrpcClient<typeof models.store_v1.StoreService>;
  routingClient: GrpcClient<typeof models.routing_v1.RoutingService>;
  publicationClient: GrpcClient<typeof models.routing_v1.PublicationService>;
  searchClient: GrpcClient<typeof models.search_v1.SearchService>;
  signClient: GrpcClient<typeof models.sign_v1.SignService>;
  syncClient: GrpcClient<typeof models.store_v1.SyncService>;
  eventClient: GrpcClient<typeof models.events_v1.EventService>;
  namingClient: GrpcClient<typeof models.naming_v1.NamingService>;

  storeService: StoreService;
  routingService: RoutingService;
  publicationService: PublicationService;
  searchService: SearchService;
  signService: SignService;
  syncService: SyncService;
  eventService: EventService;
  namingService: NamingService;

  constructor(config?: Config, grpcTransport?: Transport) {
    const resolvedConfig = config ?? Config.loadFromEnv();
    this.config = resolvedConfig;
    this.oauthSession = new OAuthSessionManager(resolvedConfig);

    let transport = grpcTransport;
    if (transport === undefined) {
      if (resolvedConfig.authMode === 'oidc') {
        const holder = this.oauthSession.oauthHolder;
        if (holder === null) {
          throw new Error('OAuth token holder not initialized');
        }
        transport = createOidcTransport(resolvedConfig, holder);
      } else {
        transport = createConnectGrpcTransport({
          baseUrl: resolvedConfig.serverAddress,
        });
      }
    }

    this.storeClient = createClient(models.store_v1.StoreService, transport);
    this.routingClient = createClient(models.routing_v1.RoutingService, transport);
    this.publicationClient = createClient(models.routing_v1.PublicationService, transport);
    this.searchClient = createClient(models.search_v1.SearchService, transport);
    this.signClient = createClient(models.sign_v1.SignService, transport);
    this.syncClient = createClient(models.store_v1.SyncService, transport);
    this.eventClient = createClient(models.events_v1.EventService, transport);
    this.namingClient = createClient(models.naming_v1.NamingService, transport);

    this.storeService = new StoreService(this.storeClient);
    this.routingService = new RoutingService(this.routingClient);
    this.publicationService = new PublicationService(this.publicationClient);
    this.searchService = new SearchService(this.searchClient);
    this.signService = new SignService(resolvedConfig, this.signClient);
    this.syncService = new SyncService(this.syncClient);
    this.eventService = new EventService(this.eventClient);
    this.namingService = new NamingService(this.namingClient);
  }

  static async createGRPCTransport(
    config: Config,
    options?: { oidcTokenHolder?: OAuthTokenHolder },
  ): Promise<Transport> {
    return createGrpcTransport(config, {
      oidcTokenHolder: options?.oidcTokenHolder,
    });
  }

  hasCachedOAuthToken(): boolean {
    return this.oauthSession.hasAccessToken();
  }

  getAccessToken(): string {
    const holder = this.oauthSession.oauthHolder;
    if (holder === null) {
      throw new Error('OAuth token holder not initialized');
    }
    return holder.getAccessToken();
  }

  async authenticateOAuthPkce(): Promise<void> {
    await this.oauthSession.authenticate();
  }

  async push(
    records: models.core_v1.Record[],
  ): Promise<models.core_v1.RecordRef[]> {
    return this.storeService.push(records);
  }

  async push_referrer(
    requests: models.store_v1.PushReferrerRequest[],
  ): Promise<models.store_v1.PushReferrerResponse[]> {
    return this.storeService.push_referrer(requests);
  }

  async pull(refs: models.core_v1.RecordRef[]): Promise<models.core_v1.Record[]> {
    return this.storeService.pull(refs);
  }

  async pull_referrer(
    requests: models.store_v1.PullReferrerRequest[],
  ): Promise<models.store_v1.PullReferrerResponse[]> {
    return this.storeService.pull_referrer(requests);
  }

  async searchCIDs(
    request: models.search_v1.SearchCIDsRequest,
  ): Promise<models.search_v1.SearchCIDsResponse[]> {
    return this.searchService.searchCIDs(request);
  }

  async searchRecords(
    request: models.search_v1.SearchRecordsRequest,
  ): Promise<models.search_v1.SearchRecordsResponse[]> {
    return this.searchService.searchRecords(request);
  }

  async lookup(refs: models.core_v1.RecordRef[]): Promise<models.core_v1.RecordMeta[]> {
    return this.storeService.lookup(refs);
  }

  async list(
    request: models.routing_v1.ListRequest,
  ): Promise<models.routing_v1.ListResponse[]> {
    return this.routingService.list(request);
  }

  async publish(request: models.routing_v1.PublishRequest): Promise<void> {
    return this.routingService.publish(request);
  }

  async unpublish(request: models.routing_v1.UnpublishRequest): Promise<void> {
    return this.routingService.unpublish(request);
  }

  async delete(refs: models.core_v1.RecordRef[]): Promise<void> {
    return this.storeService.delete(refs);
  }

  sign(req: models.sign_v1.SignRequest): void {
    this.signService.sign(req);
  }

  async verify(
    request: models.sign_v1.VerifyRequest,
  ): Promise<models.sign_v1.VerifyResponse> {
    return this.signService.verify(request);
  }

  async create_sync(
    request: models.store_v1.CreateSyncRequest,
  ): Promise<models.store_v1.CreateSyncResponse> {
    return this.syncService.create_sync(request);
  }

  async list_syncs(
    request: models.store_v1.ListSyncsRequest,
  ): Promise<models.store_v1.ListSyncsItem[]> {
    return this.syncService.list_syncs(request);
  }

  async get_sync(
    request: models.store_v1.GetSyncRequest,
  ): Promise<models.store_v1.GetSyncResponse> {
    return this.syncService.get_sync(request);
  }

  async delete_sync(
    request: models.store_v1.DeleteSyncRequest,
  ): Promise<models.store_v1.DeleteSyncResponse> {
    return this.syncService.delete_sync(request);
  }

  listen(
    request: models.events_v1.ListenRequest,
  ): AsyncIterable<models.events_v1.ListenResponse> {
    return this.eventService.listen(request);
  }

  async create_publication(
    request: models.routing_v1.PublishRequest,
  ): Promise<models.routing_v1.CreatePublicationResponse> {
    return this.publicationService.create_publication(request);
  }

  async list_publication(
    request: models.routing_v1.ListPublicationsRequest,
  ): Promise<models.routing_v1.ListPublicationsItem[]> {
    return this.publicationService.list_publication(request);
  }

  async get_publication(
    request: models.routing_v1.GetPublicationRequest,
  ): Promise<models.routing_v1.GetPublicationResponse> {
    return this.publicationService.get_publication(request);
  }

  async resolve(
    request: models.naming_v1.ResolveRequest,
  ): Promise<models.naming_v1.ResolveResponse> {
    return this.namingService.resolve(request);
  }

  async getVerificationInfo(
    request: models.naming_v1.GetVerificationInfoRequest,
  ): Promise<models.naming_v1.GetVerificationInfoResponse> {
    return this.namingService.getVerificationInfo(request);
  }
}
