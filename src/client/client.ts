// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { Client as GrpcClient, createClient, type Transport } from '@connectrpc/connect';
import { createGrpcTransport as createConnectGrpcTransport } from '@connectrpc/connect-node';

import type {
  ExportAgentRequest,
  GetAgentRequest,
  GetAgentResponse,
  GetWellKnownCatalogRequest,
  GetWellKnownCatalogResponse,
  HttpBody,
  ListAgentsRequest,
  ListAgentsResponse,
} from '../models/catalog_v1';
import type { Record, RecordMeta, RecordRef } from '../models/core_v1';
import type { ListenRequest, ListenResponse } from '../models/events_v1';
import type {
  GetVerificationInfoRequest,
  GetVerificationInfoResponse,
  ResolveRequest,
  ResolveResponse,
} from '../models/naming_v1';
import type {
  CreatePublicationResponse,
  GetPublicationRequest,
  GetPublicationResponse,
  ListPublicationsItem,
  ListPublicationsRequest,
  ListRequest,
  ListResponse,
  PublishRequest,
  SearchRequest,
  SearchResponse,
  UnpublishRequest,
} from '../models/routing_v1';
import type {
  SearchCIDsRequest,
  SearchCIDsResponse,
  SearchRecordsRequest,
  SearchRecordsResponse,
} from '../models/search_v1';
import type { SignRequest, VerifyRequest, VerifyResponse } from '../models/sign_v1';
import type {
  CreateSyncRequest,
  CreateSyncResponse,
  DeleteReferrerRequest,
  DeleteReferrerResponse,
  DeleteSyncRequest,
  DeleteSyncResponse,
  GetSyncRequest,
  GetSyncResponse,
  ListSyncsItem,
  ListSyncsRequest,
  PullReferrerRequest,
  PullReferrerResponse,
  PushReferrerRequest,
  PushReferrerResponse,
} from '../models/store_v1';
import * as catalog_v1 from '../models/catalog_v1';
import * as events_v1 from '../models/events_v1';
import * as naming_v1 from '../models/naming_v1';
import * as routing_v1 from '../models/routing_v1';
import * as search_v1 from '../models/search_v1';
import * as sign_v1 from '../models/sign_v1';
import * as store_v1 from '../models/store_v1';
import { OAuthSessionManager } from './auth/session.js';
import { Config } from './config.js';
import {
  AIFinderService,
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
 *
 * @public
 */
export class Client {
  config: Config;
  readonly oauthSession: OAuthSessionManager;

  /** @internal */
  storeClient: GrpcClient<typeof store_v1.StoreService>;
  /** @internal */
  routingClient: GrpcClient<typeof routing_v1.RoutingService>;
  /** @internal */
  publicationClient: GrpcClient<typeof routing_v1.PublicationService>;
  /** @internal */
  searchClient: GrpcClient<typeof search_v1.SearchService>;
  /** @internal */
  signClient: GrpcClient<typeof sign_v1.SignService>;
  /** @internal */
  syncClient: GrpcClient<typeof store_v1.SyncService>;
  /** @internal */
  eventClient: GrpcClient<typeof events_v1.EventService>;
  /** @internal */
  namingClient: GrpcClient<typeof naming_v1.NamingService>;
  /** @internal */
  aiFinderClient: GrpcClient<typeof catalog_v1.AIFinderService>;

  /** @internal */
  storeService: StoreService;
  /** @internal */
  routingService: RoutingService;
  /** @internal */
  publicationService: PublicationService;
  /** @internal */
  searchService: SearchService;
  /** @internal */
  signService: SignService;
  /** @internal */
  syncService: SyncService;
  /** @internal */
  eventService: EventService;
  /** @internal */
  namingService: NamingService;
  /** @internal */
  aiFinderService: AIFinderService;

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

    this.storeClient = createClient(store_v1.StoreService, transport);
    this.routingClient = createClient(routing_v1.RoutingService, transport);
    this.publicationClient = createClient(routing_v1.PublicationService, transport);
    this.searchClient = createClient(search_v1.SearchService, transport);
    this.signClient = createClient(sign_v1.SignService, transport);
    this.syncClient = createClient(store_v1.SyncService, transport);
    this.eventClient = createClient(events_v1.EventService, transport);
    this.namingClient = createClient(naming_v1.NamingService, transport);
    this.aiFinderClient = createClient(catalog_v1.AIFinderService, transport);

    this.storeService = new StoreService(this.storeClient);
    this.routingService = new RoutingService(this.routingClient);
    this.publicationService = new PublicationService(this.publicationClient);
    this.searchService = new SearchService(this.searchClient);
    this.signService = new SignService(resolvedConfig, this.signClient);
    this.syncService = new SyncService(this.syncClient);
    this.eventService = new EventService(this.eventClient);
    this.namingService = new NamingService(this.namingClient);
    this.aiFinderService = new AIFinderService(this.aiFinderClient);
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

  async push(records: Record[]): Promise<RecordRef[]> {
    return this.storeService.push(records);
  }

  async push_referrer(requests: PushReferrerRequest[]): Promise<PushReferrerResponse[]> {
    return this.storeService.push_referrer(requests);
  }

  async pull(refs: RecordRef[]): Promise<Record[]> {
    return this.storeService.pull(refs);
  }

  async pull_referrer(requests: PullReferrerRequest[]): Promise<PullReferrerResponse[]> {
    return this.storeService.pull_referrer(requests);
  }

  async searchCIDs(request: SearchCIDsRequest): Promise<SearchCIDsResponse[]> {
    return this.searchService.searchCIDs(request);
  }

  async searchRecords(request: SearchRecordsRequest): Promise<SearchRecordsResponse[]> {
    return this.searchService.searchRecords(request);
  }

  async lookup(refs: RecordRef[]): Promise<RecordMeta[]> {
    return this.storeService.lookup(refs);
  }

  async list(request: ListRequest): Promise<ListResponse[]> {
    return this.routingService.list(request);
  }

  async searchRouting(request: SearchRequest): Promise<SearchResponse[]> {
    return this.routingService.searchRouting(request);
  }

  async publish(request: PublishRequest): Promise<void> {
    return this.routingService.publish(request);
  }

  async unpublish(request: UnpublishRequest): Promise<void> {
    return this.routingService.unpublish(request);
  }

  async delete(refs: RecordRef[]): Promise<void> {
    return this.storeService.delete(refs);
  }

  async deleteReferrer(request: DeleteReferrerRequest): Promise<DeleteReferrerResponse> {
    return this.storeService.deleteReferrer(request);
  }

  sign(req: SignRequest): void {
    this.signService.sign(req);
  }

  async verify(request: VerifyRequest): Promise<VerifyResponse> {
    return this.signService.verify(request);
  }

  async create_sync(request: CreateSyncRequest): Promise<CreateSyncResponse> {
    return this.syncService.create_sync(request);
  }

  async list_syncs(request: ListSyncsRequest): Promise<ListSyncsItem[]> {
    return this.syncService.list_syncs(request);
  }

  async get_sync(request: GetSyncRequest): Promise<GetSyncResponse> {
    return this.syncService.get_sync(request);
  }

  async delete_sync(request: DeleteSyncRequest): Promise<DeleteSyncResponse> {
    return this.syncService.delete_sync(request);
  }

  listen(request: ListenRequest): AsyncIterable<ListenResponse> {
    return this.eventService.listen(request);
  }

  async create_publication(request: PublishRequest): Promise<CreatePublicationResponse> {
    return this.publicationService.create_publication(request);
  }

  async list_publication(request: ListPublicationsRequest): Promise<ListPublicationsItem[]> {
    return this.publicationService.list_publication(request);
  }

  async get_publication(request: GetPublicationRequest): Promise<GetPublicationResponse> {
    return this.publicationService.get_publication(request);
  }

  async resolve(request: ResolveRequest): Promise<ResolveResponse> {
    return this.namingService.resolve(request);
  }

  async getVerificationInfo(
    request: GetVerificationInfoRequest,
  ): Promise<GetVerificationInfoResponse> {
    return this.namingService.getVerificationInfo(request);
  }

  async listAgents(request: ListAgentsRequest): Promise<ListAgentsResponse> {
    return this.aiFinderService.listAgents(request);
  }

  async getAgent(request: GetAgentRequest): Promise<GetAgentResponse> {
    return this.aiFinderService.getAgent(request);
  }

  async exportAgent(request: ExportAgentRequest): Promise<HttpBody> {
    return this.aiFinderService.exportAgent(request);
  }

  async getWellKnownCatalog(
    request: GetWellKnownCatalogRequest,
  ): Promise<GetWellKnownCatalogResponse> {
    return this.aiFinderService.getWellKnownCatalog(request);
  }
}
