// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create } from '@bufbuild/protobuf';
import type { Client } from '@connectrpc/connect';

import * as models from '../../models/index.js';
import {
  PUBLIC_KEY_REFERRER_TYPE,
  SIGNATURE_REFERRER_TYPE,
  marshalPublicKeyReferrer,
  marshalSignatureReferrer,
  signBlobWithKey,
  signBlobWithOidc,
  unmarshalPublicKeyReferrer,
  unmarshalSignatureReferrer,
  verifyWithFetcher,
} from '../signing/index.js';
import type { StoreService } from './store.js';

export class SignService {
  private readonly signClient: Client<typeof models.sign_v1.SignService>;
  private readonly storeService: StoreService;

  constructor(signClient: Client<typeof models.sign_v1.SignService>, storeService: StoreService) {
    this.signClient = signClient;
    this.storeService = storeService;
  }

  /**
   * Signs a record locally with the requested provider (key or OIDC) and pushes the public
   * key and signature to the store as referrers.
   */
  async sign(req: models.sign_v1.SignRequest): Promise<models.sign_v1.SignResponse> {
    const provider = req.provider?.request;
    if (provider?.case === undefined) {
      throw new Error('signature provider must be specified');
    }

    const recordRef = req.recordRef;
    if (!recordRef?.cid) {
      throw new Error('record ref must be specified');
    }

    const payload = Buffer.from(recordRef.cid);
    let result: { signature: models.sign_v1.Signature; publicKey: models.sign_v1.PublicKey };

    try {
      switch (provider.case) {
        case 'key':
          result = await signBlobWithKey(payload, provider.value);
          break;
        case 'oidc':
          result = await signBlobWithOidc(payload, provider.value);
          break;
        default:
          throw new Error(`unsupported signature provider type: ${String(provider)}`);
      }
    } catch (e) {
      throw new Error(`failed to sign record: ${e}`, { cause: e });
    }

    try {
      await this.pushReferrers(recordRef, result.signature, result.publicKey);
    } catch (e) {
      throw new Error(`failed to push referrers to store: ${e}`, { cause: e });
    }

    return create(models.sign_v1.SignResponseSchema, { signature: result.signature });
  }

  /**
   * Verifies the signatures of a record. When `fromServer` is set, the cached server
   * verification result is returned, otherwise verification is performed locally.
   */
  async verify(request: models.sign_v1.VerifyRequest): Promise<models.sign_v1.VerifyResponse> {
    const recordRef = request.recordRef;
    if (!recordRef?.cid) {
      throw new Error(
        request.fromServer
          ? 'VerifyRequest.recordRef with cid is required'
          : 'record CID is required',
      );
    }

    if (request.fromServer) {
      return await this.signClient.verify(request);
    }

    try {
      await this.storeService.lookup([recordRef]);
    } catch (e) {
      if (String(e).includes('record not found')) {
        return create(models.sign_v1.VerifyResponseSchema, {
          success: false,
          errorMessage: 'record not found',
        });
      }
      throw new Error(`failed to lookup record: ${e}`, { cause: e });
    }

    return await verifyWithFetcher(request, this);
  }

  /** Fetches all signature referrers for a record. */
  async pullSignatures(recordRef: models.core_v1.RecordRef): Promise<models.sign_v1.Signature[]> {
    const responses = await this.pullReferrers(recordRef, SIGNATURE_REFERRER_TYPE);

    const signatures: models.sign_v1.Signature[] = [];
    for (const response of responses) {
      if (response.referrer === undefined) {
        continue;
      }
      try {
        signatures.push(unmarshalSignatureReferrer(response.referrer));
      } catch {
        continue; // Skip referrers that cannot be decoded
      }
    }
    return signatures;
  }

  /** Fetches all public key referrers for a record. */
  async pullPublicKeys(recordRef: models.core_v1.RecordRef): Promise<string[]> {
    const responses = await this.pullReferrers(recordRef, PUBLIC_KEY_REFERRER_TYPE);

    const publicKeys: string[] = [];
    for (const response of responses) {
      if (response.referrer === undefined) {
        continue;
      }
      try {
        const key = unmarshalPublicKeyReferrer(response.referrer).key;
        if (key !== '') {
          publicKeys.push(key);
        }
      } catch {
        continue; // Skip referrers that cannot be decoded
      }
    }
    return publicKeys;
  }

  private async pullReferrers(
    recordRef: models.core_v1.RecordRef,
    referrerType: string,
  ): Promise<models.store_v1.PullReferrerResponse[]> {
    try {
      return await this.storeService.pull_referrer([
        create(models.store_v1.PullReferrerRequestSchema, { recordRef, referrerType }),
      ]);
    } catch (e) {
      throw new Error(`failed to create pull referrer stream: ${e}`, { cause: e });
    }
  }

  private async pushReferrers(
    recordRef: models.core_v1.RecordRef,
    signature: models.sign_v1.Signature,
    publicKey: models.sign_v1.PublicKey,
  ): Promise<void> {
    // The public key is pushed first, then the signature (same order as the Go client).
    const publicKeyReferrer = marshalPublicKeyReferrer(publicKey);
    try {
      await this.pushReferrer(recordRef, publicKeyReferrer);
    } catch (e) {
      throw new Error(`failed to store public key: ${e}`, { cause: e });
    }

    const signatureReferrer = marshalSignatureReferrer(signature);
    try {
      await this.pushReferrer(recordRef, signatureReferrer);
    } catch (e) {
      throw new Error(`failed to store signature: ${e}`, { cause: e });
    }
  }

  private async pushReferrer(
    recordRef: models.core_v1.RecordRef,
    referrer: models.core_v1.RecordReferrer,
  ): Promise<void> {
    const responses = await this.storeService.push_referrer([
      create(models.store_v1.PushReferrerRequestSchema, {
        recordRef,
        type: referrer.type,
        annotations: referrer.annotations,
        createdAt: referrer.createdAt,
        data: referrer.data,
      }),
    ]);
    for (const response of responses) {
      if (!response.success) {
        throw new Error(response.errorMessage ?? 'push referrer failed');
      }
    }
  }
}
