// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Client } from '@connectrpc/connect';
import { create } from '@bufbuild/protobuf';

import * as models from '../../models/index.js';

/** The reported method for a record resolved through a verified owner claim. */
const OWNER_CLAIM_METHOD = 'owner-claim';

export class IdentityService {
  private readonly identityClient: Client<typeof models.identity_v1.IdentityService>;

  constructor(identityClient: Client<typeof models.identity_v1.IdentityService>) {
    this.identityClient = identityClient;
  }

  async resolve(
    request: models.identity_v1.ResolveRequest,
  ): Promise<models.identity_v1.ResolveResponse> {
    return await this.identityClient.resolve(request);
  }

  /**
   * getVerificationInfo reports whether a record has a verified owner,
   * projected from its ownership claim (identity.v1.GetIdentityStatus).
   */
  async getVerificationInfo(
    request: models.identity_v1.GetVerificationInfoRequest,
  ): Promise<models.identity_v1.GetVerificationInfoResponse> {
    const statusRequest = create(models.identity_v1.GetIdentityStatusRequestSchema, {
      cid: request.cid,
      name: request.name,
      version: request.version,
    });
    const status = await this.identityClient.getIdentityStatus(statusRequest);

    return verificationInfo(status);
  }
}

/** Projects the ownership claim result onto the legacy naming.v1 result shape. */
function verificationInfo(
  status: models.identity_v1.GetIdentityStatusResponse,
): models.identity_v1.GetVerificationInfoResponse {
  const owner = status.owner;
  if (owner === undefined) {
    return { verified: false, errorMessage: 'no verification found' };
  }

  if (owner.status !== models.identity_v1.ClaimVerificationStatus.VERIFIED) {
    return { verified: false, errorMessage: owner.error ?? 'verification failed' };
  }

  return {
    verified: true,
    verification: {
      domain: {
        domain: owner.subject,
        method: OWNER_CLAIM_METHOD,
        verifiedAt: owner.verifiedAt,
      },
    },
  };
}
