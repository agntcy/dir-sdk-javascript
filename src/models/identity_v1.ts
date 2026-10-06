// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Timestamp } from '@bufbuild/protobuf/wkt';

export {
  file_agntcy_dir_identity_v1_identity_service,
  ClaimVerification,
  ClaimVerificationSchema,
  ClaimVerificationStatus,
  GetIdentityStatusRequest,
  GetIdentityStatusRequestSchema,
  GetIdentityStatusResponse,
  GetIdentityStatusResponseSchema,
  ResolveRequest,
  ResolveRequestSchema,
  ResolveResponse,
  ResolveResponseSchema,
  IdentityService,
} from '@buf/agntcy_dir.bufbuild_es/agntcy/dir/identity/v1/identity_service_pb';
export {
  file_agntcy_dir_identity_v1_claim,
  Claim,
  ClaimSchema,
  ClaimRole,
} from '@buf/agntcy_dir.bufbuild_es/agntcy/dir/identity/v1/claim_pb';
export type { Timestamp };

/**
 * GetVerificationInfoRequest looks up the ownership-claim verification
 * status of a record, either by CID or by name (with an optional version).
 *
 * @public
 */
export interface GetVerificationInfoRequest {
  cid?: string;
  name?: string;
  version?: string;
}

/**
 * DomainVerification describes the verified owner of a record's name.
 *
 * @public
 */
export interface DomainVerification {
  /** The verified owner subject. */
  domain: string;
  /** How the owner was verified. */
  method: string;
  /** When the owner was last verified. */
  verifiedAt?: Timestamp;
}

/**
 * Verification holds the details of a verified name.
 *
 * @public
 */
export interface Verification {
  domain?: DomainVerification;
}

/**
 * GetVerificationInfoResponse is the result of a name ownership lookup,
 * projected from the record's ownership claim (identity.v1).
 *
 * @public
 */
export interface GetVerificationInfoResponse {
  verified: boolean;
  verification?: Verification;
  errorMessage?: string;
}
