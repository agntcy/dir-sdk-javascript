// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create } from '@bufbuild/protobuf';

import * as models from '../../models/index.js';

/** Returns the value unless it is empty (proto3 zero value), in which case the default is used. */
function orDefault(value: string | undefined, defaultValue: string): string {
  return value !== undefined && value !== '' ? value : defaultValue;
}

export const DEFAULT_FULCIO_URL = 'https://fulcio.sigstore.dev';
export const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';
export const DEFAULT_TIMESTAMP_URL = 'https://timestamp.sigstore.dev/api/v1/timestamp';
export const DEFAULT_TUF_MIRROR_URL = 'https://tuf-repo-cdn.sigstore.dev';
export const DEFAULT_OIDC_PROVIDER_URL = 'https://oauth2.sigstore.dev/auth';
export const DEFAULT_OIDC_CLIENT_ID = 'sigstore';

/** Returns SignOptionsOIDC with defaults applied for empty fields. */
export function getDefaultSignOptions(
  options?: models.sign_v1.SignOptionsOIDC,
): models.sign_v1.SignOptionsOIDC {
  return create(models.sign_v1.SignOptionsOIDCSchema, {
    fulcioUrl: orDefault(options?.fulcioUrl, DEFAULT_FULCIO_URL),
    rekorUrl: orDefault(options?.rekorUrl, DEFAULT_REKOR_URL),
    timestampUrl: orDefault(options?.timestampUrl, DEFAULT_TIMESTAMP_URL),
    skipTlog: options?.skipTlog ?? false,
    oidcProviderUrl: orDefault(options?.oidcProviderUrl, DEFAULT_OIDC_PROVIDER_URL),
    oidcClientId: orDefault(options?.oidcClientId, DEFAULT_OIDC_CLIENT_ID),
    oidcClientSecret: options?.oidcClientSecret ?? '',
  });
}

/** Returns VerifyOptionsOIDC with defaults applied for empty fields. */
export function getDefaultVerifyOptions(
  options?: models.sign_v1.VerifyOptionsOIDC,
): models.sign_v1.VerifyOptionsOIDC {
  return create(models.sign_v1.VerifyOptionsOIDCSchema, {
    tufMirrorUrl: orDefault(options?.tufMirrorUrl, DEFAULT_TUF_MIRROR_URL),
    trustedRootPath: options?.trustedRootPath ?? '',
    ignoreTlog: options?.ignoreTlog ?? false,
    ignoreTsa: options?.ignoreTsa ?? false,
    ignoreSct: options?.ignoreSct ?? false,
  });
}
