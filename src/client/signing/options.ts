// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create } from '@bufbuild/protobuf';

import * as models from '../../models/index.js';

export const DEFAULT_FULCIO_URL = 'https://fulcio.sigstore.dev';
export const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';
export const DEFAULT_TIMESTAMP_URL = 'https://timestamp.sigstore.dev/api/v1/timestamp';
export const DEFAULT_TUF_MIRROR_URL = 'https://tuf-repo-cdn.sigstore.dev';
export const DEFAULT_OIDC_PROVIDER_URL = 'https://oauth2.sigstore.dev/auth';
export const DEFAULT_OIDC_CLIENT_ID = 'sigstore';

export function getSignOptionsOidc(
  options: models.sign_v1.SignOptionsOIDC | undefined,
): models.sign_v1.SignOptionsOIDC {
  return create(models.sign_v1.SignOptionsOIDCSchema, {
    fulcioUrl: options?.fulcioUrl ?? DEFAULT_FULCIO_URL,
    rekorUrl: options?.rekorUrl ?? DEFAULT_REKOR_URL,
    timestampUrl: options?.timestampUrl ?? DEFAULT_TIMESTAMP_URL,
    skipTlog: options?.skipTlog ?? false,
    oidcProviderUrl: options?.oidcProviderUrl ?? DEFAULT_OIDC_PROVIDER_URL,
    oidcClientId: options?.oidcClientId ?? DEFAULT_OIDC_CLIENT_ID,
    oidcClientSecret: options?.oidcClientSecret ?? '',
  });
}

export function getVerifyOptionsOidc(
  options: models.sign_v1.VerifyOptionsOIDC | undefined,
): models.sign_v1.VerifyOptionsOIDC {
  return create(models.sign_v1.VerifyOptionsOIDCSchema, {
    tufMirrorUrl: options?.tufMirrorUrl ?? DEFAULT_TUF_MIRROR_URL,
    trustedRootPath: options?.trustedRootPath ?? '',
    ignoreTlog: options?.ignoreTlog ?? false,
    ignoreTsa: options?.ignoreTsa ?? false,
    ignoreSct: options?.ignoreSct ?? false,
  });
}
