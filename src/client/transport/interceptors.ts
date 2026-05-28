// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type { Interceptor } from '@connectrpc/connect';
import { createClient as createClientSpiffe } from 'spiffe';

import type { Config } from '../config.js';
import type { OAuthTokenHolder } from '../auth/oauthPkce.js';

export function createBearerAuthInterceptor(holder: OAuthTokenHolder): Interceptor {
  return (next) => async (req) => {
    req.header.set('authorization', `Bearer ${holder.getAccessToken()}`);
    return await next(req);
  };
}

export function createJwtAuthInterceptor(config: Config): Interceptor {
  if (config.spiffeEndpointSocket === '') {
    throw new Error('SPIFFE socket path is required for JWT authentication');
  }
  if (config.jwtAudience === '') {
    throw new Error('JWT audience is required for JWT authentication');
  }

  const client = createClientSpiffe(config.spiffeEndpointSocket);

  return (next) => async (req) => {
    const jwtCall = client.fetchJWTSVID({
      spiffeId: '',
      audience: [config.jwtAudience],
    });

    const response = await jwtCall.response;

    if (!response.svids || response.svids.length === 0) {
      throw new Error('Failed to fetch JWT-SVID from SPIRE: no SVIDs returned');
    }

    const jwtToken = response.svids[0].svid;
    req.header.set('authorization', `Bearer ${jwtToken}`);

    return await next(req);
  };
}
