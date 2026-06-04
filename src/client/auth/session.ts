// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { Config } from '../config.js';
import { fetchOpenidConfiguration, OAuthTokenHolder, runLoopbackPkceLogin } from './oauthPkce.js';
import { CachedToken, TokenCache } from './tokenCache.js';

export function cachedTokenFromResponse(
  config: Config,
  payload: Record<string, unknown>,
): CachedToken {
  const expiresIn = payload.expires_in;
  let expiresAt: Date | undefined;
  if (typeof expiresIn === 'number' && Number.isFinite(expiresIn)) {
    expiresAt = new Date(Date.now() + expiresIn * 1000);
  } else if (typeof expiresIn === 'string' && expiresIn !== '') {
    const n = Number(expiresIn);
    if (Number.isFinite(n)) {
      expiresAt = new Date(Date.now() + n * 1000);
    }
  }
  const refreshToken = payload.refresh_token;
  const tokenType = payload.token_type;
  return new CachedToken(
    String(payload.access_token),
    typeof tokenType === 'string' ? tokenType : '',
    'oidc',
    config.oidcIssuer,
    typeof refreshToken === 'string' ? refreshToken : '',
    expiresAt,
    '',
    '',
    '',
    new Date(),
  );
}

/**
 * Coordinates OIDC token state with interactive PKCE flow and cache.
 *
 * @public
 */
export class OAuthSessionManager {
  readonly config: Config;
  private readonly tokenCache: TokenCache;
  private _oauthHolder: OAuthTokenHolder | null = null;

  constructor(config: Config) {
    this.config = config;
    this.tokenCache = new TokenCache();

    if (this.config.authMode === 'oidc') {
      this._oauthHolder = new OAuthTokenHolder();
      if (this.config.authToken) {
        this._oauthHolder.setTokens(this.config.authToken);
      } else {
        const cachedToken = this.tokenCache.getValidToken();
        if (cachedToken !== undefined) {
          this._oauthHolder.setTokens(cachedToken.accessToken);
        }
      }
    }
  }

  get oauthHolder(): OAuthTokenHolder | null {
    return this._oauthHolder;
  }

  hasAccessToken(): boolean {
    if (this._oauthHolder === null) {
      return false;
    }
    try {
      this._oauthHolder.getAccessToken();
      return true;
    } catch {
      return false;
    }
  }

  async authenticate(): Promise<void> {
    if (this.config.authMode !== 'oidc') {
      throw new Error("authenticateOAuthPkce() requires authMode='oidc'");
    }
    if (this.config.oidcIssuer === '') {
      throw new Error('oidc_issuer is required for authenticateOAuthPkce()');
    }
    if (this.config.oidcClientId === '') {
      throw new Error('oidc_client_id is required for authenticateOAuthPkce()');
    }
    if (this._oauthHolder === null) {
      throw new Error('OAuth token holder not initialized');
    }
    const verify = !this.config.tlsSkipVerify;
    const timeoutMs = Math.min(30_000, this.config.oidcAuthTimeout * 1000);
    const meta = await fetchOpenidConfiguration(this.config.oidcIssuer, {
      verify,
      timeoutMs,
    });
    const payload = await runLoopbackPkceLogin(this.config, meta, {
      verify,
      timeoutMs: this.config.oidcAuthTimeout * 1000,
    });
    this._oauthHolder.updateFromTokenResponse(payload);
    this.tokenCache.save(cachedTokenFromResponse(this.config, payload));
    console.log('Authenticated with OAuth PKCE');
    console.log('Access token acquired.');
  }
}
