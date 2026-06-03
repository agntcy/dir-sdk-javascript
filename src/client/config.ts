// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { existsSync } from 'node:fs';
import { env } from 'node:process';

export type AuthMode = '' | 'x509' | 'jwt' | 'tls' | 'oidc';

function parseBoolEnv(value: string | undefined, defaultVal: boolean): boolean {
  if (value === undefined || value === '') {
    return defaultVal;
  }
  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function parseIntEnv(value: string | undefined, defaultVal: number): number {
  if (value === undefined || value === '') {
    return defaultVal;
  }
  return Number.parseInt(value, 10);
}

function parseFloatEnv(value: string | undefined, defaultVal: number): number {
  if (value === undefined || value === '') {
    return defaultVal;
  }
  return Number.parseFloat(value);
}

function parseCommaScopes(value: string | undefined, defaultList: string[]): string[] {
  if (value === undefined || value === '') {
    return [...defaultList];
  }
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export class DockerConfig {
  static DEFAULT_DIRCTL_IMAGE = 'ghcr.io/agntcy/dir-ctl';
  static DEFAULT_DIRCTL_IMAGE_TAG = 'latest';

  dirctlImage: string;
  dirctlImageTag: string;
  envs: Map<string, string>;
  mounts: string[];
  user: string;

  constructor(
    dirctlImage: string,
    dirctlImageTag: string,
    envs: Map<string, string>,
    mounts: string[],
    user: string,
  ) {
    this.dirctlImage = dirctlImage;
    this.dirctlImageTag = dirctlImageTag;
    this.envs = envs;
    this.mounts = mounts;
    this.user = user;
  }

  getDockerArgs(): string[] {
    this.pruneMounts();
    const commands = ['container', 'run', '--name=dir-ctl', '--rm', '--network', 'host'];
    if (this.user) {
      commands.push('--user');
      commands.push(this.user);
    }
    this.envs.forEach((value: string, key: string) => {
      commands.push('--env');
      commands.push(`${key}=${value}`);
    });
    this.mounts.forEach((value: string) => {
      commands.push('--mount');
      commands.push(value);
    });
    commands.push(`${this.dirctlImage}:${this.dirctlImageTag}`);
    return commands;
  }

  pruneMounts(): void {
    this.mounts = this.mounts.filter((mount: string) => {
      if (mount.startsWith('type=bind')) {
        const parts = mount.split(',');
        const srcPart = parts.find((p) => p.startsWith('src='));
        if (srcPart === undefined) {
          return false;
        }
        const _src = srcPart.split('=')[1];
        return existsSync(_src);
      }
      return false;
    });
  }
}

/**
 * Configuration class for the AGNTCY Directory client.
 */
export class Config {
  static DEFAULT_SERVER_ADDRESS = '127.0.0.1:8888';
  static DEFAULT_DIRCTL_PATH = 'dirctl';
  static DEFAULT_SPIFFE_ENDPOINT_SOCKET = '';
  static DEFAULT_AUTH_MODE = '';
  static DEFAULT_AUTH_TOKEN = '';
  static DEFAULT_JWT_AUDIENCE = '';
  static DEFAULT_TLS_CA_FILE = '';
  static DEFAULT_TLS_CERT_FILE = '';
  static DEFAULT_TLS_KEY_FILE = '';
  static DEFAULT_TLS_SERVER_NAME = '';
  static DEFAULT_TLS_SKIP_VERIFY = false;
  static DEFAULT_OIDC_ISSUER = '';
  static DEFAULT_OIDC_CLIENT_ID = '';
  static DEFAULT_OIDC_CLIENT_SECRET = '';
  static DEFAULT_OIDC_REDIRECT_URI = 'http://localhost:8484/callback';
  static DEFAULT_OIDC_CALLBACK_PORT = 8484;
  static DEFAULT_OIDC_AUTH_TIMEOUT = 300;
  static DEFAULT_OIDC_SCOPES = ['openid', 'profile', 'email'];

  serverAddress: string;
  dirctlPath: string;
  spiffeEndpointSocket: string;
  authMode: AuthMode;
  authToken: string;
  /** Backward-compatible alias for `authToken`. */
  oidcAccessToken: string;
  jwtAudience: string;
  tlsCaFile: string;
  tlsCertFile: string;
  tlsKeyFile: string;
  tlsServerName: string;
  tlsSkipVerify: boolean;
  oidcIssuer: string;
  oidcClientId: string;
  oidcClientSecret: string;
  oidcRedirectUri: string;
  oidcCallbackPort: number;
  oidcAuthTimeout: number;
  oidcScopes: string[];
  dockerConfig: DockerConfig | undefined;

  constructor(
    serverAddress = Config.DEFAULT_SERVER_ADDRESS,
    dirctlPath = Config.DEFAULT_DIRCTL_PATH,
    spiffeEndpointSocket = Config.DEFAULT_SPIFFE_ENDPOINT_SOCKET,
    authMode: AuthMode = Config.DEFAULT_AUTH_MODE as AuthMode,
    jwtAudience = Config.DEFAULT_JWT_AUDIENCE,
    tlsCaFile = Config.DEFAULT_TLS_CA_FILE,
    tlsCertFile = Config.DEFAULT_TLS_CERT_FILE,
    tlsKeyFile = Config.DEFAULT_TLS_KEY_FILE,
    authToken = Config.DEFAULT_AUTH_TOKEN,
    tlsServerName = Config.DEFAULT_TLS_SERVER_NAME,
    tlsSkipVerify = Config.DEFAULT_TLS_SKIP_VERIFY,
    oidcIssuer = Config.DEFAULT_OIDC_ISSUER,
    oidcClientId = Config.DEFAULT_OIDC_CLIENT_ID,
    oidcClientSecret = Config.DEFAULT_OIDC_CLIENT_SECRET,
    oidcRedirectUri = Config.DEFAULT_OIDC_REDIRECT_URI,
    oidcCallbackPort = Config.DEFAULT_OIDC_CALLBACK_PORT,
    oidcAuthTimeout = Config.DEFAULT_OIDC_AUTH_TIMEOUT,
    oidcScopes: string[] | undefined = undefined,
    oidcAccessToken: string | undefined = undefined,
    dockerConfig: DockerConfig | undefined = undefined,
  ) {
    const resolvedAuthToken = [authToken, oidcAccessToken].find(Boolean) ?? '';

    if (
      !serverAddress.startsWith('http://') &&
      !serverAddress.startsWith('https://')
    ) {
      if (
        authMode === 'x509' ||
        authMode === 'jwt' ||
        authMode === 'tls' ||
        authMode === 'oidc'
      ) {
        serverAddress = `https://${serverAddress}`;
      } else {
        serverAddress = `http://${serverAddress}`;
      }
    }

    this.serverAddress = serverAddress;
    this.dirctlPath = dirctlPath;
    this.spiffeEndpointSocket = spiffeEndpointSocket;
    this.authMode = authMode;
    this.authToken = resolvedAuthToken;
    this.oidcAccessToken = resolvedAuthToken;
    this.jwtAudience = jwtAudience;
    this.tlsCaFile = tlsCaFile;
    this.tlsCertFile = tlsCertFile;
    this.tlsKeyFile = tlsKeyFile;
    this.tlsServerName = tlsServerName;
    this.tlsSkipVerify = tlsSkipVerify;
    this.oidcIssuer = oidcIssuer;
    this.oidcClientId = oidcClientId;
    this.oidcClientSecret = oidcClientSecret;
    this.oidcRedirectUri = oidcRedirectUri;
    this.oidcCallbackPort = oidcCallbackPort;
    this.oidcAuthTimeout = oidcAuthTimeout;
    this.oidcScopes =
      oidcScopes !== undefined ? [...oidcScopes] : [...Config.DEFAULT_OIDC_SCOPES];
    this.dockerConfig = dockerConfig;
  }

  static loadFromEnv(prefix = 'DIRECTORY_CLIENT_') {
    const dirctlPath = env.DIRCTL_PATH ?? Config.DEFAULT_DIRCTL_PATH;

    const serverAddress =
      env[`${prefix}SERVER_ADDRESS`] ?? Config.DEFAULT_SERVER_ADDRESS;
    const spiffeEndpointSocketPath =
      env[`${prefix}SPIFFE_SOCKET_PATH`] ?? Config.DEFAULT_SPIFFE_ENDPOINT_SOCKET;
    const authMode = (env[`${prefix}AUTH_MODE`] ?? Config.DEFAULT_AUTH_MODE) as AuthMode;
    const authToken = env[`${prefix}AUTH_TOKEN`] ?? Config.DEFAULT_AUTH_TOKEN;
    const jwtAudience = env[`${prefix}JWT_AUDIENCE`] ?? Config.DEFAULT_JWT_AUDIENCE;
    const tlsCaFile = env[`${prefix}TLS_CA_FILE`] ?? Config.DEFAULT_TLS_CA_FILE;
    const tlsCertFile = env[`${prefix}TLS_CERT_FILE`] ?? Config.DEFAULT_TLS_CERT_FILE;
    const tlsKeyFile = env[`${prefix}TLS_KEY_FILE`] ?? Config.DEFAULT_TLS_KEY_FILE;
    const tlsServerName =
      env[`${prefix}TLS_SERVER_NAME`] ?? Config.DEFAULT_TLS_SERVER_NAME;
    const tlsSkipVerify = parseBoolEnv(
      env[`${prefix}TLS_SKIP_VERIFY`],
      Config.DEFAULT_TLS_SKIP_VERIFY,
    );
    const oidcIssuer = env[`${prefix}OIDC_ISSUER`] ?? Config.DEFAULT_OIDC_ISSUER;
    const oidcClientId =
      env[`${prefix}OIDC_CLIENT_ID`] ?? Config.DEFAULT_OIDC_CLIENT_ID;
    const oidcClientSecret =
      env[`${prefix}OIDC_CLIENT_SECRET`] ?? Config.DEFAULT_OIDC_CLIENT_SECRET;
    const oidcRedirectUri =
      env[`${prefix}OIDC_REDIRECT_URI`] ?? Config.DEFAULT_OIDC_REDIRECT_URI;
    const oidcCallbackPort = parseIntEnv(
      env[`${prefix}OIDC_CALLBACK_PORT`],
      Config.DEFAULT_OIDC_CALLBACK_PORT,
    );
    const oidcAuthTimeout = parseFloatEnv(
      env[`${prefix}OIDC_AUTH_TIMEOUT`],
      Config.DEFAULT_OIDC_AUTH_TIMEOUT,
    );
    const oidcScopes = parseCommaScopes(
      env[`${prefix}OIDC_SCOPES`],
      Config.DEFAULT_OIDC_SCOPES,
    );

    let dockerConfig: DockerConfig | undefined = undefined;
    const dirctlImage = env.DIRCTL_IMAGE;
    const dirctlImageTag = env.DIRCTL_IMAGE_TAG;
    if (dirctlImage || dirctlImageTag) {
      dockerConfig = new DockerConfig(
        dirctlImage ?? DockerConfig.DEFAULT_DIRCTL_IMAGE,
        dirctlImageTag ?? DockerConfig.DEFAULT_DIRCTL_IMAGE_TAG,
        new Map<string, string>(),
        [],
        '0:0',
      );
    }

    return new Config(
      serverAddress,
      dirctlPath,
      spiffeEndpointSocketPath,
      authMode,
      jwtAudience,
      tlsCaFile,
      tlsCertFile,
      tlsKeyFile,
      authToken,
      tlsServerName,
      tlsSkipVerify,
      oidcIssuer,
      oidcClientId,
      oidcClientSecret,
      oidcRedirectUri,
      oidcCallbackPort,
      oidcAuthTimeout,
      oidcScopes,
      undefined,
      dockerConfig,
    );
  }

  getCommandAndArgs(args: string[]): [string, string[]] {
    if (this.dockerConfig) {
      const dockerArgs = this.dockerConfig.getDockerArgs();
      return ['docker', dockerArgs.concat(args)];
    }
    return [`${this.dirctlPath}`, args];
  }
}
