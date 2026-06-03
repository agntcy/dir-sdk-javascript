// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import type * as http2 from 'node:http2';

import type { Transport } from '@connectrpc/connect';
import { createGrpcTransport as createConnectGrpcTransport } from '@connectrpc/connect-node';
import { createClient as createClientSpiffe, type X509SVID } from 'spiffe';

import type { Config } from '../config.js';
import type { OAuthTokenHolder } from '../auth/oauthPkce.js';
import { createBearerAuthInterceptor, createJwtAuthInterceptor } from './interceptors.js';

function convertToPEM(bytes: Uint8Array, label: string): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64String = btoa(binary);
  const lines = base64String.match(/.{1,64}/g) ?? [];
  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`].join('\n');
}

function secureNodeOptions(
  config: Config,
  base: http2.SecureClientSessionOptions,
): http2.SecureClientSessionOptions {
  const out: http2.SecureClientSessionOptions = { ...base };
  const sn = config.tlsServerName.trim();
  if (sn !== '') {
    out.servername = sn;
  }
  return out;
}

export function createOidcTransport(config: Config, holder: OAuthTokenHolder): Transport {
  let ca: string | undefined;
  if (config.tlsCaFile !== '') {
    try {
      ca = readFileSync(config.tlsCaFile).toString();
    } catch (e) {
      throw new Error(`Failed to read TLS CA file: ${(e as Error).message}`);
    }
  }
  const nodeBase: http2.SecureClientSessionOptions = {};
  if (ca !== undefined) {
    nodeBase.ca = ca;
  }
  return createConnectGrpcTransport({
    baseUrl: config.serverAddress,
    interceptors: [createBearerAuthInterceptor(holder)],
    nodeOptions: secureNodeOptions(config, nodeBase),
  });
}

async function createX509Transport(config: Config): Promise<Transport> {
  if (config.spiffeEndpointSocket === '') {
    throw new Error('SPIFFE socket path is required for X.509 authentication');
  }

  const client = createClientSpiffe(config.spiffeEndpointSocket);

  let svid: X509SVID = {
    spiffeId: '',
    hint: '',
    x509Svid: new Uint8Array(),
    x509SvidKey: new Uint8Array(),
    bundle: new Uint8Array(),
  };

  const svidStream = client.fetchX509SVID({});
  for await (const message of svidStream.responses) {
    message.svids.forEach((_svid) => {
      svid = _svid;
    });

    if (message.svids.length > 0) {
      break;
    }
  }

  return createConnectGrpcTransport({
    baseUrl: config.serverAddress,
    nodeOptions: secureNodeOptions(config, {
      ca: convertToPEM(svid.bundle, 'TRUSTED CERTIFICATE'),
      cert: convertToPEM(svid.x509Svid, 'CERTIFICATE'),
      key: convertToPEM(svid.x509SvidKey, 'PRIVATE KEY'),
    }),
  });
}

async function createJWTTransport(config: Config): Promise<Transport> {
  if (config.spiffeEndpointSocket === '') {
    throw new Error('SPIFFE socket path is required for JWT authentication');
  }

  const client = createClientSpiffe(config.spiffeEndpointSocket);

  let bundle: Uint8Array | null = null;
  const bundleStream = client.fetchX509Bundles({});
  for await (const message of bundleStream.responses) {
    for (const [, bundleData] of Object.entries(message.bundles)) {
      bundle = new Uint8Array(bundleData);
      break;
    }
    if (bundle !== null) {
      break;
    }
  }

  if (bundle === null || bundle.length === 0) {
    throw new Error('Failed to fetch X.509 bundle from SPIRE: no bundles returned');
  }

  return createConnectGrpcTransport({
    baseUrl: config.serverAddress,
    interceptors: [createJwtAuthInterceptor(config)],
    nodeOptions: secureNodeOptions(config, {
      ca: convertToPEM(bundle, 'CERTIFICATE'),
    }),
  });
}

async function createTLSTransport(config: Config): Promise<Transport> {
  if (config.tlsCaFile === '') {
    throw new Error('TLS CA file is required for TLS authentication');
  }
  if (config.tlsCertFile === '') {
    throw new Error('TLS certificate file is required for TLS authentication');
  }
  if (config.tlsKeyFile === '') {
    throw new Error('TLS key file is required for TLS authentication');
  }

  let root_ca: string;
  let cert_chain: string;
  let private_key: string;

  try {
    root_ca = readFileSync(config.tlsCaFile).toString();
    cert_chain = readFileSync(config.tlsCertFile).toString();
    private_key = readFileSync(config.tlsKeyFile).toString();
  } catch (e) {
    console.error('Error reading file:', (e as Error).message);
    throw e;
  }

  return createConnectGrpcTransport({
    baseUrl: config.serverAddress,
    nodeOptions: secureNodeOptions(config, {
      ca: root_ca,
      cert: cert_chain,
      key: private_key,
    }),
  });
}

export async function createGrpcTransport(
  config: Config,
  options?: { oidcTokenHolder?: OAuthTokenHolder },
): Promise<Transport> {
  switch (config.authMode) {
    case '':
      return createConnectGrpcTransport({
        baseUrl: config.serverAddress,
      });

    case 'jwt':
      return await createJWTTransport(config);

    case 'x509':
      return await createX509Transport(config);

    case 'tls':
      return await createTLSTransport(config);

    case 'oidc': {
      const holder = options?.oidcTokenHolder;
      if (holder === undefined) {
        throw new Error(
          'createGrpcTransport: authMode oidc requires options.oidcTokenHolder',
        );
      }
      return createOidcTransport(config, holder);
    }

    default:
      throw new Error(`Unsupported auth mode: ${config.authMode}`);
  }
}
