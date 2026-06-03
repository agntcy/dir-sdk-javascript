// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { env } from 'node:process';

import type { Config } from '../config.js';
import * as models from '../../models/index.js';

export function signWithKey(
  config: Config,
  cid: string,
  req: models.sign_v1.SignWithKey,
): SpawnSyncReturns<string> {
  // NOTE: dirctl appends :80 or :443 to server address if has http or https:// prefix
  const dirctlServerAddress = config.serverAddress.replace(/^https?:\/\//, '');

  const shell_env = { ...env };
  shell_env.COSIGN_PASSWORD = req.password ? String(req.password) : '';
  if (config.dockerConfig) {
    config.dockerConfig.envs.set('COSIGN_PASSWORD', shell_env.COSIGN_PASSWORD);
    config.dockerConfig.envs.set('DIRECTORY_CLIENT_SERVER_ADDRESS', dirctlServerAddress);
  }

  const args = ['sign', cid, '--key', req.privateKey];
  const [command, commandArgs] = config.getCommandAndArgs(args);

  return spawnSync(command, commandArgs, {
    env: { ...env, 'DIRECTORY_CLIENT_SERVER_ADDRESS': dirctlServerAddress },
    encoding: 'utf8',
    stdio: 'pipe',
  });
}

export function signWithOidc(
  config: Config,
  cid: string,
  req: models.sign_v1.SignWithOIDC,
): SpawnSyncReturns<string> {
  const args = ['sign', cid];
  if (req.idToken !== '') {
    args.push(...['--oidc-token', req.idToken]);
  }
  if (
    req.options?.oidcProviderUrl !== undefined &&
    req.options.oidcProviderUrl !== ''
  ) {
    args.push(...['--oidc-provider-url', req.options.oidcProviderUrl]);
  }
  if (req.options?.oidcClientId !== undefined && req.options.oidcClientId !== '') {
    args.push(...['--oidc-client-id', req.options.oidcClientId]);
  }
  if (req.options?.oidcClientSecret !== undefined && req.options.oidcClientSecret !== '') {
    args.push(...['--oidc-client-secret', req.options.oidcClientSecret]);
  }
  if (req.options?.skipTlog !== undefined && req.options.skipTlog) {
    args.push('--skip-tlog');
  }
  if (req.options?.fulcioUrl !== undefined && req.options.fulcioUrl !== '') {
    args.push(...['--fulcio-url', req.options.fulcioUrl]);
  }
  if (req.options?.rekorUrl !== undefined && req.options.rekorUrl !== '') {
    args.push(...['--rekor-url', req.options.rekorUrl]);
  }
  if (req.options?.timestampUrl !== undefined && req.options.timestampUrl !== '') {
    args.push(...['--timestamp-url', req.options.timestampUrl]);
  }

  const [command, commandArgs] = config.getCommandAndArgs(args);

  // NOTE: dirctl appends :80 or :443 to server address if has http or https:// prefix
  const dirctlServerAddress = config.serverAddress.replace(/^https?:\/\//, '');

  return spawnSync(command, commandArgs, {
    env: { ...env, 'DIRECTORY_CLIENT_SERVER_ADDRESS': dirctlServerAddress },
    encoding: 'utf8',
    stdio: 'pipe',
  });
}

export function signRecord(config: Config, req: models.sign_v1.SignRequest): void {
  const cid = req.recordRef?.cid ?? '';
  let output: SpawnSyncReturns<string>;

  switch (req.provider?.request.case) {
    case 'oidc':
      output = signWithOidc(config, cid, req.provider.request.value);
      break;
    case 'key':
      output = signWithKey(config, cid, req.provider.request.value);
      break;
    default:
      throw new Error('unsupported provider was supplied');
  }

  if (output.status !== 0) {
    throw output.error ?? output.stderr;
  }
}
