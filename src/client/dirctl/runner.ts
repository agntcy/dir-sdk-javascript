// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { env } from 'node:process';

import { Config, DockerConfig } from '../config.js';

function copyDockerConfig(dockerConfig: DockerConfig): DockerConfig {
  return new DockerConfig(
    dockerConfig.dirctlImage,
    dockerConfig.dirctlImageTag,
    new Map(dockerConfig.envs),
    [...dockerConfig.mounts],
    dockerConfig.user,
  );
}

export function buildDirctlBaseCommand(
  config: Config,
  shellEnv?: Record<string, string>,
  extraMounts?: string[],
): string[] {
  const extra = extraMounts ?? [];
  if (config.dirctlPath) {
    return [config.dirctlPath];
  }
  if (config.dockerConfig === undefined) {
    throw new Error('Either dirctlPath or dockerConfig must be configured');
  }

  const dockerConfig = copyDockerConfig(config.dockerConfig);
  if (shellEnv) {
    for (const [key, value] of Object.entries(shellEnv)) {
      dockerConfig.envs.set(key, value);
    }
  }
  dockerConfig.mounts.push(...extra);
  return dockerConfig.getDockerArgs();
}

export function runDirctl(
  config: Config,
  args: string[],
  options?: {
    env?: Record<string, string>;
    extraMounts?: string[];
  },
): SpawnSyncReturns<string> {
  const base = buildDirctlBaseCommand(config, options?.env, options?.extraMounts);
  const command = base[0];
  const commandArgs = [...base.slice(1), ...args];
  const shellEnv = { ...env, ...options?.env };

  return spawnSync(command, commandArgs, {
    env: shellEnv,
    encoding: 'utf8',
    stdio: 'pipe',
  });
}

export function getDirctlCommandAndArgs(config: Config, args: string[]): [string, string[]] {
  return config.getCommandAndArgs(args);
}
