// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { env } from 'node:process';

import { fromJsonString } from '@bufbuild/protobuf';

import type { Config } from '../config.js';
import * as models from '../../models/index.js';

function runVerifyCommand(
  config: Config,
  args: string[],
): void {
  const [command, commandArgs] = config.getCommandAndArgs(args);
  const output = spawnSync(command, commandArgs, {
    env: { ...env },
    encoding: 'utf8',
    stdio: 'pipe',
  });

  if (output.status !== 0) {
    throw new Error(output.stderr || output.stdout || 'Verification failed');
  }
}

export function verifyWithKey(
  config: Config,
  cid: string,
  req: models.sign_v1.VerifyWithKey,
  outputPath: string,
): void {
  const args = ['verify', cid, '--key', req.publicKey, '--output-file', outputPath];
  runVerifyCommand(config, args);
}

export function verifyWithAny(
  config: Config,
  cid: string,
  req: models.sign_v1.VerifyWithAny | undefined,
  outputPath: string,
): void {
  const args = ['verify', cid, '--output-file', outputPath];

  if (req?.oidcOptions !== undefined) {
    if (req.oidcOptions.tufMirrorUrl !== undefined && req.oidcOptions.tufMirrorUrl !== '') {
      args.push(...['--tuf-mirror-url', req.oidcOptions.tufMirrorUrl]);
    }
    if (req.oidcOptions.trustedRootPath !== undefined && req.oidcOptions.trustedRootPath !== '') {
      args.push(...['--trusted-root-path', req.oidcOptions.trustedRootPath]);
    }
    if (req.oidcOptions.ignoreTlog === true) {
      args.push('--ignore-tlog');
    }
    if (req.oidcOptions.ignoreTsa === true) {
      args.push('--ignore-tsa');
    }
    if (req.oidcOptions.ignoreSct === true) {
      args.push('--ignore-sct');
    }
  }

  runVerifyCommand(config, args);
}

export function verifyWithOidc(
  config: Config,
  cid: string,
  req: models.sign_v1.VerifyWithOIDC | undefined,
  outputPath: string,
): void {
  const args = ['verify', cid, '--output-file', outputPath];

  if (req !== undefined) {
    if (req.issuer !== undefined && req.issuer !== '') {
      args.push(...['--oidc-issuer', req.issuer]);
    }
    if (req.subject !== undefined && req.subject !== '') {
      args.push(...['--oidc-subject', req.subject]);
    }

    if (req.options !== undefined) {
      if (req.options.tufMirrorUrl !== undefined && req.options.tufMirrorUrl !== '') {
        args.push(...['--tuf-mirror-url', req.options.tufMirrorUrl]);
      }
      if (req.options.trustedRootPath !== undefined && req.options.trustedRootPath !== '') {
        args.push(...['--trusted-root-path', req.options.trustedRootPath]);
      }
      if (req.options.ignoreTlog === true) {
        args.push('--ignore-tlog');
      }
      if (req.options.ignoreTsa === true) {
        args.push('--ignore-tsa');
      }
      if (req.options.ignoreSct === true) {
        args.push('--ignore-sct');
      }
    }
  }

  runVerifyCommand(config, args);
}

export function verifyRecord(
  config: Config,
  request: models.sign_v1.VerifyRequest,
): models.sign_v1.VerifyResponse {
  const tempDir = mkdtempSync(join(tmpdir(), 'dirctl-verify-'));
  const outputPath = join(tempDir, 'output.json');
  closeSync(openSync(outputPath, 'w'));
  let resolvedOutputPath = outputPath;

  if (config.dockerConfig) {
    resolvedOutputPath = outputPath.split('/').reverse()[0];
    config.dockerConfig.mounts.push(`type=bind,src=${outputPath},dst=/${resolvedOutputPath}`);
  }

  try {
    const cid = request.recordRef?.cid || '';

    switch (request.provider?.request.case) {
      case 'oidc':
        verifyWithOidc(config, cid, request.provider.request.value, resolvedOutputPath);
        break;
      case 'key':
        verifyWithKey(config, cid, request.provider.request.value, resolvedOutputPath);
        break;
      case 'any':
        verifyWithAny(config, cid, request.provider.request.value, resolvedOutputPath);
        break;
      default:
        verifyWithAny(config, cid, undefined, resolvedOutputPath);
        break;
    }

    const jsonContent = readFileSync(outputPath, 'utf8');
    return fromJsonString(models.sign_v1.VerifyResponseSchema, jsonContent);
  } catch (e) {
    throw new Error(`Failed to parse verification response: ${e}`);
  } finally {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
}
