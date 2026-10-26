// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

/**
 * Interoperability tests between the SDK and the dirctl CLI.
 *
 * Records signed by the SDK must verify with dirctl, and records signed by dirctl must verify
 * with the SDK. These tests need a running Directory server (DIRECTORY_CLIENT_SERVER_ADDRESS),
 * the dirctl binary (DIRCTL_PATH or PATH) and the cosign binary (COSIGN_PATH or PATH), and are
 * skipped otherwise. Only key-based signing is covered; keyless signing needs live Sigstore
 * services.
 */

import { execFileSync, spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

import { create } from '@bufbuild/protobuf';
import { afterAll, beforeAll, describe, expect, test, type TestContext } from 'vitest';
import { v4 as uuidv4 } from 'uuid';

import { Client, Config, models } from '../src';
import { marshalPublicKeyReferrer, marshalSignatureReferrer } from '../src/client/signing/index.js';
import { encryptCosignKey } from './helpers/cosignKey.js';

const KEY_PASSWORD = 'interop-pw';
const SERVER_ADDRESS = process.env.DIRECTORY_CLIENT_SERVER_ADDRESS ?? '0.0.0.0:8888';

function findBinary(explicit: string | undefined, name: string): string | undefined {
  if (explicit) {
    return explicit;
  }
  for (const dir of (process.env.PATH ?? '').split(delimiter)) {
    const candidate = join(dir, name);
    const result = spawnSync(candidate, ['version'], { stdio: 'ignore' });
    if (result.error === undefined) {
      return candidate;
    }
  }
  return undefined;
}

const DIRCTL = findBinary(process.env.DIRCTL_PATH, 'dirctl');
const COSIGN = findBinary(process.env.COSIGN_PATH, 'cosign');

interface KeyPair {
  privateKey: string;
  publicKey: string;
}

interface DirctlVerifyResult {
  success?: boolean;
  signers?: { key?: { algorithm: string; publicKey: string } }[];
}

function newRecord(name: string): models.core_v1.Record {
  return create(models.core_v1.RecordSchema, {
    data: {
      name: `agntcy-interop-${name}-${uuidv4().substring(0, 8)}`,
      version: 'v3.0.0',
      schema_version: '1.1.0',
      description: 'Record used to test dirctl and SDK interoperability.',
      authors: ['Cisco Systems'],
      created_at: '2025-03-19T17:06:37Z',
      skills: [
        {
          name: 'language_processing/language_generation/text_completion',
          id: 10301,
        },
      ],
      locators: [{ type: 'container_image', urls: ['https://ghcr.io/agntcy/marketing-strategy'] }],
      domains: [{ name: 'technology/networking', id: 103 }],
      modules: [],
    },
  });
}

describe.skipIf(!DIRCTL || !COSIGN)('dirctl interoperability', () => {
  let client: Client;
  let serverAvailable = false;
  let dir: string;
  let keys: Record<string, KeyPair>;

  beforeAll(async () => {
    const config = Config.loadFromEnv();
    client = new Client(config, await Client.createGRPCTransport(config));
    try {
      await client.push([newRecord('probe')]);
      serverAvailable = true;
    } catch {
      return; // Tests are skipped when the Directory server is not reachable
    }

    dir = mkdtempSync(join(tmpdir(), 'dir-sdk-interop-'));
    execFileSync(COSIGN!, ['generate-key-pair'], {
      cwd: dir,
      env: { ...process.env, COSIGN_PASSWORD: KEY_PASSWORD },
      stdio: 'ignore',
    });

    // cosign cannot generate Ed25519 keys, so the key is written in the cosign format here.
    const ed25519 = generateKeyPairSync('ed25519');
    writeFileSync(
      join(dir, 'ed25519.key'),
      encryptCosignKey(ed25519.privateKey.export({ type: 'pkcs8', format: 'der' }), KEY_PASSWORD),
    );
    writeFileSync(
      join(dir, 'ed25519.pub'),
      ed25519.publicKey.export({ type: 'spki', format: 'pem' }),
    );

    keys = {
      'ECDSA-P-256': { privateKey: join(dir, 'cosign.key'), publicKey: join(dir, 'cosign.pub') },
      Ed25519: { privateKey: join(dir, 'ed25519.key'), publicKey: join(dir, 'ed25519.pub') },
    };
  }, 60_000);

  afterAll(() => {
    if (dir !== undefined) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function requireServer(ctx: TestContext): void {
    if (!serverAvailable) {
      ctx.skip();
    }
  }

  function dirctl(...args: string[]): SpawnSyncReturns<string> {
    return spawnSync(DIRCTL!, args, {
      encoding: 'utf8',
      timeout: 120_000,
      env: {
        ...process.env,
        COSIGN_PASSWORD: KEY_PASSWORD,
        DIRECTORY_CLIENT_SERVER_ADDRESS: SERVER_ADDRESS,
      },
    });
  }

  function dirctlSign(cid: string, privateKey: string): void {
    const result = dirctl('sign', cid, '--key', privateKey);
    expect(result.status, result.stderr).toBe(0);
  }

  // `dirctl verify --output json` omits `success` when verification fails.
  function dirctlVerify(cid: string, publicKey?: string): DirctlVerifyResult {
    const args = ['verify', cid, '--output', 'json'];
    if (publicKey) {
      args.push('--key', publicKey);
    }
    const result = dirctl(...args);
    expect(result.status, result.stderr).toBe(0);
    return JSON.parse(result.stdout) as DirctlVerifyResult;
  }

  async function push(name: string): Promise<models.core_v1.RecordRef> {
    return (await client.push([newRecord(name)]))[0];
  }

  async function sdkSign(ref: models.core_v1.RecordRef, privateKey: string): Promise<void> {
    await client.sign(
      create(models.sign_v1.SignRequestSchema, {
        recordRef: ref,
        provider: {
          request: {
            case: 'key',
            value: { privateKey, password: Buffer.from(KEY_PASSWORD) },
          },
        },
      }),
    );
  }

  function sdkVerify(
    ref: models.core_v1.RecordRef,
    publicKey?: string,
  ): Promise<models.sign_v1.VerifyResponse> {
    return client.verify(
      create(models.sign_v1.VerifyRequestSchema, {
        recordRef: ref,
        provider: {
          request: publicKey ? { case: 'key', value: { publicKey } } : { case: 'any', value: {} },
        },
      }),
    );
  }

  function publicPem(algorithm: string): string {
    return readFileSync(keys[algorithm].publicKey, 'utf8');
  }

  test('SDK signature verifies with dirctl', async (ctx) => {
    requireServer(ctx);
    for (const [algorithm, { privateKey, publicKey }] of Object.entries(keys)) {
      const ref = await push(`sdk-${algorithm}`);
      await sdkSign(ref, privateKey);

      for (const result of [dirctlVerify(ref.cid), dirctlVerify(ref.cid, publicKey)]) {
        expect(result.success, algorithm).toBe(true);
        const signer = result.signers?.[0].key;
        expect(signer?.algorithm).toBe(algorithm);
        expect(signer?.publicKey).toBe(publicPem(algorithm));
      }
    }
  });

  test('dirctl signature verifies with the SDK', async (ctx) => {
    requireServer(ctx);
    for (const [algorithm, { privateKey, publicKey }] of Object.entries(keys)) {
      const ref = await push(`dirctl-${algorithm}`);
      dirctlSign(ref.cid, privateKey);

      for (const response of [await sdkVerify(ref), await sdkVerify(ref, publicKey)]) {
        expect(response.success, response.errorMessage).toBe(true);
        const signer = response.signers[0].type;
        expect(signer.case).toBe('key');
        if (signer.case === 'key') {
          expect(signer.value.algorithm).toBe(algorithm);
          expect(signer.value.publicKey).toBe(publicPem(algorithm));
        }
      }
    }
  });

  test('SDK and dirctl produce equivalent referrers', async (ctx) => {
    requireServer(ctx);
    for (const [algorithm, { privateKey }] of Object.entries(keys)) {
      const sdkRef = await push(`equiv-sdk-${algorithm}`);
      const dirctlRef = await push(`equiv-dirctl-${algorithm}`);
      await sdkSign(sdkRef, privateKey);
      dirctlSign(dirctlRef.cid, privateKey);

      const sdkSigs = await client.signService.pullSignatures(sdkRef);
      const dirctlSigs = await client.signService.pullSignatures(dirctlRef);
      expect(sdkSigs).toHaveLength(1);
      expect(dirctlSigs).toHaveLength(1);

      // Same populated fields and metadata; only time and (for ECDSA) randomness may differ.
      const populated = (sig: models.sign_v1.Signature): string[] =>
        Object.entries(sig)
          .filter(([key, value]) => !key.startsWith('$') && value !== '' && value !== undefined)
          .filter(([, value]) => typeof value !== 'object' || Object.keys(value).length > 0)
          .map(([key]) => key)
          .sort();
      expect(populated(sdkSigs[0])).toEqual(populated(dirctlSigs[0]));
      expect(sdkSigs[0].algorithm).toBe(algorithm);
      expect(dirctlSigs[0].algorithm).toBe(algorithm);
      expect(sdkSigs[0].contentBundle).toBe('');
      expect(dirctlSigs[0].contentBundle).toBe('');
      expect(await client.signService.pullPublicKeys(sdkRef)).toEqual(
        await client.signService.pullPublicKeys(dirctlRef),
      );
    }
  });

  test('signature is rejected for a different record', async (ctx) => {
    requireServer(ctx);
    const { privateKey, publicKey } = keys['ECDSA-P-256'];
    const signed = await push('payload-signed');
    const other = await push('payload-other');
    await sdkSign(signed, privateKey);

    // Re-attach the SDK's referrers to a different record.
    const referrers = [
      ...(await client.signService.pullSignatures(signed)).map(marshalSignatureReferrer),
      marshalPublicKeyReferrer(
        create(models.sign_v1.PublicKeySchema, { key: publicPem('ECDSA-P-256') }),
      ),
    ];
    for (const referrer of referrers) {
      await client.push_referrer([
        create(models.store_v1.PushReferrerRequestSchema, {
          recordRef: other,
          type: referrer.type,
          annotations: referrer.annotations,
          createdAt: referrer.createdAt,
          data: referrer.data,
        }),
      ]);
    }

    expect((await sdkVerify(other, publicKey)).success).toBe(false);
    expect(dirctlVerify(other.cid, publicKey).success ?? false).toBe(false);
  });

  test('wrong key is rejected by both', async (ctx) => {
    requireServer(ctx);
    const { privateKey } = keys['ECDSA-P-256'];
    const otherPublic = keys.Ed25519.publicKey;

    const sdkRef = await push('wrong-key-sdk');
    await sdkSign(sdkRef, privateKey);
    const dirctlRef = await push('wrong-key-dirctl');
    dirctlSign(dirctlRef.cid, privateKey);

    for (const ref of [sdkRef, dirctlRef]) {
      expect((await sdkVerify(ref, otherPublic)).success).toBe(false);
      expect(dirctlVerify(ref.cid, otherPublic).success ?? false).toBe(false);
    }
  });

  test('cosign verifies the SDK signature', async (ctx) => {
    requireServer(ctx);
    const { privateKey, publicKey } = keys['ECDSA-P-256'];
    const ref = await push('cosign');
    await sdkSign(ref, privateKey);
    const [signature] = await client.signService.pullSignatures(ref);

    const payload = join(dir, 'payload.txt');
    writeFileSync(payload, ref.cid);
    execFileSync(
      COSIGN!,
      [
        'verify-blob',
        '--key',
        publicKey,
        '--signature',
        signature.signature,
        '--insecure-ignore-tlog',
        payload,
      ],
      { stdio: 'ignore' },
    );
  });
});
