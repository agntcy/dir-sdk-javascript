// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { create } from '@bufbuild/protobuf';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { SignService } from '../src/client/services/signing.js';
import type { StoreService } from '../src/client/services/store.js';
import {
  PUBLIC_KEY_REFERRER_TYPE,
  SIGNATURE_REFERRER_TYPE,
  detectKeyAlgorithm,
  getDefaultSignOptions,
  loadPrivateKey,
  signBlobWithKey,
  verifySignatureWithKey,
  verifyWithFetcher,
  type Fetcher,
} from '../src/client/signing/index.js';
import { loadSigner } from '../src/client/signing/keys.js';
import { models } from '../src/index.js';
import { encryptCosignKey } from './helpers/cosignKey.js';

const CID = 'bafytestcid';
const PASSWORD = 'testing-key';
const payload = Buffer.from(CID);

const ed25519 = generateKeyPairSync('ed25519');
const ed25519Der = ed25519.privateKey.export({ type: 'pkcs8', format: 'der' });
const ed25519PublicPem = ed25519.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const x25519 = generateKeyPairSync('x25519');

/** Rewrites the JSON payload of a cosign encrypted key PEM. */
// eslint-disable-next-line no-unused-vars
function tamper(pem: string, mutate: (data: Record<string, unknown>) => void): string {
  const body = pem.replace(/-----[A-Z ]+-----|\s+/g, '');
  const data = JSON.parse(Buffer.from(body, 'base64').toString('utf8')) as Record<string, unknown>;
  mutate(data);
  const encoded = Buffer.from(JSON.stringify(data)).toString('base64');
  return `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n${encoded}\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n`;
}

describe('private key loading', () => {
  const pem = encryptCosignKey(ed25519Der, PASSWORD);
  const password = Buffer.from(PASSWORD);

  test('invalid and unsupported PEM input is rejected', () => {
    expect(() => loadPrivateKey('not a pem')).toThrow('invalid pem block');
    // Unterminated, mismatched and malformed block types are rejected.
    for (const pem of [
      '-----BEGIN PRIVATE KEY-----\nAAAA\n',
      '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----',
      '-----BEGIN private key-----\nAAAA\n-----END private key-----',
      '-----BEGIN PRIVATE KEY',
    ]) {
      expect(() => loadPrivateKey(pem)).toThrow('invalid pem block');
    }
    // A hostile input with many repeated markers is handled in linear time.
    const hostile = '-----BEGIN  -----'.repeat(50000);
    const start = Date.now();
    expect(() => loadPrivateKey(hostile)).toThrow('invalid pem block');
    expect(Date.now() - start).toBeLessThan(2000);
    expect(() =>
      loadPrivateKey('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'),
    ).toThrow('unsupported pem type: CERTIFICATE');
  });

  test('malformed encrypted payloads are rejected', () => {
    const notJson = `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n${Buffer.from('nope').toString('base64')}\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----`;
    expect(() => loadPrivateKey(notJson, password)).toThrow('invalid encrypted key payload');

    expect(() =>
      loadPrivateKey(
        tamper(pem, (d) => ((d.kdf as { name: string }).name = 'pbkdf2')),
        password,
      ),
    ).toThrow('unsupported KDF');
    expect(() =>
      loadPrivateKey(
        tamper(pem, (d) => ((d.cipher as { name: string }).name = 'aes')),
        password,
      ),
    ).toThrow('unsupported cipher');
    expect(() =>
      loadPrivateKey(
        tamper(pem, (d) => ((d.kdf as { params: { N: number } }).params.N = 2)),
        password,
      ),
    ).toThrow('unsupported scrypt parameters');
    expect(() =>
      loadPrivateKey(
        tamper(pem, (d) => delete d.kdf),
        password,
      ),
    ).toThrow('unsupported KDF');
    expect(() =>
      loadPrivateKey(
        tamper(pem, (d) => ((d.cipher as { nonce: string }).nonce = 'AAAA')),
        password,
      ),
    ).toThrow('incorrect nonce size');
    expect(() =>
      loadPrivateKey(
        tamper(pem, (d) => delete (d.cipher as { nonce?: string }).nonce),
        password,
      ),
    ).toThrow('incorrect nonce size');
    expect(() => loadPrivateKey(pem, Buffer.from('wrong'))).toThrow('wrong password');
  });

  test('missing salt and ciphertext fall back to empty values and fail decryption', () => {
    const stripped = tamper(pem, (d) => {
      delete (d.kdf as { salt?: string }).salt;
      delete d.ciphertext;
    });
    expect(() => loadPrivateKey(stripped, password)).toThrow('wrong password');
  });

  test('ENCRYPTED COSIGN PRIVATE KEY label is accepted', () => {
    const relabeled = pem.replace(/SIGSTORE/g, 'COSIGN');
    expect(loadPrivateKey(relabeled, password).publicKeyPem()).toBe(ed25519PublicPem);
  });

  test('standard PEM encodings are accepted', () => {
    const pw = 'pw';
    const encrypted = ed25519.privateKey
      .export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: pw })
      .toString();
    expect(encrypted).toContain('BEGIN ENCRYPTED PRIVATE KEY');
    expect(loadPrivateKey(encrypted, Buffer.from(pw)).publicKeyPem()).toBe(ed25519PublicPem);

    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    const sec1 = ec.export({ type: 'sec1', format: 'pem' }).toString();
    expect(sec1).toContain('BEGIN EC PRIVATE KEY');
    expect(loadPrivateKey(sec1).signMessage(payload).length).toBeGreaterThan(0);

    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    const pkcs1 = rsa.export({ type: 'pkcs1', format: 'pem' }).toString();
    expect(pkcs1).toContain('BEGIN RSA PRIVATE KEY');
    expect(loadPrivateKey(pkcs1).signMessage(payload).length).toBe(256);
  });

  test('unsupported key types cannot sign', async () => {
    const pkcs8 = x25519.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    expect(() => loadPrivateKey(pkcs8).signMessage(payload)).toThrow('unsupported public key type');
    await expect(
      signBlobWithKey(payload, create(models.sign_v1.SignWithKeySchema, { privateKey: pkcs8 })),
    ).rejects.toThrow('signing blob: Error: unsupported public key type');
  });
});

describe('key references', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'dir-sdk-keys-'));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    rmSync(dir, { recursive: true, force: true });
  });

  test('inline PEM errors are not retried as references', async () => {
    const bad = '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----';
    await expect(loadSigner(bad)).rejects.toThrow('loading private key from reference');
    await expect(
      verifySignatureWithKey(bad.replace('PRIVATE', 'PUBLIC'), 'c2ln', payload),
    ).rejects.toThrow('failed to load public key');
  });

  test('missing files and unsupported schemes are rejected', async () => {
    await expect(verifySignatureWithKey(join(dir, 'missing.pub'), 'c2ln', payload)).rejects.toThrow(
      'failed to load public key',
    );
    await expect(verifySignatureWithKey('kms://key', 'c2ln', payload)).rejects.toThrow(
      'unsupported key reference scheme',
    );
  });

  test('keys can be fetched over HTTP(S)', async () => {
    const sig = signBlobWithKey(
      payload,
      create(models.sign_v1.SignWithKeySchema, {
        privateKey: ed25519.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      }),
    );
    const fetchMock = vi.fn((url: string) =>
      Promise.resolve(
        url.endsWith('/ok.pub')
          ? new Response(ed25519PublicPem)
          : new Response('nope', { status: 404, statusText: 'Not Found' }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const { signature } = await sig;
    await expect(
      verifySignatureWithKey('https://keys.example/ok.pub', signature.signature, payload),
    ).resolves.toBe(ed25519PublicPem);
    await expect(
      verifySignatureWithKey('https://keys.example/missing.pub', signature.signature, payload),
    ).rejects.toThrow('404 Not Found');
  });

  test('private keys can be fetched over HTTP(S)', async () => {
    const pem = ed25519.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    vi.stubGlobal('fetch', () => Promise.resolve(new Response(pem)));
    const request = create(models.sign_v1.SignWithKeySchema, {
      privateKey: 'http://keys.example/private.key',
    });
    const { publicKey } = await signBlobWithKey(payload, request);
    expect(publicKey.key).toBe(ed25519PublicPem);
  });

  test('public key files can be referenced', async () => {
    const path = join(dir, 'ed.pub');
    writeFileSync(path, ed25519PublicPem);
    const { signature } = await signBlobWithKey(
      payload,
      create(models.sign_v1.SignWithKeySchema, {
        privateKey: ed25519.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      }),
    );
    await expect(verifySignatureWithKey(path, signature.signature, payload)).resolves.toBe(
      ed25519PublicPem,
    );
  });
});

describe('signature verification edge cases', () => {
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const ecPublicPem = ec.publicKey.export({ type: 'spki', format: 'pem' }).toString();

  test('malformed signatures are rejected for every key type', async () => {
    // Not valid base64, so it is handled as raw bytes of the wrong length.
    await expect(verifySignatureWithKey(ed25519PublicPem, 'abc', payload)).rejects.toThrow(
      'signature verification failed',
    );
    await expect(verifySignatureWithKey(ecPublicPem, 'abc', payload)).rejects.toThrow(
      'signature verification failed',
    );
    await expect(verifySignatureWithKey(ecPublicPem, 'AAAA', payload)).rejects.toThrow(
      'signature verification failed',
    );
  });

  test('unsupported public keys are rejected', async () => {
    const pem = x25519.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    await expect(verifySignatureWithKey(pem, 'c2ln', payload)).rejects.toThrow(
      'unsupported public key type',
    );
    expect(detectKeyAlgorithm(pem)).toBe('unknown');
  });

  test('detectKeyAlgorithm', () => {
    expect(detectKeyAlgorithm('garbage')).toBe('unknown');
    expect(detectKeyAlgorithm(ecPublicPem)).toBe('ECDSA-P-256');
    expect(detectKeyAlgorithm(ed25519PublicPem)).toBe('Ed25519');
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
    expect(detectKeyAlgorithm(rsa.export({ type: 'spki', format: 'pem' }).toString())).toBe(
      'RSA-2048',
    );
  });
});

describe('sign options', () => {
  test('defaults are applied and explicit values are kept', () => {
    const defaults = getDefaultSignOptions();
    expect(defaults.fulcioUrl).toBe('https://fulcio.sigstore.dev');
    expect(defaults.oidcClientSecret).toBe('');
    expect(defaults.skipTlog).toBe(false);

    const custom = getDefaultSignOptions(
      create(models.sign_v1.SignOptionsOIDCSchema, {
        fulcioUrl: 'https://fulcio.example',
        skipTlog: true,
        oidcClientSecret: 'secret',
      }),
    );
    expect(custom).toMatchObject({
      fulcioUrl: 'https://fulcio.example',
      rekorUrl: 'https://rekor.sigstore.dev',
      skipTlog: true,
      oidcClientSecret: 'secret',
    });
  });
});

describe('verifyWithFetcher failures', () => {
  const ref = create(models.core_v1.RecordRefSchema, { cid: CID });
  const request = create(models.sign_v1.VerifyRequestSchema, { recordRef: ref });
  const signature = create(models.sign_v1.SignatureSchema, { signature: 'c2ln' });

  function fetcher(overrides: Partial<Fetcher>): Fetcher {
    return {
      pullSignatures: () => Promise.resolve([signature]),
      pullPublicKeys: () => Promise.resolve([ed25519PublicPem]),
      ...overrides,
    };
  }

  test('fetcher errors are wrapped', async () => {
    await expect(
      verifyWithFetcher(request, fetcher({ pullSignatures: () => Promise.reject(new Error('x')) })),
    ).rejects.toThrow('pull signatures: Error: x');
    await expect(
      verifyWithFetcher(request, fetcher({ pullPublicKeys: () => Promise.reject(new Error('y')) })),
    ).rejects.toThrow('pull public keys: Error: y');
  });

  test('signatures that fail verification are skipped', async () => {
    const withBundle = create(models.sign_v1.SignatureSchema, { contentBundle: 'not-json' });
    const response = await verifyWithFetcher(
      request,
      fetcher({ pullSignatures: () => Promise.resolve([signature, withBundle]) }),
    );
    expect(response.success).toBe(false);
    expect(response.errorMessage).toBe('no valid signatures found matching verification criteria');
  });

  test('unsupported provider types do not verify', async () => {
    const bogus = { recordRef: ref, provider: { request: { case: 'bogus', value: {} } } };
    const response = await verifyWithFetcher(bogus as never, fetcher({}));
    expect(response.success).toBe(false);
  });
});

describe('SignService failure handling', () => {
  function service(store: Record<string, unknown>): SignService {
    return new SignService({ verify: vi.fn() } as never, store as unknown as StoreService);
  }

  const pem = ed25519.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const signRequest = create(models.sign_v1.SignRequestSchema, {
    recordRef: { cid: CID },
    provider: { request: { case: 'key', value: { privateKey: pem } } },
  });

  const okResponse = create(models.store_v1.PushReferrerResponseSchema, { success: true });

  test('unsupported providers and signing failures are reported', async () => {
    const svc = service({});
    await expect(
      svc.sign({
        recordRef: { cid: CID },
        provider: { request: { case: 'bogus', value: {} } },
      } as never),
    ).rejects.toThrow('failed to sign record');
    await expect(
      svc.sign(
        create(models.sign_v1.SignRequestSchema, {
          recordRef: { cid: CID },
          provider: { request: { case: 'key', value: { privateKey: '' } } },
        }),
      ),
    ).rejects.toThrow('failed to sign record: Error: private_key is required');
  });

  test('referrer push failures are reported', async () => {
    const pushKeyFails = vi.fn().mockRejectedValueOnce(new Error('boom'));
    await expect(service({ push_referrer: pushKeyFails }).sign(signRequest)).rejects.toThrow(
      'failed to push referrers to store: Error: failed to store public key: Error: boom',
    );

    const pushSigFails = vi
      .fn()
      .mockResolvedValueOnce([okResponse])
      .mockResolvedValueOnce([
        create(models.store_v1.PushReferrerResponseSchema, {
          success: false,
          errorMessage: 'full',
        }),
      ]);
    await expect(service({ push_referrer: pushSigFails }).sign(signRequest)).rejects.toThrow(
      'failed to store signature: Error: full',
    );

    const pushNoMessage = vi
      .fn()
      .mockResolvedValue([create(models.store_v1.PushReferrerResponseSchema, { success: false })]);
    await expect(service({ push_referrer: pushNoMessage }).sign(signRequest)).rejects.toThrow(
      'push referrer failed',
    );
  });

  test('verify validates the record and reports lookup failures', async () => {
    const svc = service({ lookup: vi.fn().mockRejectedValue(new Error('unavailable')) });
    await expect(
      svc.verify(create(models.sign_v1.VerifyRequestSchema, { recordRef: { cid: '' } })),
    ).rejects.toThrow('record CID is required');
    await expect(
      svc.verify(create(models.sign_v1.VerifyRequestSchema, { recordRef: { cid: CID } })),
    ).rejects.toThrow('failed to lookup record: Error: unavailable');
  });

  test('referrer pull failures are reported', async () => {
    const svc = service({ pull_referrer: vi.fn().mockRejectedValue(new Error('down')) });
    const recordRef = create(models.core_v1.RecordRefSchema, { cid: CID });
    await expect(svc.pullSignatures(recordRef)).rejects.toThrow(
      'failed to create pull referrer stream: Error: down',
    );
    await expect(svc.pullPublicKeys(recordRef)).rejects.toThrow(
      'failed to create pull referrer stream',
    );
  });

  test('referrers that cannot be decoded are skipped', async () => {
    const referrer = (type: string, data?: Record<string, unknown>) =>
      create(models.store_v1.PullReferrerResponseSchema, {
        referrer: create(models.core_v1.RecordReferrerSchema, { type, data: data as never }),
      });
    const pull = vi.fn((requests: models.store_v1.PullReferrerRequest[]) =>
      Promise.resolve(
        requests[0].referrerType === SIGNATURE_REFERRER_TYPE
          ? [
              create(models.store_v1.PullReferrerResponseSchema, {}),
              referrer(SIGNATURE_REFERRER_TYPE),
              referrer(SIGNATURE_REFERRER_TYPE, { unknown: 'field' }),
              referrer(SIGNATURE_REFERRER_TYPE, { signature: 'c2ln' }),
            ]
          : [
              create(models.store_v1.PullReferrerResponseSchema, {}),
              referrer(PUBLIC_KEY_REFERRER_TYPE),
              referrer(PUBLIC_KEY_REFERRER_TYPE, { key: 5 }),
              referrer(PUBLIC_KEY_REFERRER_TYPE, {}),
              referrer(PUBLIC_KEY_REFERRER_TYPE, { key: ed25519PublicPem }),
            ],
      ),
    );
    const svc = service({ pull_referrer: pull });
    const recordRef = create(models.core_v1.RecordRefSchema, { cid: CID });

    const signatures = await svc.pullSignatures(recordRef);
    expect(signatures.map((s) => s.signature)).toEqual(['c2ln']);
    await expect(svc.pullPublicKeys(recordRef)).resolves.toEqual([ed25519PublicPem]);
  });
});
