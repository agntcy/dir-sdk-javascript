// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { generateKeyPairSync, randomBytes, scryptSync, sign as cryptoSign } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { create } from '@bufbuild/protobuf';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { describe, expect, test, vi } from 'vitest';

import { SignService } from '../src/client/services/signing.js';
import type { StoreService } from '../src/client/services/store.js';
import {
  PUBLIC_KEY_REFERRER_TYPE,
  SIGNATURE_REFERRER_TYPE,
  detectKeyAlgorithm,
  getDefaultVerifyOptions,
  getValueMatcher,
  verifyWithOidc,
  loadPrivateKey,
  marshalPublicKeyReferrer,
  marshalSignatureReferrer,
  signBlobWithKey,
  unmarshalPublicKeyReferrer,
  unmarshalSignatureReferrer,
  verifySignatureWithKey,
  verifyWithFetcher,
  verifyWithKeys,
  type Fetcher,
} from '../src/client/signing/index.js';
import { models } from '../src/index.js';

const CID = 'bafytestcid';
const PASSWORD = 'testing-key';

interface Vector {
  Name: string;
  PrivateKey: string;
  PublicKey: string;
  Signature: string;
  Algorithm: string;
}

// Keys and signatures produced by the Go implementation (password "pw", payload CID "bafytestcid").
const goVectors = JSON.parse(
  readFileSync(join(__dirname, 'testdata', 'cosign_key_vectors.json'), 'utf8'),
) as Vector[];

/** Builds a cosign `ENCRYPTED SIGSTORE PRIVATE KEY` PEM (scrypt + nacl/secretbox). */
function encryptCosignKey(der: Buffer, password: string): string {
  const salt = randomBytes(32);
  const nonce = randomBytes(24);
  const params = { N: 32768, r: 8, p: 1 };
  const key = scryptSync(password, salt, 32, { ...params, maxmem: 128 * 1024 * 1024 });
  const payload = {
    kdf: { name: 'scrypt', params, salt: salt.toString('base64') },
    cipher: { name: 'nacl/secretbox', nonce: nonce.toString('base64') },
    ciphertext: Buffer.from(xsalsa20poly1305(key, nonce).encrypt(der)).toString('base64'),
  };
  const body = Buffer.from(JSON.stringify(payload))
    .toString('base64')
    .replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n${body}\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n`;
}

function signRequestWithKey(privateKey: string, password = ''): models.sign_v1.SignWithKey {
  return create(models.sign_v1.SignWithKeySchema, {
    privateKey,
    password: Buffer.from(password),
  });
}

describe('key signing and verification', () => {
  test.each(['ec', 'rsa', 'ed25519'] as const)('round trip with %s key', async (type) => {
    const { privateKey } =
      type === 'ec'
        ? generateKeyPairSync('ec', { namedCurve: 'P-384' })
        : type === 'rsa'
          ? generateKeyPairSync('rsa', { modulusLength: 2048 })
          : generateKeyPairSync('ed25519');
    const der = privateKey.export({ type: 'pkcs8', format: 'der' });
    const pem = encryptCosignKey(der, PASSWORD);

    const { signature, publicKey } = await signBlobWithKey(
      Buffer.from(CID),
      signRequestWithKey(pem, PASSWORD),
    );

    expect(signature.signature).not.toBe('');
    expect(signature.signedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(signature.algorithm).toBe(detectKeyAlgorithm(publicKey.key));
    expect(publicKey.key).toContain('BEGIN PUBLIC KEY');

    await expect(
      verifySignatureWithKey(publicKey.key, signature.signature, Buffer.from(CID)),
    ).resolves.toBe(publicKey.key);
    await expect(
      verifySignatureWithKey(publicKey.key, signature.signature, Buffer.from('other')),
    ).rejects.toThrow('signature verification failed');
  });

  test('plain PEM private key is accepted', async () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const { signature, publicKey } = await signBlobWithKey(
      Buffer.from(CID),
      signRequestWithKey(pem),
    );
    expect(signature.algorithm).toBe('ECDSA-P-256');
    await verifySignatureWithKey(publicKey.key, signature.signature, Buffer.from(CID));
  });

  test('private key and public key can be loaded from file references', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const dir = mkdtempSync(join(tmpdir(), 'dir-sdk-sign-'));
    const keyPath = join(dir, 'cosign.key');
    writeFileSync(
      keyPath,
      encryptCosignKey(privateKey.export({ type: 'pkcs8', format: 'der' }), PASSWORD),
    );

    const { signature, publicKey } = await signBlobWithKey(
      Buffer.from(CID),
      signRequestWithKey(keyPath, PASSWORD),
    );
    const pubPath = join(dir, 'cosign.pub');
    writeFileSync(pubPath, publicKey.key);

    await expect(
      verifySignatureWithKey(pubPath, signature.signature, Buffer.from(CID)),
    ).resolves.toBe(publicKey.key);
  });

  test('wrong password and missing key are rejected', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = encryptCosignKey(privateKey.export({ type: 'pkcs8', format: 'der' }), PASSWORD);

    await expect(
      signBlobWithKey(Buffer.from(CID), signRequestWithKey(pem, 'nope')),
    ).rejects.toThrow('loading private key from reference');
    await expect(signBlobWithKey(Buffer.from(CID), signRequestWithKey(''))).rejects.toThrow(
      'private_key is required',
    );
    await expect(
      signBlobWithKey(Buffer.from(CID), signRequestWithKey('/nonexistent/cosign.key')),
    ).rejects.toThrow('loading private key from reference');
  });

  test('pure Ed25519 signatures are accepted by the verifier', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const sig = cryptoSign(null, Buffer.from(CID), privateKey).toString('base64');
    const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    await expect(verifySignatureWithKey(pem, sig, Buffer.from(CID))).resolves.toBe(pem);
  });

  describe.each(goVectors)('Go compatibility ($Name)', (vector) => {
    test('Go signature verifies', async () => {
      await verifySignatureWithKey(vector.PublicKey, vector.Signature, Buffer.from(CID));
      expect(detectKeyAlgorithm(vector.PublicKey)).toBe(vector.Algorithm);
    });

    test('Go encrypted key can be decrypted and used to sign', async () => {
      const signer = loadPrivateKey(vector.PrivateKey, Buffer.from('pw'));
      expect(signer.publicKeyPem()).toBe(vector.PublicKey);

      const sig = signer.signMessage(Buffer.from(CID)).toString('base64');
      await verifySignatureWithKey(vector.PublicKey, sig, Buffer.from(CID));
      if (vector.Name !== 'ecdsa') {
        // Ed25519ph and RSA PKCS#1 v1.5 are deterministic: byte-for-byte equal to Go.
        expect(sig).toBe(vector.Signature);
      }
    });
  });

  test('verifyWithKeys tries all keys and reports signer info', async () => {
    const [ec, ed] = goVectors;
    const sig = create(models.sign_v1.SignatureSchema, { signature: ed.Signature });

    const info = await verifyWithKeys(Buffer.from(CID), [ec.PublicKey, ed.PublicKey], sig);
    expect(info.type.case).toBe('key');
    if (info.type.case === 'key') {
      expect(info.type.value.publicKey).toBe(ed.PublicKey);
      expect(info.type.value.algorithm).toBe('Ed25519');
    }

    await expect(verifyWithKeys(Buffer.from(CID), [ec.PublicKey], sig)).rejects.toThrow(
      'no valid signature found for the provided public keys',
    );
  });
});

describe('referrer encoding', () => {
  test('referrer types match the Go implementation', () => {
    expect(SIGNATURE_REFERRER_TYPE).toBe('agntcy.dir.sign.v1.Signature');
    expect(PUBLIC_KEY_REFERRER_TYPE).toBe('agntcy.dir.sign.v1.PublicKey');
  });

  test('signature referrer uses protojson field names and omits empty fields', () => {
    const signature = create(models.sign_v1.SignatureSchema, {
      signature: 'c2ln',
      algorithm: 'Ed25519',
      signedAt: '2026-01-02T03:04:05Z',
    });
    const referrer = marshalSignatureReferrer(signature);

    expect(referrer.type).toBe('agntcy.dir.sign.v1.Signature');
    expect(referrer.data).toEqual({
      signature: 'c2ln',
      algorithm: 'Ed25519',
      signedAt: '2026-01-02T03:04:05Z',
    });

    const decoded = unmarshalSignatureReferrer(referrer);
    expect(decoded.signature).toBe('c2ln');
    expect(decoded.algorithm).toBe('Ed25519');
    expect(decoded.signedAt).toBe('2026-01-02T03:04:05Z');
  });

  test('OIDC signature fields round trip', () => {
    const signature = create(models.sign_v1.SignatureSchema, {
      signature: 'c2ln',
      certificate: 'Y2VydA==',
      contentType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
      contentBundle: '{"mediaType":"x"}',
      annotations: { a: 'b' },
    });
    const referrer = marshalSignatureReferrer(signature);
    expect(Object.keys(referrer.data ?? {}).sort()).toEqual([
      'annotations',
      'certificate',
      'contentBundle',
      'contentType',
      'signature',
    ]);
    expect(unmarshalSignatureReferrer(referrer)).toMatchObject({
      certificate: 'Y2VydA==',
      contentBundle: '{"mediaType":"x"}',
      annotations: { a: 'b' },
    });
  });

  test('public key referrer', () => {
    const publicKey = create(models.sign_v1.PublicKeySchema, { key: goVectors[0].PublicKey });
    const referrer = marshalPublicKeyReferrer(publicKey);
    expect(referrer.type).toBe('agntcy.dir.sign.v1.PublicKey');
    expect(referrer.data).toEqual({ key: goVectors[0].PublicKey });
    expect(unmarshalPublicKeyReferrer(referrer).key).toBe(goVectors[0].PublicKey);
  });

  test('referrers without data are rejected', () => {
    const empty = create(models.core_v1.RecordReferrerSchema, {});
    expect(() => unmarshalSignatureReferrer(empty)).toThrow('referrer or data is nil');
    expect(() => unmarshalPublicKeyReferrer(undefined)).toThrow('referrer or data is nil');
  });
});

describe('value matcher and options', () => {
  test('getValueMatcher', () => {
    expect(getValueMatcher('')).toEqual({ exact: '', regex: /.*/ });
    expect(
      getValueMatcher('https://github.com/org/.*').regex?.test('https://github.com/org/x'),
    ).toBe(true);
    expect(getValueMatcher('(unclosed')).toEqual({ exact: '(unclosed', regex: undefined });
  });

  test('verify option defaults', () => {
    const opts = getDefaultVerifyOptions();
    expect(opts.tufMirrorUrl).toBe('https://tuf-repo-cdn.sigstore.dev');
    expect(opts.ignoreTlog).toBe(false);
    expect(
      getDefaultVerifyOptions(
        create(models.sign_v1.VerifyOptionsOIDCSchema, {
          tufMirrorUrl: 'https://m',
          ignoreSct: true,
        }),
      ),
    ).toMatchObject({ tufMirrorUrl: 'https://m', ignoreSct: true });
  });
});

describe('OIDC verification input handling', () => {
  const oidc = create(models.sign_v1.VerifyWithOIDCSchema, {
    options: { trustedRootPath: '/nonexistent/trusted_root.json' },
  });

  test('invalid bundle is rejected', async () => {
    const signature = create(models.sign_v1.SignatureSchema, { contentBundle: 'not-json' });
    await expect(verifyWithOidc(Buffer.from(CID), oidc, signature)).rejects.toThrow(
      'failed to parse bundle',
    );
  });

  test('missing trusted root is rejected', async () => {
    const signature = create(models.sign_v1.SignatureSchema, {
      contentBundle: JSON.stringify({
        mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
        verificationMaterial: { certificate: { rawBytes: 'AA==' } },
        messageSignature: {
          messageDigest: { algorithm: 'SHA2_256', digest: 'AA==' },
          signature: 'AA==',
        },
      }),
    });
    await expect(verifyWithOidc(Buffer.from(CID), oidc, signature)).rejects.toThrow(
      'failed to load trusted root from path',
    );
  });
});

describe('verifyWithFetcher', () => {
  const ref = create(models.core_v1.RecordRefSchema, { cid: CID });

  function fetcher(signatures: string[], publicKeys: string[]): Fetcher {
    return {
      pullSignatures: () =>
        Promise.resolve(
          signatures.map((s) => create(models.sign_v1.SignatureSchema, { signature: s })),
        ),
      pullPublicKeys: () => Promise.resolve(publicKeys),
    };
  }

  const [ec, ed] = goVectors;

  test('any provider is the default and verifies key signatures with pulled keys', async () => {
    const response = await verifyWithFetcher(
      create(models.sign_v1.VerifyRequestSchema, { recordRef: ref }),
      fetcher([ec.Signature, ed.Signature], [ec.PublicKey, ed.PublicKey]),
    );
    expect(response.success).toBe(true);
    expect(response.signers).toHaveLength(2);
  });

  test('duplicate signers are reported once', async () => {
    const response = await verifyWithFetcher(
      create(models.sign_v1.VerifyRequestSchema, { recordRef: ref }),
      fetcher([ed.Signature, ed.Signature], [ed.PublicKey]),
    );
    expect(response.success).toBe(true);
    expect(response.signers).toHaveLength(1);
  });

  test('key provider only uses the supplied key', async () => {
    const request = create(models.sign_v1.VerifyRequestSchema, {
      recordRef: ref,
      provider: { request: { case: 'key', value: { publicKey: ec.PublicKey } } },
    });
    const response = await verifyWithFetcher(
      request,
      fetcher([ec.Signature, ed.Signature], [ed.PublicKey]),
    );
    expect(response.success).toBe(true);
    expect(response.signers).toHaveLength(1);
    expect(response.signers[0].type.case).toBe('key');
  });

  test('no signatures found', async () => {
    const response = await verifyWithFetcher(
      create(models.sign_v1.VerifyRequestSchema, { recordRef: ref }),
      fetcher([], []),
    );
    expect(response.success).toBe(false);
    expect(response.errorMessage).toBe('no signatures found');
  });

  test('no valid signatures matching criteria', async () => {
    const response = await verifyWithFetcher(
      create(models.sign_v1.VerifyRequestSchema, { recordRef: ref }),
      fetcher([ed.Signature], [ec.PublicKey]),
    );
    expect(response.success).toBe(false);
    expect(response.errorMessage).toBe('no valid signatures found matching verification criteria');
  });

  test('record ref is required', async () => {
    await expect(
      verifyWithFetcher(create(models.sign_v1.VerifyRequestSchema, {}), fetcher([], [])),
    ).rejects.toThrow('record ref is required');
  });
});

describe('SignService', () => {
  function mockStore() {
    const pushed: models.store_v1.PushReferrerRequest[] = [];
    const store = {
      push_referrer: vi.fn((requests: models.store_v1.PushReferrerRequest[]) => {
        pushed.push(...requests);
        return Promise.resolve(
          requests.map(() => create(models.store_v1.PushReferrerResponseSchema, { success: true })),
        );
      }),
      pull_referrer: vi.fn((requests: models.store_v1.PullReferrerRequest[]) => {
        const type = requests[0].referrerType;
        return Promise.resolve(
          pushed
            .filter((p) => p.type === type)
            .map((p) =>
              create(models.store_v1.PullReferrerResponseSchema, {
                referrer: create(models.core_v1.RecordReferrerSchema, {
                  type: p.type,
                  data: p.data,
                }),
              }),
            ),
        );
      }),
      lookup: vi.fn(() => Promise.resolve([])),
    };
    return { store, pushed };
  }

  const signClient = { verify: vi.fn() };

  test('sign pushes public key then signature referrers and verify succeeds offline', async () => {
    const { store, pushed } = mockStore();
    const service = new SignService(signClient as never, store as unknown as StoreService);
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = encryptCosignKey(privateKey.export({ type: 'pkcs8', format: 'der' }), PASSWORD);
    const ref = create(models.core_v1.RecordRefSchema, { cid: CID });

    const response = await service.sign(
      create(models.sign_v1.SignRequestSchema, {
        recordRef: ref,
        provider: { request: { case: 'key', value: signRequestWithKey(pem, PASSWORD) } },
      }),
    );

    expect(response.signature?.signature).not.toBe('');
    expect(pushed.map((p) => p.type)).toEqual([PUBLIC_KEY_REFERRER_TYPE, SIGNATURE_REFERRER_TYPE]);
    expect(pushed.every((p) => p.recordRef?.cid === CID)).toBe(true);

    const verified = await service.verify(
      create(models.sign_v1.VerifyRequestSchema, { recordRef: ref }),
    );
    expect(verified.success).toBe(true);
    expect(verified.signers).toHaveLength(1);
    expect(store.lookup).toHaveBeenCalled();
    expect(signClient.verify).not.toHaveBeenCalled();
  });

  test('sign validates its input', async () => {
    const service = new SignService(
      signClient as never,
      mockStore().store as unknown as StoreService,
    );
    await expect(service.sign(create(models.sign_v1.SignRequestSchema, {}))).rejects.toThrow(
      'signature provider must be specified',
    );
    await expect(
      service.sign(
        create(models.sign_v1.SignRequestSchema, {
          provider: { request: { case: 'key', value: signRequestWithKey('k') } },
        }),
      ),
    ).rejects.toThrow('record ref must be specified');
  });

  test('verify reports a missing record', async () => {
    const { store } = mockStore();
    store.lookup.mockRejectedValueOnce(new Error('record not found: bafy'));
    const service = new SignService(signClient as never, store as unknown as StoreService);
    const response = await service.verify(
      create(models.sign_v1.VerifyRequestSchema, { recordRef: { cid: CID } }),
    );
    expect(response.success).toBe(false);
    expect(response.errorMessage).toBe('record not found');
  });

  test('verify reports records without signatures', async () => {
    const service = new SignService(
      signClient as never,
      mockStore().store as unknown as StoreService,
    );
    const response = await service.verify(
      create(models.sign_v1.VerifyRequestSchema, { recordRef: { cid: CID } }),
    );
    expect(response.errorMessage).toBe('no signatures found');
  });

  test('verify with fromServer calls the server', async () => {
    const serverResponse = create(models.sign_v1.VerifyResponseSchema, { success: true });
    signClient.verify.mockResolvedValueOnce(serverResponse);
    const service = new SignService(
      signClient as never,
      mockStore().store as unknown as StoreService,
    );
    await expect(
      service.verify(
        create(models.sign_v1.VerifyRequestSchema, { recordRef: { cid: CID }, fromServer: true }),
      ),
    ).resolves.toBe(serverResponse);
    await expect(
      service.verify(create(models.sign_v1.VerifyRequestSchema, { fromServer: true })),
    ).rejects.toThrow('VerifyRequest.recordRef with cid is required');
  });
});
