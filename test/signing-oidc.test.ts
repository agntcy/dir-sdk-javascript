// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { create } from '@bufbuild/protobuf';
import { afterAll, beforeEach, describe, expect, test, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  sigstoreSign: vi.fn(),
  getTrustedRoot: vi.fn(),
  toSignedEntity: vi.fn(),
  verify: vi.fn(),
  verifierOptions: vi.fn(),
  defaultVerifyOptions: vi.fn(),
}));

vi.mock('sigstore', () => ({ sign: mocks.sigstoreSign }));
vi.mock('@sigstore/tuf', () => ({ getTrustedRoot: mocks.getTrustedRoot }));
vi.mock('@sigstore/bundle', () => ({ bundleFromJSON: (json: unknown) => json }));
vi.mock('@sigstore/verify', () => ({
  toSignedEntity: mocks.toSignedEntity,
  toTrustMaterial: () => ({}),
  Verifier: class {
    constructor(_trust: unknown, options: unknown) {
      mocks.verifierOptions(options);
    }
    verify(entity: unknown): unknown {
      return mocks.verify(entity);
    }
  },
}));
vi.mock('../src/client/signing/options.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/client/signing/options.js')>();
  mocks.defaultVerifyOptions.mockImplementation(original.getDefaultVerifyOptions);
  return { ...original, getDefaultVerifyOptions: mocks.defaultVerifyOptions };
});

import { SignService } from '../src/client/services/signing.js';
import type { StoreService } from '../src/client/services/store.js';
import { signBlobWithOidc, verifyWithOidc } from '../src/client/signing/index.js';
import { models } from '../src/index.js';

const CID = 'bafytestcid';
const payload = Buffer.from(CID);
const CERT_PEM = readFileSync(join(__dirname, 'testdata', 'test_cert.pem'), 'utf8');
const CERT_DER = Buffer.from(CERT_PEM.replace(/-----[A-Z ]+-----|\s+/g, ''), 'base64');
const CERT_B64 = CERT_DER.toString('base64');

const tmp = mkdtempSync(join(tmpdir(), 'dir-sdk-oidc-'));
const trustedRootPath = join(tmp, 'trusted_root.json');
writeFileSync(trustedRootPath, '{}');
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function bundle(material: unknown = { certificate: { rawBytes: CERT_B64 } }) {
  return {
    mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    verificationMaterial: material,
    messageSignature: { signature: 'c2ln' },
  };
}

function oidcSignature(material?: unknown): models.sign_v1.Signature {
  return create(models.sign_v1.SignatureSchema, {
    contentBundle: JSON.stringify(bundle(material)),
  });
}

function verifyRequest(
  options: Partial<Omit<models.sign_v1.VerifyOptionsOIDC, '$typeName' | '$unknown'>> = {},
  match: { issuer?: string; subject?: string } = {},
): models.sign_v1.VerifyWithOIDC {
  return create(models.sign_v1.VerifyWithOIDCSchema, {
    ...match,
    options: { trustedRootPath, ...options },
  });
}

const tsaTimestamp = { $case: 'timestamp-authority', timestamp: 1 };
const tlogTimestamp = { $case: 'transparency-log', tlogEntry: {} };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.toSignedEntity.mockReturnValue({
    signature: 'sig',
    key: 'key',
    tlogEntries: ['entry'],
    timestamps: [tsaTimestamp, tlogTimestamp],
  });
  mocks.verify.mockReturnValue({
    identity: {
      subjectAlternativeName: 'https://github.com/org/repo/.github/workflows/ci.yaml',
      extensions: { issuer: 'https://token.actions.githubusercontent.com' },
    },
  });
});

describe('signBlobWithOidc', () => {
  const request = (options = {}) =>
    create(models.sign_v1.SignWithOIDCSchema, { idToken: 'token', options });

  test('requires an id token', async () => {
    await expect(
      signBlobWithOidc(payload, create(models.sign_v1.SignWithOIDCSchema, {})),
    ).rejects.toThrow('id_token is required');
  });

  test('wraps sigstore failures', async () => {
    mocks.sigstoreSign.mockRejectedValue(new Error('fulcio down'));
    await expect(signBlobWithOidc(payload, request())).rejects.toThrow(
      'failed to sign record: Error: fulcio down',
    );
  });

  test('requires a certificate in the bundle', async () => {
    mocks.sigstoreSign.mockResolvedValue({ mediaType: 'm' });
    await expect(signBlobWithOidc(payload, request())).rejects.toThrow(
      'failed to get certificate from bundle',
    );
  });

  test('returns the signature and the certificate public key', async () => {
    mocks.sigstoreSign.mockResolvedValue(bundle());
    const { signature, publicKey } = await signBlobWithOidc(payload, request());

    expect(signature.signature).toBe('c2ln');
    expect(signature.certificate).toBe(CERT_B64);
    expect(signature.contentType).toBe('application/vnd.dev.sigstore.bundle.v0.3+json');
    expect(JSON.parse(signature.contentBundle)).toEqual(bundle());
    expect(signature.signedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(publicKey.key).toContain('BEGIN PUBLIC KEY');
    expect(mocks.sigstoreSign).toHaveBeenCalledWith(
      payload,
      expect.objectContaining({
        fulcioURL: 'https://fulcio.sigstore.dev',
        tlogUpload: true,
        identityToken: 'token',
      }),
    );
  });

  test('supports certificate chains, skipping the transparency log and no signature', async () => {
    mocks.sigstoreSign.mockResolvedValue({
      mediaType: 'm',
      verificationMaterial: { x509CertificateChain: { certificates: [{ rawBytes: CERT_B64 }] } },
    });
    const { signature } = await signBlobWithOidc(payload, request({ skipTlog: true }));
    expect(signature.signature).toBe('');
    expect(signature.certificate).toBe(CERT_B64);
    expect(mocks.sigstoreSign).toHaveBeenCalledWith(
      payload,
      expect.objectContaining({ tlogUpload: false }),
    );
  });

  test('SignService signs with the OIDC provider', async () => {
    mocks.sigstoreSign.mockResolvedValue(bundle());
    const push_referrer = vi.fn((requests: unknown[]) =>
      Promise.resolve(
        requests.map(() => create(models.store_v1.PushReferrerResponseSchema, { success: true })),
      ),
    );
    const service = new SignService({} as never, { push_referrer } as unknown as StoreService);

    const response = await service.sign(
      create(models.sign_v1.SignRequestSchema, {
        recordRef: { cid: CID },
        provider: { request: { case: 'oidc', value: { idToken: 'token' } } },
      }),
    );
    expect(response.signature?.certificate).toBe(CERT_B64);
    expect(push_referrer).toHaveBeenCalledTimes(2);
  });
});

describe('verifyWithOidc', () => {
  test('verifies and reports the OIDC signer', async () => {
    const info = await verifyWithOidc(payload, verifyRequest(), oidcSignature());

    expect(info.type.case).toBe('oidc');
    if (info.type.case === 'oidc') {
      expect(info.type.value.issuer).toBe('https://token.actions.githubusercontent.com');
      expect(info.type.value.subject).toBe('https://github.com/org/repo/.github/workflows/ci.yaml');
      expect(info.type.value.certificateIssuer).toBe('CN=sigstore-intermediate,O=sigstore.dev');
    }
    expect(mocks.verifierOptions).toHaveBeenCalledWith({
      tlogThreshold: 1,
      ctlogThreshold: 1,
      timestampThreshold: 0,
    });
    // Transparency log entries are kept and only RFC 3161 timestamps count as observers.
    expect(mocks.verify).toHaveBeenCalledWith(
      expect.objectContaining({ tlogEntries: ['entry'], timestamps: [tsaTimestamp] }),
    );
  });

  test('matches issuer and subject with regular expressions and exact values', async () => {
    await expect(
      verifyWithOidc(
        payload,
        verifyRequest(
          {},
          { issuer: 'https://token\\.actions\\..*', subject: 'https://github.com/org/.*' },
        ),
        oidcSignature(),
      ),
    ).resolves.toBeDefined();

    await expect(
      verifyWithOidc(payload, verifyRequest({}, { issuer: 'https://other' }), oidcSignature()),
    ).rejects.toThrow('expected issuer value to match regex');
    // An invalid regular expression is compared literally.
    await expect(
      verifyWithOidc(payload, verifyRequest({}, { subject: '(literal' }), oidcSignature()),
    ).rejects.toThrow('expected SAN value "(literal"');
  });

  test('ignoring the transparency log uses the current time', async () => {
    await verifyWithOidc(
      payload,
      verifyRequest({ ignoreTlog: true, ignoreSct: true }),
      oidcSignature(),
    );
    expect(mocks.verifierOptions).toHaveBeenCalledWith({
      tlogThreshold: 0,
      ctlogThreshold: 0,
      timestampThreshold: 0,
    });
    const entity = mocks.verify.mock.calls[0][0] as { tlogEntries: unknown[]; timestamps: any[] };
    expect(entity.tlogEntries).toEqual([]);
    expect(entity.timestamps).toHaveLength(2);
    expect(entity.timestamps[0]).toBe(tsaTimestamp);
    expect(entity.timestamps[1].$case).toBe('transparency-log');
  });

  test('ignoring both the timestamps and the log only relies on the current time', async () => {
    await verifyWithOidc(
      payload,
      verifyRequest({ ignoreTlog: true, ignoreTsa: true }),
      oidcSignature(),
    );
    const entity = mocks.verify.mock.calls[0][0] as { timestamps: unknown[] };
    expect(entity.timestamps).toHaveLength(1);
  });

  test('timestamps are required unless ignored', async () => {
    mocks.toSignedEntity.mockReturnValue({ tlogEntries: [], timestamps: [tlogTimestamp] });
    await expect(verifyWithOidc(payload, verifyRequest(), oidcSignature())).rejects.toThrow(
      'threshold not met for verified signed timestamps: 0 < 1',
    );
    await expect(
      verifyWithOidc(payload, verifyRequest({ ignoreTsa: true }), oidcSignature()),
    ).rejects.toThrow('no valid observer timestamps found');
  });

  test('bundles must be signed with a certificate', async () => {
    mocks.verify.mockReturnValue({});
    await expect(verifyWithOidc(payload, verifyRequest(), oidcSignature())).rejects.toThrow(
      'expected certificate identity',
    );
  });

  test('empty identity extensions are handled', async () => {
    mocks.verify.mockReturnValue({ identity: {} });
    const info = await verifyWithOidc(payload, verifyRequest(), oidcSignature());
    expect(info.type.case === 'oidc' && info.type.value.issuer).toBe('');
  });

  test('verifier failures are wrapped', async () => {
    mocks.verify.mockImplementation(() => {
      throw new Error('bad chain');
    });
    await expect(verifyWithOidc(payload, verifyRequest(), oidcSignature())).rejects.toThrow(
      'verification failed: Error: bad chain',
    );
  });

  test('the certificate issuer is empty without a certificate and read from chains', async () => {
    const withoutCert = await verifyWithOidc(payload, verifyRequest(), oidcSignature({}));
    expect(withoutCert.type.case === 'oidc' && withoutCert.type.value.certificateIssuer).toBe('');

    const chain = await verifyWithOidc(
      payload,
      verifyRequest(),
      oidcSignature({ x509CertificateChain: { certificates: [{ rawBytes: CERT_B64 }] } }),
    );
    expect(chain.type.case === 'oidc' && chain.type.value.certificateIssuer).toBe(
      'CN=sigstore-intermediate,O=sigstore.dev',
    );
  });

  test('the trusted root is fetched from the TUF mirror', async () => {
    mocks.getTrustedRoot.mockResolvedValue({});
    await verifyWithOidc(
      payload,
      verifyRequest({ trustedRootPath: '', tufMirrorUrl: 'https://tuf.example' }),
      oidcSignature(),
    );
    expect(mocks.getTrustedRoot).toHaveBeenCalledWith({ mirrorURL: 'https://tuf.example' });

    mocks.getTrustedRoot.mockRejectedValue(new Error('offline'));
    await expect(
      verifyWithOidc(payload, verifyRequest({ trustedRootPath: '' }), oidcSignature()),
    ).rejects.toThrow('failed to fetch trusted root from TUF: Error: offline');
  });

  test('a trusted root source is required', async () => {
    mocks.defaultVerifyOptions.mockReturnValueOnce(
      create(models.sign_v1.VerifyOptionsOIDCSchema, { tufMirrorUrl: '', trustedRootPath: '' }),
    );
    await expect(verifyWithOidc(payload, verifyRequest(), oidcSignature())).rejects.toThrow(
      'no trusted root source specified',
    );
  });
});
