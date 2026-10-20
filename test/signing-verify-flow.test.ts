// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { create } from '@bufbuild/protobuf';
import { beforeEach, describe, expect, test, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ verifyWithOidc: vi.fn() }));

vi.mock('../src/client/signing/oidc.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/client/signing/oidc.js')>()),
  verifyWithOidc: mocks.verifyWithOidc,
}));

import { verifyWithFetcher, type Fetcher } from '../src/client/signing/index.js';
import { models } from '../src/index.js';

const ref = create(models.core_v1.RecordRefSchema, { cid: 'bafytestcid' });

function oidcSigner(subject: string): models.sign_v1.SignerInfo {
  return create(models.sign_v1.SignerInfoSchema, {
    type: {
      case: 'oidc',
      value: create(models.sign_v1.SignerInfoOIDCSchema, {
        issuer: 'https://issuer',
        subject,
        certificateIssuer: 'CN=ca',
      }),
    },
  });
}

function fetcher(signatures: models.sign_v1.Signature[]): Fetcher {
  return {
    pullSignatures: () => Promise.resolve(signatures),
    pullPublicKeys: () => Promise.resolve([]),
  };
}

const bundleSignature = (bundle: string) =>
  create(models.sign_v1.SignatureSchema, { contentBundle: bundle });

beforeEach(() => {
  vi.clearAllMocks();
});

describe('verifyWithFetcher with OIDC signatures', () => {
  test('the OIDC provider verifies every signature and reports each signer once', async () => {
    mocks.verifyWithOidc
      .mockResolvedValueOnce(oidcSigner('alice'))
      .mockResolvedValueOnce(oidcSigner('alice'))
      .mockResolvedValueOnce(oidcSigner('bob'))
      .mockRejectedValueOnce(new Error('untrusted'));

    const response = await verifyWithFetcher(
      create(models.sign_v1.VerifyRequestSchema, {
        recordRef: ref,
        provider: { request: { case: 'oidc', value: { issuer: 'https://issuer' } } },
      }),
      fetcher([
        bundleSignature('1'),
        bundleSignature('2'),
        bundleSignature('3'),
        bundleSignature('4'),
      ]),
    );

    expect(response.success).toBe(true);
    expect(response.signers.map((s) => s.type.case === 'oidc' && s.type.value.subject)).toEqual([
      'alice',
      'bob',
    ]);
    expect(mocks.verifyWithOidc).toHaveBeenCalledTimes(4);
  });

  test('the any provider verifies bundles with OIDC and wraps failures', async () => {
    mocks.verifyWithOidc.mockResolvedValueOnce(oidcSigner('alice'));
    const request = create(models.sign_v1.VerifyRequestSchema, { recordRef: ref });

    const verified = await verifyWithFetcher(request, fetcher([bundleSignature('{}')]));
    expect(verified.success).toBe(true);

    mocks.verifyWithOidc.mockRejectedValueOnce(new Error('untrusted'));
    const failed = await verifyWithFetcher(request, fetcher([bundleSignature('{}')]));
    expect(failed.success).toBe(false);
    expect(failed.errorMessage).toBe('no valid signatures found matching verification criteria');
  });

  test('signers without a known type are all reported under one key', async () => {
    mocks.verifyWithOidc.mockResolvedValue(create(models.sign_v1.SignerInfoSchema, {}));
    const response = await verifyWithFetcher(
      create(models.sign_v1.VerifyRequestSchema, { recordRef: ref }),
      fetcher([bundleSignature('1'), bundleSignature('2')]),
    );
    expect(response.signers).toHaveLength(1);
  });
});
