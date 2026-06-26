// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { X509Certificate } from 'node:crypto';

import { create } from '@bufbuild/protobuf';
import { verify, type Bundle } from 'sigstore';

import { detectKeyAlgorithm, loadPublicKey, verifyPayload } from './cosignKeys.js';
import { StoreFetcher } from './fetcher.js';
import { getVerifyOptionsOidc } from './options.js';
import type { StoreService } from '../services/store.js';
import * as models from '../../models/index.js';

const OTHER_NAME_OID = '1.3.6.1.4.1.57264.1.7';
const ISSUER_OID = '1.3.6.1.4.1.57264.1.8';

function valueMatchers(value: string): { exact: string | undefined; pattern: RegExp | undefined } {
  if (value === '') {
    return { exact: undefined, pattern: /.*/ };
  }
  try {
    return { exact: undefined, pattern: new RegExp(value) };
  } catch {
    return { exact: value, pattern: undefined };
  }
}

function certificateIdentities(cert: X509Certificate): { issuer: string; identities: string[] } {
  const issuerMatch = cert.subjectAltName?.match(new RegExp(`${ISSUER_OID}=([^,]+)`));
  const issuer = issuerMatch?.[1] ?? '';
  const identities = (cert.subjectAltName ?? '')
    .split(', ')
    .map((entry) => entry.trim())
    .filter(
      (entry) => entry.includes('@') || entry.startsWith('http') || entry.includes(OTHER_NAME_OID),
    );
  return { issuer, identities };
}

function matchesIdentity(issuer: string, subject: string, cert: X509Certificate): boolean {
  const { issuer: certIssuer, identities } = certificateIdentities(cert);
  const issuerMatcher = valueMatchers(issuer);
  const subjectMatcher = valueMatchers(subject);

  const issuerOk =
    issuerMatcher.exact === certIssuer || (issuerMatcher.pattern?.test(certIssuer) ?? false);
  const subjectOk = identities.some(
    (identity) =>
      subjectMatcher.exact === identity || (subjectMatcher.pattern?.test(identity) ?? false),
  );
  return issuerOk && subjectOk;
}

function verifyWithKeys(
  payload: Buffer,
  publicKeys: string[],
  signature: models.sign_v1.Signature,
): models.sign_v1.SignerInfo {
  for (const publicKey of publicKeys) {
    try {
      const publicKeyPem = loadPublicKey(publicKey);
      const signatureBytes = Buffer.from(signature.signature, 'base64');
      verifyPayload(publicKeyPem, signatureBytes, payload);
      return create(models.sign_v1.SignerInfoSchema, {
        type: {
          case: 'key',
          value: {
            publicKey: publicKeyPem,
            algorithm: detectKeyAlgorithm(publicKeyPem),
          },
        },
      });
    } catch {
      continue;
    }
  }
  throw new Error('no valid signature found for the provided public keys');
}

async function verifyWithOidc(
  payload: Buffer,
  req: models.sign_v1.VerifyWithOIDC | undefined,
  signature: models.sign_v1.Signature,
): Promise<models.sign_v1.SignerInfo> {
  const opts = getVerifyOptionsOidc(req?.options);
  const bundle = JSON.parse(signature.contentBundle) as Bundle;

  await verify(bundle, payload, {
    tufMirrorURL: opts.tufMirrorUrl,
    tufRootPath: opts.trustedRootPath !== '' ? opts.trustedRootPath : undefined,
    certificateIssuer: req?.issuer !== '' ? req?.issuer : undefined,
    certificateIdentityURI: req?.subject !== '' ? req?.subject : undefined,
  });

  const certificateDer = Buffer.from(signature.certificate, 'base64');
  const cert = new X509Certificate(certificateDer);
  const { issuer, identities } = certificateIdentities(cert);
  const subject = identities[0] ?? '';

  if ((req?.issuer ?? '') !== '' || (req?.subject ?? '') !== '') {
    if (!matchesIdentity(req?.issuer ?? '', req?.subject ?? '', cert)) {
      throw new Error('verification failed');
    }
  }

  return create(models.sign_v1.SignerInfoSchema, {
    type: {
      case: 'oidc',
      value: {
        issuer,
        subject,
      },
    },
  });
}

async function verifyWithAny(
  payload: Buffer,
  publicKeys: string[],
  signature: models.sign_v1.Signature,
): Promise<models.sign_v1.SignerInfo> {
  if (signature.contentBundle === '') {
    return verifyWithKeys(payload, publicKeys, signature);
  }
  return verifyWithOidc(payload, create(models.sign_v1.VerifyWithOIDCSchema, {}), signature);
}

function getSignerKey(signer: models.sign_v1.SignerInfo): string {
  if (signer.type.case === 'key') {
    return `key:${signer.type.value.publicKey}`;
  }
  if (signer.type.case === 'oidc') {
    return `oidc:${signer.type.value.issuer}:${signer.type.value.subject}`;
  }
  return '';
}

export async function verifyWithFetcher(
  request: models.sign_v1.VerifyRequest,
  fetcher: StoreFetcher,
): Promise<models.sign_v1.VerifyResponse> {
  if (request.recordRef?.cid === undefined || request.recordRef.cid === '') {
    throw new Error('record ref is required');
  }

  try {
    await fetcher.lookup(request.recordRef);
  } catch {
    return create(models.sign_v1.VerifyResponseSchema, {
      success: false,
      errorMessage: 'record not found',
    });
  }

  let provider =
    request.provider ??
    create(models.sign_v1.VerifyRequestProviderSchema, {
      request: {
        case: 'any',
        value: create(models.sign_v1.VerifyWithAnySchema, {
          oidcOptions: getVerifyOptionsOidc(undefined),
        }),
      },
    });

  if (
    provider.request.case !== 'key' &&
    provider.request.case !== 'oidc' &&
    provider.request.case !== 'any'
  ) {
    provider = create(models.sign_v1.VerifyRequestProviderSchema, {
      request: {
        case: 'any',
        value: create(models.sign_v1.VerifyWithAnySchema, {
          oidcOptions: getVerifyOptionsOidc(undefined),
        }),
      },
    });
  }

  const signatures = await fetcher.pullSignatures(request.recordRef);
  if (signatures.length === 0) {
    return create(models.sign_v1.VerifyResponseSchema, {
      success: false,
      errorMessage: 'no signatures found',
    });
  }

  let publicKeys: string[] = [];
  if (provider.request.case === 'key') {
    publicKeys = [provider.request.value.publicKey];
  } else if (provider.request.case === 'any') {
    publicKeys = await fetcher.pullPublicKeys(request.recordRef);
  }

  const payload = Buffer.from(request.recordRef.cid, 'utf8');
  const seenKeys = new Set<string>();
  const signers: models.sign_v1.SignerInfo[] = [];

  for (const signature of signatures) {
    try {
      let signerInfo: models.sign_v1.SignerInfo;
      switch (provider.request.case) {
        case 'oidc':
          signerInfo = await verifyWithOidc(payload, provider.request.value, signature);
          break;
        case 'key':
          signerInfo = verifyWithKeys(payload, publicKeys, signature);
          break;
        case 'any':
          signerInfo = await verifyWithAny(payload, publicKeys, signature);
          break;
        default:
          throw new Error('unsupported verification provider type');
      }

      const signerKey = getSignerKey(signerInfo);
      if (seenKeys.has(signerKey)) {
        continue;
      }
      seenKeys.add(signerKey);
      signers.push(signerInfo);
    } catch {
      continue;
    }
  }

  if (signers.length === 0) {
    return create(models.sign_v1.VerifyResponseSchema, {
      success: false,
      errorMessage: 'no valid signatures found matching verification criteria',
    });
  }

  return create(models.sign_v1.VerifyResponseSchema, {
    success: true,
    signers,
  });
}

export async function verifyRecord(
  storeService: StoreService,
  request: models.sign_v1.VerifyRequest,
): Promise<models.sign_v1.VerifyResponse> {
  return verifyWithFetcher(request, new StoreFetcher(storeService));
}
