// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { create } from '@bufbuild/protobuf';
import { bundleFromJSON, type SerializedBundle } from '@sigstore/bundle';
import { TrustedRoot } from '@sigstore/protobuf-specs';
import * as tuf from '@sigstore/tuf';
import { toSignedEntity, toTrustMaterial, Verifier, type SignedEntity } from '@sigstore/verify';
import { sign as sigstoreSign } from 'sigstore';

import * as models from '../../models/index.js';
import { getDefaultSignOptions, getDefaultVerifyOptions } from './options.js';

type Timestamp = SignedEntity['timestamps'][number];

// Mirrors DefaultRekorTimeout of the Go implementation (the longest of the service timeouts).
const SIGN_TIMEOUT_MS = 90_000;
const SIGN_RETRIES = 1;

/** Signs a blob using OIDC authentication (ephemeral key, Fulcio certificate, Rekor/TSA). */
export async function signBlobWithOidc(
  payload: Uint8Array,
  req: models.sign_v1.SignWithOIDC,
): Promise<{ signature: models.sign_v1.Signature; publicKey: models.sign_v1.PublicKey }> {
  const signingTime = new Date();
  const opts = getDefaultSignOptions(req.options);

  if (req.idToken === '') {
    throw new Error('failed to sign record: id_token is required');
  }

  let bundle: SerializedBundle;
  try {
    bundle = await sigstoreSign(Buffer.from(payload), {
      fulcioURL: opts.fulcioUrl,
      rekorURL: opts.rekorUrl,
      tsaServerURL: opts.timestampUrl,
      tlogUpload: !opts.skipTlog,
      identityToken: req.idToken,
      retry: { retries: SIGN_RETRIES },
      timeout: SIGN_TIMEOUT_MS,
    });
  } catch (e) {
    throw new Error(`failed to sign record: ${e}`, { cause: e });
  }

  const material = bundle.verificationMaterial;
  const certificate =
    material?.certificate?.rawBytes ?? material?.x509CertificateChain?.certificates?.[0]?.rawBytes;
  if (!certificate) {
    throw new Error('failed to get certificate from bundle');
  }
  const publicKeyPem = new X509Certificate(Buffer.from(certificate, 'base64')).publicKey
    .export({ type: 'spki', format: 'pem' })
    .toString();

  const signature = create(models.sign_v1.SignatureSchema, {
    signature: bundle.messageSignature?.signature ?? '',
    certificate,
    contentType: bundle.mediaType,
    contentBundle: JSON.stringify(bundle),
    signedAt: toRfc3339(signingTime),
  });
  const publicKey = create(models.sign_v1.PublicKeySchema, { key: publicKeyPem });

  return { signature, publicKey };
}

/** RFC 3339 timestamp in UTC without fractional seconds (Go `time.RFC3339`). */
export function toRfc3339(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Returns an (exact, regex) matcher tuple for the value (Go `getValueMatcher`). */
export function getValueMatcher(value: string): { exact: string; regex: RegExp | undefined } {
  if (value === '') {
    return { exact: '', regex: /.*/ };
  }
  try {
    return { exact: '', regex: new RegExp(value) };
  } catch {
    return { exact: value, regex: undefined };
  }
}

function matches(matcher: ReturnType<typeof getValueMatcher>, actual: string, what: string): void {
  if (matcher.exact !== '' && matcher.exact !== actual) {
    throw new Error(`expected ${what} value "${matcher.exact}", got "${actual}"`);
  }
  if (matcher.regex !== undefined && !matcher.regex.test(actual)) {
    throw new Error(
      `expected ${what} value to match regex "${matcher.regex.source}", got "${actual}"`,
    );
  }
}

async function getTrustedRoot(opts: models.sign_v1.VerifyOptionsOIDC): Promise<TrustedRoot> {
  if (opts.trustedRootPath !== '') {
    try {
      return TrustedRoot.fromJSON(JSON.parse(readFileSync(opts.trustedRootPath, 'utf8')));
    } catch (e) {
      throw new Error(`failed to load trusted root from path ${opts.trustedRootPath}: ${e}`, {
        cause: e,
      });
    }
  }
  if (opts.tufMirrorUrl !== '') {
    try {
      return await tuf.getTrustedRoot({ mirrorURL: opts.tufMirrorUrl });
    } catch (e) {
      throw new Error(`failed to fetch trusted root from TUF: ${e}`, { cause: e });
    }
  }
  throw new Error('no trusted root source specified');
}

/**
 * Builds the signed entity handed to the verifier according to the verify options, following
 * the sigstore-go verifier options used by the Go implementation:
 * - transparency log entries are only checked (and required) unless `ignoreTlog` is set,
 *   in which case the current time is used to establish the certificate time;
 * - only RFC 3161 timestamps count as observer timestamps and are required unless `ignoreTsa`.
 */
function buildSignedEntity(
  entity: SignedEntity,
  opts: models.sign_v1.VerifyOptionsOIDC,
): SignedEntity {
  let timestamps: Timestamp[] = [];

  if (!opts.ignoreTsa) {
    timestamps = entity.timestamps.filter((t) => t.$case === 'timestamp-authority');
    if (timestamps.length < 1) {
      throw new Error(
        `failed to verify timestamps: threshold not met for verified signed timestamps: ${timestamps.length} < 1`,
      );
    }
  }

  if (opts.ignoreTlog) {
    // Use the current time to verify the certificate when the log is not used.
    timestamps.push({
      $case: 'transparency-log',
      tlogEntry: {
        inclusionPromise: {},
        logId: { keyId: Buffer.alloc(0) },
        integratedTime: String(Math.floor(Date.now() / 1000)),
      },
    } as unknown as Timestamp);
  }

  if (timestamps.length === 0) {
    throw new Error('failed to verify timestamps: no valid observer timestamps found');
  }

  return {
    signature: entity.signature,
    key: entity.key,
    tlogEntries: opts.ignoreTlog ? [] : entity.tlogEntries,
    timestamps,
  };
}

/**
 * Verifies a Sigstore bundle using OIDC identity. This performs full Sigstore verification:
 * certificate chain validation, transparency log, signed timestamps, SCTs and OIDC
 * issuer/identity matching.
 */
export async function verifyWithOidc(
  payload: Uint8Array,
  req: models.sign_v1.VerifyWithOIDC,
  signature: models.sign_v1.Signature,
): Promise<models.sign_v1.SignerInfo> {
  const opts = getDefaultVerifyOptions(req.options);

  let bundle;
  try {
    bundle = bundleFromJSON(JSON.parse(signature.contentBundle));
  } catch (e) {
    throw new Error(`failed to parse bundle: ${e}`, { cause: e });
  }

  let trustedRoot: TrustedRoot;
  try {
    trustedRoot = await getTrustedRoot(opts);
  } catch (e) {
    throw new Error(`failed to get trusted material: ${e}`, { cause: e });
  }

  const verifier = new Verifier(toTrustMaterial(trustedRoot), {
    tlogThreshold: opts.ignoreTlog ? 0 : 1,
    ctlogThreshold: opts.ignoreSct ? 0 : 1,
    timestampThreshold: 0,
  });

  const issuerMatcher = getValueMatcher(req.issuer);
  const subjectMatcher = getValueMatcher(req.subject);

  try {
    const entity = buildSignedEntity(toSignedEntity(bundle, Buffer.from(payload)), opts);
    const signer = verifier.verify(entity);

    const identity = signer.identity;
    if (identity === undefined) {
      throw new Error('expected certificate identity, bundle was not signed with a certificate');
    }
    const issuer = identity.extensions?.issuer ?? '';
    const subject = identity.subjectAlternativeName ?? '';
    matches(issuerMatcher, issuer, 'issuer');
    matches(subjectMatcher, subject, 'SAN');

    return create(models.sign_v1.SignerInfoSchema, {
      type: {
        case: 'oidc',
        value: create(models.sign_v1.SignerInfoOIDCSchema, {
          issuer,
          subject,
          certificateIssuer: getCertificateIssuer(signature),
        }),
      },
    });
  } catch (e) {
    throw new Error(`verification failed: ${e}`, { cause: e });
  }
}

/** Issuer DN of the signing certificate, formatted like Go's `pkix.Name.String()`. */
function getCertificateIssuer(signature: models.sign_v1.Signature): string {
  const bundle = JSON.parse(signature.contentBundle) as SerializedBundle;
  const raw =
    bundle.verificationMaterial?.certificate?.rawBytes ??
    bundle.verificationMaterial?.x509CertificateChain?.certificates?.[0]?.rawBytes;
  if (!raw) {
    return '';
  }
  return new X509Certificate(Buffer.from(raw, 'base64')).issuer.split('\n').reverse().join(',');
}
