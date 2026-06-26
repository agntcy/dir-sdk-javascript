// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import { X509Certificate } from 'node:crypto';

import { create } from '@bufbuild/protobuf';
import { sign, type Bundle } from 'sigstore';

import { getSignOptionsOidc } from './options.js';
import * as models from '../../models/index.js';

function getCertificateDer(bundle: Bundle): Buffer {
  const material = bundle.verificationMaterial;
  if (material.certificate !== undefined) {
    return Buffer.from(material.certificate.rawBytes);
  }
  const chainCert = material.x509CertificateChain?.certificates?.[0];
  if (chainCert !== undefined) {
    return Buffer.from(chainCert.rawBytes);
  }
  throw new Error('bundle is missing signing certificate');
}

export async function signWithOidc(
  cid: string,
  req: models.sign_v1.SignWithOIDC,
): Promise<{ signature: models.sign_v1.Signature; publicKey: models.sign_v1.PublicKey }> {
  const opts = getSignOptionsOidc(req.options);
  const payload = Buffer.from(cid, 'utf8');

  const bundle = await sign(payload, {
    fulcioURL: opts.fulcioUrl,
    rekorURL: opts.rekorUrl,
    tsaServerURL: opts.timestampUrl || undefined,
    identityToken: req.idToken,
    tlogUpload: !opts.skipTlog,
  });

  const bundleJson = JSON.stringify(bundle);
  const certificateDer = getCertificateDer(bundle);
  const signatureBytes = Buffer.from(bundle.messageSignature?.signature ?? '', 'base64');
  const publicKeyPem = new X509Certificate(certificateDer).publicKey
    .export({ type: 'spki', format: 'pem' })
    .toString();

  return {
    signature: create(models.sign_v1.SignatureSchema, {
      signature: signatureBytes.toString('base64'),
      certificate: certificateDer.toString('base64'),
      contentType: bundle.mediaType,
      contentBundle: bundleJson,
      signedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    }),
    publicKey: create(models.sign_v1.PublicKeySchema, {
      key: publicKeyPem,
    }),
  };
}
