// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

export { detectKeyAlgorithm, loadPrivateKey, verifySignatureWithKey } from './keys.js';
export { getDefaultSignOptions, getDefaultVerifyOptions } from './options.js';
export {
  marshalPublicKeyReferrer,
  marshalSignatureReferrer,
  PUBLIC_KEY_REFERRER_TYPE,
  SIGNATURE_REFERRER_TYPE,
  unmarshalPublicKeyReferrer,
  unmarshalSignatureReferrer,
} from './referrer.js';
export { signBlobWithKey, signBlobWithOidc, type SignResult } from './sign.js';
export { verifyWithFetcher, verifyWithKeys, type Fetcher } from './verify.js';
export { getValueMatcher, verifyWithOidc } from './oidc.js';
