// Copyright (c) 2023 Cloudflare, Inc.
// SPDX-License-Identifier: Apache-2.0

// ACT (Anonymous Credit Tokens) issuance support
// Specification: draft-schlesinger-privacypass-act-01

import { act, MediaType } from '@cloudflare/privacypass-ts';
import { Context } from './context';
import { TokenType } from './types';
import { b64ToB64URL, u8ToB64 } from './utils/base64';
import { clearDirectoryCache } from './cache';

const {
	ACTTokenRequest,
	ACTTokenResponse,
	ACTTokenChallenge,
	Issuer: ACTIssuer,
	ristretto255,
	generateParameters,
	keyGen,
	encodePrivateKey,
	decodePrivateKey,
	encodePublicKey,
	decodePublicKey,
	WebCryptoPRNG,
} = act;
type SystemParams = act.SystemParams;
type PrivateKey = act.PrivateKey;
type PublicKey = act.PublicKey;

// R2 metadata for ACT keys
interface ACTStorageMetadata extends Record<string, string> {
	notBefore: string;
	publicKey: string; // base64url encoded
	tokenKeyID: string;
}

// ACT key pair with metadata
interface ACTKeyPairWithMetadata {
	params: SystemParams;
	privateKey: PrivateKey;
	publicKey: PublicKey;
	notBefore: number;
}

// Compute truncated token key ID from public key (last byte of SHA-256)
const actKeyToTokenKeyID = async (publicKeyBytes: Uint8Array): Promise<number> => {
	const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKeyBytes));
	return hash[hash.length - 1];
};

// Get ACT system parameters from environment
// Domain separator follows spec format: ACT-v1:organization:service:deployment:version
const getACTParams = (ctx: Context): { domainSeparator: Uint8Array; L: number } => {
	const domainSeparator = ctx.env.ACT_DOMAIN_SEPARATOR;
	const L = ctx.env.ACT_L;

	if (!domainSeparator) {
		throw new Error('ACT_DOMAIN_SEPARATOR not configured');
	}
	if (!L) {
		throw new Error('ACT_L not configured');
	}

	// Format: "org:service:deployment:version" -> "ACT-v1:org:service:deployment:version"
	const structuredSeparator = domainSeparator.startsWith('ACT-v1:')
		? domainSeparator
		: `ACT-v1:${domainSeparator}`;

	return {
		domainSeparator: new TextEncoder().encode(structuredSeparator),
		L: parseInt(L, 10),
	};
};

// Get ACT key pair from R2
export const getACTKeyPair = async (
	ctx: Context,
	keyID: number
): Promise<ACTKeyPairWithMetadata> => {
	const bucket = ctx.env.ACT_ISSUANCE_KEYS;
	if (!bucket) {
		throw new Error('ACT_ISSUANCE_KEYS bucket not configured');
	}

	const key = await bucket.get(keyID.toString());
	if (key === null) {
		throw new Error(`ACT key ${keyID} not found`);
	}

	const metadata = key.customMetadata as ACTStorageMetadata | undefined;
	if (!metadata) {
		throw new Error(`ACT key ${keyID} missing metadata`);
	}

	const { domainSeparator, L } = getACTParams(ctx);
	const params = generateParameters(ristretto255, domainSeparator, L);

	const privateKeyBytes = new Uint8Array(await key.arrayBuffer());
	const privateKey = decodePrivateKey(params.group, privateKeyBytes);
	const publicKey = decodePublicKey(params.group, decodeBase64URL(metadata.publicKey));

	const notBefore = parseInt(metadata.notBefore ?? Math.floor(Date.now() / 1000).toString(), 10);

	return { params, privateKey, publicKey, notBefore };
};

// Handle ACT token request (issuance)
export const handleACTTokenRequest = async (
	ctx: Context,
	buffer: ArrayBuffer,
	domain: string,
	credits: bigint
): Promise<{ serialized: Uint8Array; status: number; responseContentType: string }> => {
	const tokenRequest = ACTTokenRequest.deserialize(new Uint8Array(buffer));
	const keyID = tokenRequest.truncatedTokenKeyId;

	const { params, privateKey, publicKey, notBefore: _notBefore } = await getACTKeyPair(ctx, keyID);

	// Create issuer instance
	const issuer = new ACTIssuer(params, privateKey, publicKey);

	// Parse challenge from request to get context
	// For ACT, we need the challenge to compute request_context
	// The challenge is embedded in the token request flow
	const challenge = new ACTTokenChallenge(
		domain,
		new Uint8Array(32), // redemption context - will be provided by origin
		[domain],
		new Uint8Array(0) // credential context - empty for initial issuance
	);

	const responseBytes = issuer.issue(tokenRequest.encodedRequest, credits, challenge);
	const tokenResponse = new ACTTokenResponse(responseBytes);

	ctx.metrics.issuanceRequestTotal.inc();
	ctx.metrics.signedTokenTotal.inc({ key_id: keyID });
	ctx.key_id = keyID;

	return {
		serialized: tokenResponse.serialize(),
		status: 200,
		responseContentType: MediaType.PRIVATE_TOKEN_RESPONSE,
	};
};

// Verify ACT spend proof and issue refund
export const verifyACTSpendProof = async (
	ctx: Context,
	keyID: number,
	proofBytes: Uint8Array,
	returnCredits: bigint
): Promise<{ valid: boolean; refund?: Uint8Array }> => {
	const { params, privateKey, publicKey } = await getACTKeyPair(ctx, keyID);

	const issuer = new ACTIssuer(params, privateKey, publicKey);
	return issuer.verifyAndIssueRefund(proofBytes, returnCredits);
};

// Rotate ACT key
export const rotateACTKey = async (ctx: Context): Promise<Uint8Array> => {
	const bucket = ctx.env.ACT_ISSUANCE_KEYS;
	if (!bucket) {
		throw new Error('ACT_ISSUANCE_KEYS bucket not configured');
	}

	const { domainSeparator, L } = getACTParams(ctx);
	const params = generateParameters(ristretto255, domainSeparator, L);

	let publicKey: PublicKey;
	let privateKey: PrivateKey;
	let publicKeyBytes: Uint8Array;
	let tokenKeyID: number;

	const rng = new WebCryptoPRNG();

	// Generate key pair with unique truncated token key ID
	do {
		const keyPair = keyGen(ristretto255, rng);
		privateKey = keyPair.privateKey;
		publicKey = keyPair.publicKey;
		publicKeyBytes = encodePublicKey(publicKey);
		tokenKeyID = await actKeyToTokenKeyID(publicKeyBytes);
	} while ((await bucket.head(tokenKeyID.toString())) !== null);

	const privateKeyBytes = encodePrivateKey(privateKey);

	const metadata: ACTStorageMetadata = {
		notBefore: ((Date.now() + Number.parseInt(ctx.env.KEY_NOT_BEFORE_DELAY_IN_MS)) / 1000).toFixed(
			0
		),
		publicKey: b64ToB64URL(u8ToB64(publicKeyBytes)),
		tokenKeyID: tokenKeyID.toString(),
	};

	await bucket.put(tokenKeyID.toString(), privateKeyBytes, {
		customMetadata: metadata,
	});

	if (ctx.cacheSettings.enabled) {
		ctx.waitUntil(clearDirectoryCache(ctx));
	}

	ctx.wshimLogger.log(`ACT key rotated successfully, new key ${tokenKeyID}`);

	return publicKeyBytes;
};

// Get ACT token keys for directory
export const getACTTokenKeys = async (
	ctx: Context
): Promise<Array<{ 'token-type': TokenType; 'token-key': string; 'not-before'?: number }>> => {
	const bucket = ctx.env.ACT_ISSUANCE_KEYS;
	if (!bucket) {
		return [];
	}

	const keyList = await bucket.list({ include: ['customMetadata'] });
	if (keyList.objects.length === 0) {
		return [];
	}

	const freshestKeyCount = Number.parseInt(ctx.env.MINIMUM_FRESHEST_KEYS ?? '2');
	const keys = keyList.objects
		.sort((a, b) => new Date(b.uploaded).getTime() - new Date(a.uploaded).getTime())
		.slice(0, freshestKeyCount);

	return keys.map(key => ({
		'token-type': TokenType.ACT,
		'token-key': (key.customMetadata as ACTStorageMetadata).publicKey,
		'not-before': Number.parseInt(
			(key.customMetadata as ACTStorageMetadata).notBefore ??
				(new Date(key.uploaded).getTime() / 1000).toFixed(0)
		),
	}));
};

// Helper: decode base64url to Uint8Array
function decodeBase64URL(str: string): Uint8Array {
	const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
	const padding = '='.repeat((4 - (base64.length % 4)) % 4);
	const binary = atob(base64 + padding);
	return Uint8Array.from(binary, c => c.charCodeAt(0));
}
