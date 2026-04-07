import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { Address, hash, xdr } from "@stellar/stellar-sdk";
import base64url from "base64url";
import type { StorageAdapter } from "../types";
import type {
  Client as SmartAccountClient,
  Signer as ContractSigner,
  ContextRuleType,
} from "smart-account-kit-bindings";
import { WEBAUTHN_TIMEOUT_MS, SECP256R1_PUBLIC_KEY_SIZE } from "../constants";

/** WebAuthn signature data for the smart account contract */
interface WebAuthnSigData {
  authenticator_data: Buffer;
  client_data: Buffer;
  signature: Buffer;
}
import {
  compactSignature,
  extractPublicKeyFromAttestation,
  generateChallenge,
} from "../utils";
import { validateContextRuleIds } from "./invocation-utils";

type ContractSignerId = ContractSigner;

type WebAuthnDeps = {
  rpId?: string;
  rpName: string;
  webAuthn: {
    startRegistration: (args: { optionsJSON: PublicKeyCredentialCreationOptionsJSON }) => Promise<RegistrationResponseJSON>;
    startAuthentication: (args: { optionsJSON: PublicKeyCredentialRequestOptionsJSON }) => Promise<AuthenticationResponseJSON>;
  };
};

type RequireWallet = () => { wallet: SmartAccountClient; contractId: string };

type SignAuthEntryDeps = WebAuthnDeps & {
  networkPassphrase: string;
  storage: StorageAdapter;
  webauthnVerifierAddress: string;
  calculateExpiration: () => Promise<number>;
  getCredentialId: () => string | undefined;
  requireWallet: RequireWallet;
};

export async function createPasskey(
  deps: WebAuthnDeps,
  appName: string,
  userName: string,
  authenticatorSelection?: {
    authenticatorAttachment?: "platform" | "cross-platform";
    residentKey?: "discouraged" | "preferred" | "required";
    userVerification?: "discouraged" | "preferred" | "required";
  }
): Promise<{
  rawResponse: RegistrationResponseJSON;
  credentialId: string;
  publicKey: Uint8Array;
}> {
  const now = new Date();
  const displayName = `${userName} — ${now.toLocaleString()}`;

  const options: PublicKeyCredentialCreationOptionsJSON = {
    challenge: generateChallenge(),
    rp: {
      id: deps.rpId,
      name: appName || deps.rpName,
    },
    user: {
      id: base64url(`${userName}:${now.getTime()}:${Math.random()}`),
      name: displayName,
      displayName,
    },
    authenticatorSelection: {
      residentKey: authenticatorSelection?.residentKey ?? "preferred",
      userVerification: authenticatorSelection?.userVerification ?? "preferred",
      authenticatorAttachment: authenticatorSelection?.authenticatorAttachment,
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    timeout: WEBAUTHN_TIMEOUT_MS,
  };

  const rawResponse = await deps.webAuthn.startRegistration({ optionsJSON: options });
  const publicKey = await extractPublicKeyFromAttestation(rawResponse.response);

  return {
    rawResponse,
    credentialId: rawResponse.id,
    publicKey,
  };
}

export async function authenticatePasskey(
  deps: WebAuthnDeps
): Promise<{ credentialId: string; rawResponse: AuthenticationResponseJSON }> {
  const authOptions: PublicKeyCredentialRequestOptionsJSON = {
    challenge: generateChallenge(),
    rpId: deps.rpId,
    userVerification: "preferred",
    timeout: WEBAUTHN_TIMEOUT_MS,
  };

  const rawResponse = await deps.webAuthn.startAuthentication({ optionsJSON: authOptions });

  return {
    credentialId: rawResponse.id,
    rawResponse,
  };
}

export async function signAuthEntry(
  deps: SignAuthEntryDeps,
  entry: xdr.SorobanAuthorizationEntry,
  options?: {
    credentialId?: string;
    expiration?: number;
    contextRuleIds?: number[];
  }
): Promise<xdr.SorobanAuthorizationEntry> {
  const entryXdrBytes = entry.toXDR();
  const normalizedEntry = xdr.SorobanAuthorizationEntry.fromXDR(entryXdrBytes);

  const credentials = normalizedEntry.credentials().address();
  const expiration = options?.expiration ?? await deps.calculateExpiration();
  credentials.signatureExpirationLedger(expiration);

  const contextRuleIds = options?.contextRuleIds ?? [0];
  validateContextRuleIds(contextRuleIds, normalizedEntry.rootInvocation());

  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
    new xdr.HashIdPreimageSorobanAuthorization({
      networkId: hash(Buffer.from(deps.networkPassphrase)),
      nonce: credentials.nonce(),
      signatureExpirationLedger: credentials.signatureExpirationLedger(),
      invocation: normalizedEntry.rootInvocation(),
    })
  );
  const signaturePayload = hash(preimage.toXDR());

  // Compute auth digest: sha256(signature_payload || context_rule_ids.to_xdr())
  const contextRuleIdsXdr = xdr.ScVal.scvVec(
    contextRuleIds.map(id => xdr.ScVal.scvU32(id))
  ).toXDR();
  const authDigest = hash(Buffer.concat([signaturePayload, contextRuleIdsXdr]));

  const credentialId = options?.credentialId ?? deps.getCredentialId();

  const authOptions: PublicKeyCredentialRequestOptionsJSON = {
    challenge: base64url(authDigest),
    rpId: deps.rpId,
    userVerification: "preferred",
    timeout: WEBAUTHN_TIMEOUT_MS,
    ...(credentialId && {
      allowCredentials: [{ id: credentialId, type: "public-key" }],
    }),
  };

  const authResponse = await deps.webAuthn.startAuthentication({
    optionsJSON: authOptions,
  });

  const rawSignature = base64url.toBuffer(authResponse.response.signature);
  const compactedSignature = compactSignature(rawSignature);

  const keyData = await findKeyDataByCredentialId(
    deps.storage,
    authResponse.id,
    deps.requireWallet,
    deps.webauthnVerifierAddress
  );

  const signerId: ContractSignerId = {
    tag: "External",
    values: [
      deps.webauthnVerifierAddress,
      keyData,
    ],
  };

  const webAuthnSigData = {
    authenticator_data: base64url.toBuffer(authResponse.response.authenticatorData),
    client_data: base64url.toBuffer(authResponse.response.clientDataJSON),
    signature: Buffer.from(compactedSignature),
  };

  const scMapEntry = buildSignatureMapEntry(signerId, webAuthnSigData);

  const currentSig = credentials.signature();
  if (currentSig.switch().name === "scvVoid") {
    // First signer: create AuthPayload struct
    credentials.signature(buildAuthPayloadScVal([scMapEntry], contextRuleIds));
  } else {
    // Additional signer: append to existing AuthPayload's signers map
    const signersMap = getSignersMapFromAuthPayload(currentSig);
    signersMap?.push(scMapEntry);
  }

  // Sort the signers map by XDR key for deterministic ordering
  const signersMap = getSignersMapFromAuthPayload(credentials.signature());
  if (signersMap && signersMap.length > 1) {
    signersMap.sort((a, b) => {
      const aKeyXdr = a.key().toXDR("hex");
      const bKeyXdr = b.key().toXDR("hex");
      return aKeyXdr.localeCompare(bKeyXdr);
    });
  }

  if (credentialId) {
    await deps.storage.update(credentialId, { lastUsedAt: Date.now() });
  }

  return normalizedEntry;
}

/**
 * Find keyData for a credential ID, using local storage first,
 * then falling back to on-chain lookup if needed.
 */
async function findKeyDataByCredentialId(
  storage: StorageAdapter,
  credentialId: string,
  requireWallet: RequireWallet,
  webauthnVerifierAddress: string,
): Promise<Buffer> {
  // Try local storage first (fast path)
  const credential = await storage.get(credentialId);
  if (credential?.keyData) {
    return credential.keyData;
  }

  // Fallback: reconstruct keyData from stored public key
  if (credential?.publicKey) {
    const { buildKeyData } = await import("../utils");
    return buildKeyData(credential.publicKey, credentialId);
  }

  // Fallback: scan on-chain context rules for an External signer matching this credential ID
  try {
    const { extractCredentialIdFromKeyData } = await import("../utils");
    const { wallet } = requireWallet();
    const credentialIdBuffer = base64url.toBuffer(credentialId);
    const countTx = await wallet.get_context_rules_count();
    const count = countTx.result ?? 0;
    for (let i = 0; i < count; i++) {
      try {
        const ruleTx = await wallet.get_context_rule({ context_rule_id: i });
        const rule = ruleTx.result;
        if (!rule) continue;
        for (const signer of rule.signers) {
          if (
            signer.tag === "External" &&
            signer.values[0] === webauthnVerifierAddress
          ) {
            const onChainKeyData = signer.values[1] as Buffer;
            const onChainCredId = extractCredentialIdFromKeyData(onChainKeyData);
            if (onChainCredId.equals(credentialIdBuffer)) {
              return onChainKeyData;
            }
          }
        }
      } catch {
        // rule may have been removed, skip
      }
    }
  } catch {
    // on-chain lookup failed, fall through to error
  }

  throw new Error(
    `No key data found for credential ID: ${credentialId}. ` +
    `Ensure the credential was stored with keyData (credentials created before SDK v0.3.0 may need to be re-registered).`
  );
}

/**
 * Build the AuthPayload ScVal struct for the credential signature.
 * Fields are in alphabetical order for Soroban ScMap serialization.
 */
export function buildAuthPayloadScVal(
  signerEntries: xdr.ScMapEntry[],
  contextRuleIds: number[]
): xdr.ScVal {
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("context_rule_ids"),
      val: xdr.ScVal.scvVec(contextRuleIds.map(id => xdr.ScVal.scvU32(id))),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("signers"),
      val: xdr.ScVal.scvMap(signerEntries),
    }),
  ]);
}

/**
 * Extract the signers map entries from an AuthPayload ScVal.
 * AuthPayload is scvMap([{context_rule_ids: ...}, {signers: Map}])
 */
export function getSignersMapFromAuthPayload(
  authPayload: xdr.ScVal
): xdr.ScMapEntry[] | undefined {
  const fields = authPayload.map();
  if (!fields) return undefined;
  // "signers" is the second field in alphabetical order (after "context_rule_ids")
  const signersField = fields[1];
  return signersField?.val().map() ?? undefined;
}

function buildSignatureMapEntry(
  signerId: ContractSignerId,
  sigData: WebAuthnSigData
): xdr.ScMapEntry {
  let keyVal: xdr.ScVal;
  if (signerId.tag === "Delegated") {
    keyVal = xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("Delegated"),
      xdr.ScVal.scvAddress(Address.fromString(signerId.values[0]).toScAddress()),
    ]);
  } else {
    keyVal = xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("External"),
      xdr.ScVal.scvAddress(Address.fromString(signerId.values[0]).toScAddress()),
      xdr.ScVal.scvBytes(signerId.values[1]),
    ]);
  }

  const sigDataScVal = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("authenticator_data"),
      val: xdr.ScVal.scvBytes(sigData.authenticator_data),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("client_data"),
      val: xdr.ScVal.scvBytes(sigData.client_data),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("signature"),
      val: xdr.ScVal.scvBytes(sigData.signature),
    }),
  ]);

  const sigDataXdrBytes = sigDataScVal.toXDR();
  const sigVal = xdr.ScVal.scvBytes(sigDataXdrBytes);

  return new xdr.ScMapEntry({
    key: keyVal,
    val: sigVal,
  });
}
