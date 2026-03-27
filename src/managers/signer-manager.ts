/**
 * Signer Manager
 *
 * Manages signers (passkeys and delegated accounts) for context rules.
 */

import base64url from "base64url";
import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import type { AuthenticatorTransportFuture } from "@simplewebauthn/browser";
import type { Signer as ContractSigner } from "smart-account-kit-bindings";
import type { SmartAccountEventEmitter } from "../events";
import type { StorageAdapter, StoredCredential } from "../types";
import { buildKeyData } from "../utils";
import { SECP256R1_PUBLIC_KEY_SIZE } from "../constants";

/** Dependencies required by SignerManager */
export interface SignerManagerDeps {
  /** Get the connected wallet client, throws if not connected */
  requireWallet: () => {
    wallet: {
      add_signer: (args: { context_rule_id: number; signer: ContractSigner }) => Promise<AssembledTransaction<number>>;
      remove_signer: (args: { context_rule_id: number; signer_id: number }) => Promise<AssembledTransaction<null>>;
      get_signer_id: (args: { signer: ContractSigner }) => Promise<AssembledTransaction<number>>;
    };
    contractId: string;
  };
  /** Storage adapter for credentials */
  storage: StorageAdapter;
  /** Event emitter */
  events: SmartAccountEventEmitter;
  /** WebAuthn verifier contract address */
  webauthnVerifierAddress: string;
  /** Create a passkey via WebAuthn */
  createPasskey: (appName: string, userName: string) => Promise<{
    rawResponse: { response: { transports?: AuthenticatorTransportFuture[] } };
    credentialId: string;
    publicKey: Uint8Array;
  }>;
}

/**
 * Manages signers for smart account context rules.
 */
export class SignerManager {
  constructor(private deps: SignerManagerDeps) {}

  /**
   * Add a new passkey signer to a context rule.
   * Creates a new WebAuthn passkey and registers it as an External signer.
   */
  async addPasskey(
    contextRuleId: number,
    appName: string,
    userName: string,
    options?: { nickname?: string }
  ) {
    const { wallet, contractId } = this.deps.requireWallet();

    // Create the passkey
    const { rawResponse, credentialId, publicKey } = await this.deps.createPasskey(
      appName,
      userName
    );

    // Build the External signer key data
    const keyData = buildKeyData(publicKey, credentialId);

    // Store the credential (with keyData for signing without on-chain lookup)
    const storedCredential: StoredCredential = {
      credentialId,
      publicKey,
      contractId,
      nickname: options?.nickname ?? `${userName} - ${new Date().toLocaleDateString()}`,
      createdAt: Date.now(),
      transports: rawResponse.response.transports,
      isPrimary: false,
      contextRuleId,
      keyData,
    };

    await this.deps.storage.save(storedCredential);

    // Emit credential created event
    this.deps.events.emit("credentialCreated", { credential: storedCredential });
    const signer: ContractSigner = {
      tag: "External",
      values: [this.deps.webauthnVerifierAddress, keyData],
    };

    // Build and return the add_signer transaction
    const transaction = await wallet.add_signer({
      context_rule_id: contextRuleId,
      signer,
    });

    return {
      credentialId,
      publicKey,
      transaction,
    };
  }

  /**
   * Add a delegated signer (Stellar account) to a context rule.
   */
  async addDelegated(contextRuleId: number, publicKey: string) {
    const { wallet } = this.deps.requireWallet();

    const signer: ContractSigner = {
      tag: "Delegated",
      values: [publicKey],
    };

    return wallet.add_signer({
      context_rule_id: contextRuleId,
      signer,
    });
  }

  /**
   * Remove a signer from a context rule by signer ID.
   */
  async remove(contextRuleId: number, signerId: number) {
    const { wallet } = this.deps.requireWallet();

    return wallet.remove_signer({
      context_rule_id: contextRuleId,
      signer_id: signerId,
    });
  }

  /**
   * Remove a passkey signer by credential ID.
   * Looks up the signer ID from local storage or on-chain, then removes.
   */
  async removePasskey(contextRuleId: number, credentialId: string) {
    const credential = await this.deps.storage.get(credentialId);
    if (!credential) {
      throw new Error(`Credential ${credentialId} not found in storage`);
    }

    const { wallet } = this.deps.requireWallet();

    // Use stored signerId if available, otherwise look up on-chain
    const storedSignerId = credential.signerId;
    let signerId: number;
    if (storedSignerId != null) {
      signerId = storedSignerId;
    } else {
      const keyData = buildKeyData(credential.publicKey, credentialId);
      const signer: ContractSigner = {
        tag: "External",
        values: [this.deps.webauthnVerifierAddress, keyData],
      };
      const result = await wallet.get_signer_id({ signer });
      if (result.result == null) {
        throw new Error(`Signer not found on-chain for credential ${credentialId}`);
      }
      signerId = result.result;
    }

    // Clean up local storage
    await this.deps.storage.delete(credentialId);

    return wallet.remove_signer({
      context_rule_id: contextRuleId,
      signer_id: signerId,
    });
  }
}
