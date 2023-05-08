import type { INodePub, TORUS_SAPPHIRE_NETWORK_TYPE } from "@toruslabs/constants";
import { Ecies } from "@toruslabs/eccrypto";
import BN from "bn.js";

export interface KeyIndex {
  index: string;
  service_group_id: string;
  tag: "imported" | "generated"; // we tag keys so that we can identify if generated using dkg or externally imported by user
}

export type GetOrSetNonceResult = { nonce?: string; pubNonce: { x: string; y: string }; ipfs?: string; upgraded: boolean };

export interface SetNonceData {
  operation: string;
  data: string;
  timestamp: string;
}

export interface NonceMetadataParams {
  namespace?: string;
  pub_key_X: string;
  pub_key_Y: string;
  set_data: Partial<SetNonceData>;
  signature: string;
}

export interface TorusCtorOptions {
  clientId: string;
  network: TORUS_SAPPHIRE_NETWORK_TYPE;
  enableOneKey?: boolean;
  serverTimeOffset?: number;
  allowHost?: string;
}

export interface TorusPublicKey extends INodePub {
  address: string;
  metadataNonce: BN;
  pubNonce?: { x: string; y: string };
  upgraded?: boolean;
  nodeIndexes?: number[];
}

export interface VerifierLookupResponse {
  keys: {
    pub_key_X: string;
    pub_key_Y: string;
    address: string;
    nonce_data?: GetOrSetNonceResult;
    created_at?: number;
  }[];
  is_new_key: boolean;
  node_index: number;
}

export interface CommitmentRequestResult {
  signature: string;
  data: string;
  nodepubx: string;
  nodepuby: string;
}

export interface JRPCResponse<T> {
  id: number;
  jsonrpc: "2.0";
  result?: T;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface KeyLookupResult {
  keyResult: VerifierLookupResponse;
  nodeIndexes: number[];
  errorResult: JRPCResponse<VerifierLookupResponse>["error"];
  nonceResult?: GetOrSetNonceResult;
}

export interface SignerResponse {
  "torus-timestamp": string;
  "torus-nonce": string;
  "torus-signature": string;
}

export interface KeyAssignInput {
  endpoints: string[];
  torusNodePubs: INodePub[];
  lastPoint?: number;
  firstPoint?: number;
  verifier: string;
  verifierId: string;
  signerHost: string;
  network: string;
  clientId: string;
}

export type EciesHex = {
  [key in keyof Ecies]: string;
} & { mode?: string };

export interface KeyAssignment {
  index: KeyIndex;
  public_key: {
    X: string;
    Y: string;
  };
  threshold: number;
  node_index: number;
  // this is encrypted ciphertext
  share: string;
  share_metadata: EciesHex;
  nonce_data?: GetOrSetNonceResult;
}

export interface ShareRequestResult {
  keys: KeyAssignment[];
  // these are encrypted ciphertexts
  session_tokens: string[];
  session_token_metadata: EciesHex[];
  // these are encrypted ciphertexts
  session_token_sigs: string[];
  session_token_sig_metadata: EciesHex[];
  node_pubx: string;
  node_puby: string;
}

export interface ImportedShare {
  pub_key_x: string;
  pub_key_y: string;
  encrypted_share: string;
  encrypted_share_metadata: EciesHex;
  node_index: number;
  key_type: string;
  nonce_data: string;
  nonce_signature: string;
}
export type ImportShareRequestResult = ShareRequestResult;

export interface SessionToken {
  token: string;
  signature: string;
  node_pubx: string;
  node_puby: string;
}
export interface RetrieveSharesResponse {
  ethAddress: string;
  privKey: string;
  sessionTokenData: SessionToken[];
  X: string;
  Y: string;
  metadataNonce: BN;
  postboxPubKeyX: string;
  postboxPubKeyY: string;
  sessionAuthKey: string;
  nodeIndexes: number[];
}

export interface VerifierParams {
  [key: string]: unknown;
  verifier_id: string;
  extended_verifier_id?: string;
}

export type BNString = string | BN;

export type StringifiedType = Record<string, unknown>;
