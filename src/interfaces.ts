import { Ecies } from "@toruslabs/eccrypto";
import type { INodePub } from "@toruslabs/fetch-node-details";
import BN from "bn.js";

export interface KeyIndex {
  index: string;
  service_group_id: string;
  tag: "imported" | "generated";
}

export type GetOrSetNonceResult = { nonce?: string; pubNonce: { x: string; y: string }; ipfs?: string; upgraded: boolean };

export interface MetadataResponse {
  message: string;
}

export interface MetadataParams {
  namespace?: string;
  pub_key_X: string;
  pub_key_Y: string;
  set_data: {
    data: "getNonce" | "getOrSetNonce" | string;
    timestamp: string;
  };
  signature: string;
}

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
  enableOneKey?: boolean;
  metadataHost?: string;
  serverTimeOffset?: number;
  network?: string;
}

export interface TorusPublicKey extends INodePub {
  address: string;
  metadataNonce: BN;
  pubNonce?: { x: string; y: string };
}

export interface ShareResponse {
  ethAddress: string;
  privKey: string;
  metadataNonce: BN;
}

export interface VerifierLookupResponse {
  keys: {
    pub_key_X: string;
    pub_key_Y: string;
    address: string;
    nonce_data?: GetOrSetNonceResult;
    key_metadata?: { message?: string };
  }[];
  is_new_key: boolean;
}

export interface CommitmentRequestResult {
  signature: string;
  data: string;
  nodepubx: string;
  nodepuby: string;
}

export interface SetCustomKeyOptions {
  privKeyHex?: string;
  metadataNonce?: BN;
  torusKeyHex?: string;
  customKeyHex: BN;
}

export interface V1UserTypeAndAddress {
  typeOfUser: "v1";
  nonce?: BN;
  X: string;
  Y: string;
  address: string;
}

export interface UserTypeAndAddress {
  nonce?: BN;
  pubNonce: { x: string; y: string };
  ipfs?: string;
  upgraded?: boolean;
  X: string;
  Y: string;
  address: string;
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
}

export interface KeyAssignment {
  index: KeyIndex;
  public_key: {
    X: string;
    Y: string;
  };
  threshold: number;
  verifiers: Record<string, string>;
  share: string;
  node_index: number;
  metadata: {
    [key in keyof Ecies]: string;
  };
  nonce_data?: GetOrSetNonceResult;
  key_metadata?: { message?: string };
}

export interface ShareRequestResult {
  keys: KeyAssignment[];
  session_tokens: string[];
  session_token_sigs: string[];
  node_pubx: string[];
  node_puby: string[];
}

export interface ImportedShare {
  pub_key_x: string;
  pub_key_y: string;
  share: string;
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
  metadataNonce: BN;
  sessionTokensData: SessionToken[];
  X: string;
  Y: string;
}

export interface VerifierParams {
  [key: string]: unknown;
  verifier_id: string;
  extended_verifier_id?: string;
}

export type BNString = string | BN;

export type StringifiedType = Record<string, unknown>;
