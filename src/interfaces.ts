import { Ecies } from "@toruslabs/eccrypto";
import type { INodePub } from "@toruslabs/fetch-node-details";
import BN from "bn.js";

export interface KeyIndex {
  index: string;
  service_group_id: string;
}

export type GetOrSetNonceResult =
  | { typeOfUser: "v1"; nonce?: string }
  | { typeOfUser: "v2"; nonce?: string; pubNonce: { x: string; y: string }; ipfs?: string; upgraded: boolean };

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

export interface TorusCtorOptions {
  enableOneKey?: boolean;
  metadataHost?: string;
  allowHost?: string;
  serverTimeOffset?: number;
  signerHost?: string;
  network?: string;
}

export interface TorusPublicKey extends INodePub {
  typeOfUser: "v1" | "v2";
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
  keys: { pub_key_X: string; pub_key_Y: string; key_index: KeyIndex; address: string }[];
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

export interface V2UserTypeAndAddress {
  typeOfUser: "v2";
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
}

export interface ShareRequestResult {
  keys: KeyAssignment[];
  session_tokens: string[];
  session_token_sigs: string[];
  node_pubx: string[];
  node_puby: string[];
}

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
  typeOfUser: "v1" | "v2";
}

export interface VerifierParams {
  [key: string]: unknown;
  verifier_id: string;
}
