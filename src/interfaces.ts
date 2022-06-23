import { Ecies } from "@toruslabs/eccrypto";
import type { INodePub } from "@toruslabs/fetch-node-details";
import BN from "bn.js";

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
  sapphireEndpoints?: string[];
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
  keys: { pub_key_X: string; pub_key_Y: string; key_index: string; address: string }[];
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
  // torusNodePubs: INodePub[];
  // lastPoint?: number;
  // firstPoint?: number;
  verifier: string;
  verifierId: string;
  // signerHost: string;
  // network: string;
}

export interface KeyAssignment {
  Index: string;
  PublicKey: {
    X: string;
    Y: string;
  };
  Threshold: number;
  Verifiers: Record<string, string>;
  Share: string;
  Metadata: {
    [key in keyof Ecies]: string;
  };
}

export interface Point {
  x: BN;
  y: BN;
}

export interface PointString {
  x: string;
  y: string;
}

export interface KeyAssignResult {
  keys: PointString[];
}

export interface ShareRequestResultData {
  signature: string;
  data: string;
  node_pub_keyx: BN;
  node_pub_keyy: BN;
  pub_keys: PointString[];
}

// export interface ShareRequestResult {
//   keys: ShareRequestResultData[];
// }

export interface NodeTokenArr {
  tokens: ShareRequestResultData[];
}

export interface NodeToken {
  exp: string;
  temp_key_x: BN;
  temp_key_y: BN;
  verifier_name: string;
  verifier_id: string;
  scope: string;
}

export interface RetrieveSessionTokensResponse {
  // ethAddress: string;
  // privKey: string;
  // metadataNonce: BN;
  tokens: ShareRequestResultData[];
  pubkey_x: string;
  pubkey_y: string;
}

export interface VerifierParams {
  [key: string]: unknown;
  verifier_id: string;
}
