import type { INodePub, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
import { Ecies } from "@toruslabs/eccrypto";
import BN from "bn.js";

export interface KeyIndex {
  index: string;
  service_group_id: string;
  tag: "imported" | "generated"; // we tag keys so that we can identify if generated using dkg or externally imported by user
}

export type UserType = "v1" | "v2";
export type v2NonceResultType = { typeOfUser: "v2"; nonce?: string; pubNonce: { x: string; y: string }; ipfs?: string; upgraded: boolean };

export type v1NonceResultType = { typeOfUser: "v1"; nonce?: string };
export type GetOrSetNonceResult = v2NonceResultType | v1NonceResultType;

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
  network: TORUS_NETWORK_TYPE;
  enableOneKey?: boolean;
  serverTimeOffset?: number;
  allowHost?: string;
  legacyMetadataHost?: string;
}

export interface LegacyVerifierLookupResponse {
  keys: { pub_key_X: string; pub_key_Y: string; address: string }[];
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
  node_index: string;
}

export interface CommitmentRequestResult {
  signature: string;
  data: string;
  nodepubx: string;
  nodepuby: string;
  nodeindex: string;
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

export interface LegacyKeyLookupResult {
  keyResult: Pick<LegacyVerifierLookupResponse, "keys">;
  errorResult: JRPCResponse<LegacyVerifierLookupResponse>["error"];
}

export interface KeyLookupResult {
  keyResult: Pick<VerifierLookupResponse, "keys" | "is_new_key">;
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

export interface LegacyKeyAssignment {
  Index: string;
  PublicKey: {
    X: string;
    Y: string;
  };
  Threshold: string;
  Verifiers: Record<string, string>;
  Share: string;
  Metadata: {
    [key in keyof Ecies]: string;
  };
}
export interface KeyAssignment {
  index: KeyIndex;
  public_key: {
    X: string;
    Y: string;
  };
  threshold: string;
  node_index: string;
  // this is encrypted ciphertext
  share: string;
  share_metadata: EciesHex;
  nonce_data?: GetOrSetNonceResult;
}

export interface LegacyShareRequestResult {
  keys: LegacyKeyAssignment[];
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
  is_new_key: string;
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
export interface TorusPublicKey {
  finalKeyData: {
    evmAddress: string;
    X: string; // this is final pub x user before and after updating to 2/n
    Y: string; // this is final pub y user before and after updating to 2/n
  };
  oAuthKeyData: {
    evmAddress: string;
    X: string;
    Y: string;
  };
  metadata: {
    pubNonce?: { X: string; Y: string };
    nonce?: BN;
    typeOfUser: UserType;
    upgraded: boolean | null;
  };
  nodesData: {
    nodeIndexes: number[];
  };
}

export interface TorusKey {
  finalKeyData: TorusPublicKey["finalKeyData"] & {
    privKey?: string;
  };
  oAuthKeyData: TorusPublicKey["oAuthKeyData"] & {
    privKey: string;
  };
  sessionData: {
    sessionTokenData: SessionToken[];
    sessionAuthKey: string;
  };
  metadata: TorusPublicKey["metadata"] & Required<Pick<TorusPublicKey["metadata"], "nonce">>;
  nodesData: TorusPublicKey["nodesData"];
}

export interface VerifierParams {
  [key: string]: unknown;
  verifier_id: string;
  extended_verifier_id?: string;
}

export type BNString = string | BN;

export type StringifiedType = Record<string, unknown>;

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
