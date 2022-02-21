import BN from "bn.js";
import { ec } from "elliptic";

export interface GetOrSetNonceParams {
  pub_key_X: string;
  pub_key_Y: string;
  set_data: {
    data: "getNonce" | "getOrSetNonce" | string;
    timestamp: string;
  };
  signature: string;
}

export interface MetadataResponse {
  message: string;
}

export interface MetadataParams {
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
}

export interface TorusPublicKey extends TorusNodePub {
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

type PrivateKey = Uint8Array | Buffer | string | number[] | ec.KeyPair;
// type PrivateKey = number | string | number[] | Uint8Array | Buffer | BN
export type PublicKey = Uint8Array | Buffer | string | number[] | { x: string; y: string } | ec.KeyPair;
// Uint8Array | Buffer | string | number[] | { x: string; y: string } | ec.KeyPair

export interface KeyLookupResult {
  keyResult: {
    keys: { pub_key_X: string; pub_key_Y: string }[];
  };
  errorResult: Record<string, string>;
}

export interface SetCustomKeyOptions {
  privKeyHex?: string;
  metadataNonce?: BN;
  torusKeyHex?: string;
  customKeyHex: BN;
}

export interface V1UserTypeAndAddress {
  typeOfUser: "v1";
  nonce?: string;
  X: string;
  Y: string;
  address: string;
}

export interface V2UserTypeAndAddress {
  typeOfUser: "v2";
  nonce?: string;
  pubNonce: { x: string; y: string };
  ipfs?: string;
  upgraded?: boolean;
  X: string;
  Y: string;
  address: string;
}