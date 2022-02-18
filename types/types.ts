import BN from 'bn.js'
import { ec } from 'elliptic'

export interface TorusCtorOptions {
  enableOneKey?: boolean
  metadataHost?: string
  allowHost?: string
  serverTimeOffset?: number
}

export interface TorusPublicKey extends TorusNodePub {
  typeOfUser: 'v1' | 'v2'
  address: string
  metadataNonce: BN
  pubNonce?: { x: string; y: string }
}

export interface TorusNodePub {
  X: string
  Y: string
}

export interface ShareResponse {
  ethAddress: string
  privKey: string
  metadataNonce: BN
}

export interface ExtraParams {
  [key: string]: unknown
}

export type Verifier = 'google' | 'facebook' | 'twitch' | 'reddit' | 'discord' | 'jwt' | string

type PrivateKey = Uint8Array | Buffer | string | number[] | ec.KeyPair
// type PrivateKey = number | string | number[] | Uint8Array | Buffer | BN
export type PublicKey = Uint8Array | Buffer | string | number[] | { x: string; y: string } | ec.KeyPair
// Uint8Array | Buffer | string | number[] | { x: string; y: string } | ec.KeyPair

export interface KeyLookupResult {
  keyResult: {
    keys: { pub_key_X: string; pub_key_Y: string }[]
  }
  errorResult: Record<string, string>
}

export interface SetCustomKeyOptions {
  privKeyHex?: string
  metadataNonce?: BN
  torusKeyHex?: string
  customKeyHex: BN
}
