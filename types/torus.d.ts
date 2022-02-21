import BN from 'bn.js'
import { INodePub } from '@toruslabs/fetch-node-details'

declare class Torus {
  public metadataHost: string
  public allowHost: string
  public serverTimeOffset: number
  public enableOneKey: boolean
  public signerHost: string

  constructor(options?: TorusCtorOptions)
  static setAPIKey(apiKey: string): void
  static setEmbedHost(embedHost: string): void
  static enableLogging(enabled?: boolean): void

  retrieveShares(
    endpoints: string[],
    indexes: Number[],
    verifier: 'google' | 'facebook' | 'twitch' | 'reddit' | 'discord' | 'jwt' | string,
    verifierParams: VerifierParams,
    idToken: string,
    extraParams?: ExtraParams
  ): Promise<ShareResponse>
  lagrangeInterpolation(shares: BN[], nodeIndex: BN[]): BN
  generateAddressFromPrivKey(privateKey: BN): string
  setCustomKey(options?: SetCustomKeyOptions): Promise<void>

  /**
   *
   * @note: Use this function to lookup customauth accounts.
   */
  getPublicAddress(
    endpoints: string[],
    torusNodePubs: TorusNodePub[],
    verifierArgs: VerifierArgs,
    isExtended: boolean
  ): Promise<string | TorusPublicKey>

  // Internal functions for OneKey (OpenLogin v2), only call these functions if you know what you're doing
  static isGetOrSetNonceError(err: unknown): boolean
  getOrSetNonce(
    pubKeyX: string,
    pubKeyY: string,
    privateKey?: BN,
    getOnly?: boolean
  ): Promise<
    { typeOfUser: 'v1'; nonce?: string } | { typeOfUser: 'v2'; nonce?: string; pubNonce: { x: string; y: string }; ipfs?: string; upgraded?: boolean }
  >
  /**
   *
   * @note: Use this function only to lookup openlogin tkey accounts.
   */
  getUserTypeAndAddress(
    endpoints: string[],
    torusNodePubs: TorusNodePub[],
    verifierArgs: VerifierArgs,
    doesKeyAssign?: boolean
  ): Promise<
    | { typeOfUser: 'v1'; nonce?: string; X: string; Y: string; address: string }
    | {
        typeOfUser: 'v2'
        nonce?: string
        pubNonce: { x: string; y: string }
        ipfs?: string
        upgraded?: boolean
        X: string
        Y: string
        address: string
      }
  >
  getNonce(pubKeyX: string, pubKeyY: string, privateKey?: BN, getOnly?: boolean): ReturnType<Torus['getOrSetNonce']>
  getPostboxKeyFrom1OutOf1(privKey: string, nonce: string): string
}

export as namespace TorusUtils

export default Torus

export function waitKeyLookup(endpoints: string[], verifier: string, verifierId: string, timeout: number): Promise<KeyLookupResult>
export function keyLookup(endpoints: string[], verifier: string, verifierId: string): Promise<KeyLookupResult>
export function keyAssign(options: {
  endpoints: string[]
  torusNodePubs: INodePub[]
  lastPoint: number
  firstPoint: number
  verifier: string
  verifierId: string
  signerHost: string
}): Promise<void>

interface KeyLookupResult {
  keyResult: {
    keys: { pub_key_X: string; pub_key_Y: string }[]
  }
  errorResult: Record<string, string>
}

interface ExtraParams {
  [key: string]: unknown
}

interface TorusCtorOptions {
  enableOneKey?: boolean
  metadataHost?: string
  allowHost?: string
  serverTimeOffset?: number
  signerHost?: string
}

interface TorusPublicKey extends TorusNodePub {
  typeOfUser: 'v1' | 'v2'
  address: string
  metadataNonce: BN
  pubNonce?: { x: string; y: string }
}

interface TorusNodePub {
  X: string
  Y: string
}

interface ShareResponse {
  ethAddress: string
  privKey: string
  metadataNonce: BN
}

interface VerifierArgs {
  verifier: 'google' | 'facebook' | 'twitch' | 'reddit' | 'discord' | 'jwt' | string
  verifierId: string
}

interface VerifierParams {
  verifier_id: string
}

interface SetCustomKeyOptions {
  privKeyHex?: string
  metadataNonce?: BN
  torusKeyHex?: string
  customKeyHex: BN
}
