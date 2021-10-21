import BN from 'bn.js'

declare class Torus {
  public metadataHost: string
  public allowHost: string
  public serverTimeOffset: number
  public enableOneKey: boolean

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
  getNonce(pubKeyX: string, pubKeyY: string, privateKey?: BN, getOnly?: boolean): ReturnType<Torus['getOrSetNonce']>
  getPostboxKeyFrom1OutOf1(privKey: string, nonce: string): string
}

export as namespace TorusUtils

export = Torus

interface ExtraParams {
  [key: string]: unknown
}

interface TorusCtorOptions {
  enableOneKey?: boolean
  metadataHost?: string
  allowHost?: string
  serverTimeOffset?: number
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
