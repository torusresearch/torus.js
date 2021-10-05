import BN from 'bn.js'

declare interface OneKeyUtils {
  retrieveShares(
    endpoints: string[],
    indexes: Number[],
    verifier: 'google' | 'facebook' | 'twitch' | 'reddit' | 'discord' | 'jwt' | string,
    verifierParams: VerifierParams,
    idToken: string,
    extraParams?: extraParams
  ): Promise<ShareResponse>
  getPublicAddress(
    endpoints: string[],
    torusNodePubs: TorusNodePub[],
    verifierArgs: VerifierArgs,
    isExtended: boolean
  ): Promise<string | TorusPublicKey>
}

declare class Torus {
  public metadataHost: string
  public allowHost: string
  public serverTimeOffset: number
  public oneKey: OneKeyUtils

  constructor(options?: TorusCtorOptions)
  static setAPIKey(apiKey: string): void
  static setEmbedHost(embedHost: string): void
  retrieveShares(
    endpoints: string[],
    indexes: Number[],
    verifier: 'google' | 'facebook' | 'twitch' | 'reddit' | 'discord' | 'jwt' | string,
    verifierParams: VerifierParams,
    idToken: string,
    extraParams?: extraParams
  ): Promise<ShareResponse>
  lagrangeInterpolation(shares: BN[], nodeIndex: BN[]): BN
  generateAddressFromPrivKey(privateKey: BN): string
  setCustomKey(options?: setCustomKeyOptions): Promise<void>
  getPublicAddress(
    endpoints: string[],
    torusNodePubs: TorusNodePub[],
    verifierArgs: VerifierArgs,
    isExtended: boolean
  ): Promise<string | TorusPublicKey>
  // Internal functions for OneKey (OpenLogin v2), do not call this directly if you don't know what you are doing
  getOrSetNonce(
    pubKeyX: string,
    pubKeyY: string,
    privateKey?: BN
  ): Promise<
    | { typeOfUser: 'v1'; nonce?: string }
    | {
        typeOfUser: 'v2'
        nonce?: string
        pubNonce: string
        ipfs?: string
        newUser: boolean
      }
  >
  retrieveOneKeyShares: OneKeyUtils['retrieveShares']
  getOneKeyPublicAddress: OneKeyUtils['getPublicAddress']
  getPostboxKeyFrom1OutOf1(privKey: string, nonce: string): string
}

export as namespace TorusUtils

export = Torus
interface extraParams {
  [key: string]: unknown
}

interface TorusCtorOptions {
  enableLogging?: boolean
  metadataHost?: string
  allowHost?: string
  serverTimeOffset?: number
}

interface TorusPublicKey extends TorusNodePub {
  address: string
  metadataNonce: BN
}

interface TorusPublicKeyV2 extends TorusPublicKey {
  typeOfUser: 'v1' | 'v2'
  newUser: boolean
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

interface setCustomKeyOptions {
  privKeyHex?: string
  metadataNonce?: BN
  torusKeyHex?: string
  customKeyHex: BN
}
