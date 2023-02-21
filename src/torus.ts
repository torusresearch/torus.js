// import type { INodePub } from "@toruslabs/fetch-node-details";
import { generatePrivate } from "@toruslabs/eccrypto";
import { Data, post, setAPIKey, setEmbedHost } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import stringify from "json-stable-stringify";

import {
  GetOrSetNonceResult,
  ImportedShare,
  MetadataParams,
  NonceMetadataParams,
  RetrieveSharesResponse,
  SetCustomKeyOptions,
  SetNonceData,
  TorusCtorOptions,
  TorusPublicKey,
  UserTypeAndAddress,
  VerifierLookupResponse,
  VerifierParams,
} from "./interfaces";
import { generateRandomPolynomial } from "./langrangeInterpolatePoly";
import log from "./loglevel";
import {
  _retrieveOrImportShare,
  convertMetadataToNonce,
  generateAddressFromPubKey,
  GetOrSetNonceError,
  GetPubKeyOrKeyAssign,
  keccak256,
  keyLookup,
} from "./utils";

// Implement threshold logic wrappers around public APIs
// of Torus nodes to handle malicious node responses
class Torus {
  public metadataHost: string;

  public allowHost: string;

  public serverTimeOffset: number;

  public signerHost: string;

  public network: string;

  protected ec: EC;

  constructor({ metadataHost, serverTimeOffset = 0, network = "mainnet" }: TorusCtorOptions = {}) {
    this.ec = new EC("secp256k1");
    this.metadataHost = metadataHost;
    this.serverTimeOffset = serverTimeOffset || 0; // ms
    this.network = network;
  }

  static enableLogging(v = true): void {
    if (v) log.enableAll();
    else log.disableAll();
  }

  static setAPIKey(apiKey: string): void {
    setAPIKey(apiKey);
  }

  static setEmbedHost(embedHost: string): void {
    setEmbedHost(embedHost);
  }

  static isGetOrSetNonceError(err: unknown): boolean {
    return err instanceof GetOrSetNonceError;
  }

  /**
   * Note: use this function only for openlogin tkey account lookups.
   */
  async getUserTypeAndAddress(
    endpoints: string[],
    { verifier, verifierId }: { verifier: string; verifierId: string },
    doesKeyAssign = false
  ): Promise<UserTypeAndAddress> {
    let finalKeyResult: VerifierLookupResponse;
    let finalNonceResult: GetOrSetNonceResult;
    if (doesKeyAssign) {
      const { keyResult, errorResult, nonceResult } = await GetPubKeyOrKeyAssign(endpoints, verifier, verifierId);
      if (errorResult && JSON.stringify(errorResult).includes("Verifier not supported")) {
        // change error msg
        throw new Error(`Verifier not supported. Check if you: \n
        1. Are on the right network (Torus testnet/mainnet) \n
        2. Have setup a verifier on dashboard.web3auth.io?`);
      } else if (errorResult) {
        throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
      }
      finalKeyResult = keyResult;
      finalNonceResult = nonceResult;
    } else {
      const { keyResult, errorResult } = (await keyLookup(endpoints, verifier, verifierId)) || {};
      if (errorResult && JSON.stringify(errorResult).includes("Verifier not supported")) {
        // change error msg
        throw new Error(`Verifier not supported. Check if you: \n
        1. Are on the right network (Torus testnet/mainnet) \n
        2. Have setup a verifier on dashboard.web3auth.io?`);
      } else if (errorResult && JSON.stringify(errorResult).includes("Verifier + VerifierID has not yet been assigned")) {
        throw new Error("Verifier + VerifierID has not yet been assigned");
      }
      finalKeyResult = keyResult;
    }

    if (finalKeyResult?.keys) {
      const { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0];
      let nonce: BN;

      if (!finalNonceResult) {
        try {
          finalNonceResult = await this.getOrSetNonce(X, Y, undefined, false);
          nonce = new BN(finalNonceResult.nonce || "0", 16);
        } catch {
          throw new GetOrSetNonceError("not able to fetch metadata nonce");
        }
      }

      const modifiedPubKey = this.ec
        .keyFromPublic({ x: X, y: Y })
        .getPublic()
        .add(this.ec.keyFromPublic({ x: finalNonceResult.pubNonce.x, y: finalNonceResult.pubNonce.y }).getPublic());

      const finalX = modifiedPubKey.getX().toString(16);
      const finalY = modifiedPubKey.getY().toString(16);
      const address = generateAddressFromPubKey(this.ec, modifiedPubKey.getX(), modifiedPubKey.getY());
      return {
        nonce,
        pubNonce: finalNonceResult.pubNonce,
        upgraded: finalNonceResult.upgraded,
        X: finalX,
        Y: finalY,
        address,
      };
    }

    throw new Error(
      `Failed to do key lookup for verifier: ${verifier} and verifierId: ${verifierId} Please report this issue ${JSON.stringify(
        finalKeyResult || {}
      )}`
    );
  }

  async setCustomKey({ privKeyHex, metadataNonce, torusKeyHex, customKeyHex }: SetCustomKeyOptions): Promise<void> {
    let torusKey: BN;
    if (torusKeyHex) {
      torusKey = new BN(torusKeyHex, 16);
    } else {
      const privKey = new BN(privKeyHex as string, 16);
      torusKey = privKey.sub(metadataNonce as BN).umod(this.ec.curve.n);
    }
    const customKey = new BN(customKeyHex, 16);
    const newMetadataNonce = customKey.sub(torusKey).umod(this.ec.curve.n);
    const data = this.generateMetadataParams(newMetadataNonce.toString(16), torusKey);
    await this.setMetadata(data);
  }

  async retrieveShares(
    endpoints: string[],
    verifier: string,
    verifierParams: VerifierParams,
    idToken: string,
    extraParams: Record<string, unknown> = {}
  ): Promise<RetrieveSharesResponse> {
    return _retrieveOrImportShare(this.ec, endpoints, verifier, verifierParams, idToken, undefined, extraParams);
  }

  async getMetadata(data: Omit<MetadataParams, "set_data" | "signature">, options: RequestInit = {}): Promise<BN> {
    try {
      const metadataResponse = await post<{ message?: string }>(`${this.metadataHost}/get`, data, options, { useAPIKey: true });
      return convertMetadataToNonce(metadataResponse);
    } catch (error) {
      log.error("get metadata error", error);
      return new BN(0);
    }
  }

  generateMetadataParams(message: string, privateKey: BN): MetadataParams {
    const key = this.ec.keyFromPrivate(privateKey.toString("hex", 64));
    const setData = {
      data: message,
      timestamp: new BN(~~(this.serverTimeOffset + Date.now() / 1000)).toString(16),
    };
    const sig = key.sign(keccak256(stringify(setData)).slice(2));
    return {
      pub_key_X: key.getPublic().getX().toString("hex"),
      pub_key_Y: key.getPublic().getY().toString("hex"),
      set_data: setData,
      signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN("").toString(16, 2), "hex").toString("base64"),
    };
  }

  generateNonceMetadataParams(operation: string, privateKey: BN, nonce?: BN): NonceMetadataParams {
    const key = this.ec.keyFromPrivate(privateKey.toString("hex", 64));
    const setData: Partial<SetNonceData> = {
      operation,
      timestamp: new BN(~~(this.serverTimeOffset + Date.now() / 1000)).toString(16),
    };

    if (nonce) {
      setData.data = nonce.toString("hex");
    }
    const sig = key.sign(keccak256(stringify(setData)).slice(2));
    return {
      pub_key_X: key.getPublic().getX().toString("hex"),
      pub_key_Y: key.getPublic().getY().toString("hex"),
      set_data: setData,
      signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN("").toString(16, 2), "hex").toString("base64"),
    };
  }

  async setMetadata(data: MetadataParams, options: RequestInit = {}): Promise<string> {
    try {
      const metadataResponse = await post<{ message: string }>(`${this.metadataHost}/set`, data, options, { useAPIKey: true });
      return metadataResponse.message; // IPFS hash
    } catch (error) {
      log.error("set metadata error", error);
      return "";
    }
  }

  /**
   * Note: use this function only with custom auth, don't use to lookup openlogin accounts.
   */
  async getPublicAddress(
    endpoints: string[],
    { verifier, verifierId, extendedVerifierId }: { verifier: string; verifierId: string; extendedVerifierId?: string },
    isExtended = false
  ): Promise<string | TorusPublicKey> {
    log.debug("> torus.js/getPublicAddress", { endpoints, verifier, verifierId, isExtended });

    const { keyResult, errorResult, nonceResult } = await GetPubKeyOrKeyAssign(endpoints, verifier, verifierId, extendedVerifierId);
    if (errorResult && JSON.stringify(errorResult).includes("Verifier not supported")) {
      // change error msg
      throw new Error(`Verifier not supported. Check if you: \n
      1. Are on the right network (Torus testnet/mainnet) \n
      2. Have setup a verifier on dashboard.web3auth.io?`);
    } else if (errorResult) {
      throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }
    const finalKeyResult: VerifierLookupResponse = keyResult;

    log.debug("> torus.js/getPublicAddress", { finalKeyResult });

    if (finalKeyResult?.keys) {
      // no need of nonce for extendedVerifierId
      if (!nonceResult && !extendedVerifierId) {
        throw new GetOrSetNonceError("metadata nonce is missing in share response");
      }
      let { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0];
      let modifiedPubKey: curve.base.BasePoint;
      let pubNonce: { x: string; y: string } | undefined;
      const nonce = new BN(nonceResult?.nonce || "0", 16);

      if (nonceResult?.upgraded || extendedVerifierId) {
        // OneKey is upgraded to 2/n, returned address is address of Torus key (postbox key), not tKey
        modifiedPubKey = this.ec.keyFromPublic({ x: X, y: Y }).getPublic();
      } else {
        modifiedPubKey = this.ec
          .keyFromPublic({ x: X, y: Y })
          .getPublic()
          .add(this.ec.keyFromPublic({ x: nonceResult.pubNonce.x, y: nonceResult.pubNonce.y }).getPublic());
        pubNonce = nonceResult.pubNonce;
      }

      X = modifiedPubKey.getX().toString(16);
      Y = modifiedPubKey.getY().toString(16);

      const address = generateAddressFromPubKey(this.ec, modifiedPubKey.getX(), modifiedPubKey.getY());
      log.debug("> torus.js/getPublicAddress", { X, Y, address, nonce: nonce?.toString(16), pubNonce });

      if (!isExtended) return address;
      return {
        address,
        X,
        Y,
        metadataNonce: nonce,
        pubNonce,
      };
    }
    throw new Error(`node results do not match at final lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
  }

  /**
   * Internal functions for OneKey (OpenLogin v2), only call these functions if you know what you're doing
   */

  async getOrSetNonce(X: string, Y: string, privKey?: BN, getOnly = false): Promise<GetOrSetNonceResult> {
    let data: Data;
    const msg = getOnly ? "getNonce" : "getOrSetNonce";
    if (privKey) {
      data = this.generateMetadataParams(msg, privKey);
    } else {
      data = {
        pub_key_X: X,
        pub_key_Y: Y,
        set_data: { operation: msg },
      };
    }
    return post<GetOrSetNonceResult>(`${this.metadataHost}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
  }

  async getNonce(X: string, Y: string, privKey?: BN): Promise<GetOrSetNonceResult> {
    return this.getOrSetNonce(X, Y, privKey, true);
  }

  getPostboxKeyFrom1OutOf1(privKey: string, nonce: string): string {
    const privKeyBN = new BN(privKey, 16);
    const nonceBN = new BN(nonce, 16);
    return privKeyBN.sub(nonceBN).umod(this.ec.curve.n).toString("hex");
  }

  async importPrivateKey(
    endpoints: string[],
    verifier: string,
    verifierParams: VerifierParams,
    idToken: string,
    privateKey: string,
    extraParams: Record<string, unknown> = {}
  ): Promise<RetrieveSharesResponse> {
    const threshold = 3;
    const degree = threshold - 1;
    const shareIndexes = [];

    const key = this.ec.keyFromPrivate(privateKey.padStart(64, "0"), "hex");
    for (let i = 0; i < endpoints.length; i++) {
      const shareIndex = new BN(i + 1, "hex");
      shareIndexes.push(shareIndex);
    }
    const privKeyBn = new BN(key.getPrivate(), "hex");
    const randomNonce = new BN(generatePrivate(), "hex");

    const oauthKey = privKeyBn.sub(randomNonce).umod(this.ec.curve.n);
    const oauthPubKey = this.ec.keyFromPrivate(oauthKey.toString("hex")).getPublic();

    const poly = generateRandomPolynomial(this.ec, degree, oauthKey);
    const shares = poly.generateShares(shareIndexes);
    const nonceParams = this.generateNonceMetadataParams("getOrSetNonce", oauthKey, randomNonce);
    const sharesData: ImportedShare[] = [];
    for (let i = 0; i < shareIndexes.length; i++) {
      const shareJson = shares[shareIndexes[i].toString("hex")].toJSON() as Record<string, string>;
      const nonceData = Buffer.from(stringify(nonceParams.set_data), "utf-8").toString("base64");
      const shareData: ImportedShare = {
        pub_key_x: oauthPubKey.getX().toString("hex"),
        pub_key_y: oauthPubKey.getY().toString("hex"),
        share: shareJson.share,
        node_index: parseInt(shareJson.shareIndex, 16),
        key_type: "secp256k1", // TODO: test for ed25519
        nonce_data: nonceData,
        nonce_signature: nonceParams.signature,
      };
      sharesData.push(shareData);
    }

    return _retrieveOrImportShare(this.ec, endpoints, verifier, verifierParams, idToken, sharesData, extraParams);
  }
}

export default Torus;
