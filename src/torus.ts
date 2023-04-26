// import type { INodePub } from "@toruslabs/fetch-node-details";
import { generatePrivate } from "@toruslabs/eccrypto";
import { setAPIKey, setEmbedHost } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import stringify from "json-stable-stringify";

import {
  _retrieveOrImportShare,
  generateAddressFromPubKey,
  generateRandomPolynomial,
  GetOrSetNonceError,
  GetPubKeyOrKeyAssign,
  keccak256,
} from "./helpers";
import {
  ImportedShare,
  NonceMetadataParams,
  RetrieveSharesResponse,
  SetNonceData,
  TorusCtorOptions,
  TorusPublicKey,
  VerifierParams,
} from "./interfaces";
import log from "./loglevel";

// Implement threshold logic wrappers around public APIs
// of Torus nodes to handle malicious node responses
class Torus {
  public allowHost: string;

  public serverTimeOffset: number;

  public signerHost: string;

  public network: string;

  public clientId: string;

  public ec: EC;

  constructor({ clientId, serverTimeOffset = 0, network }: TorusCtorOptions) {
    if (!clientId) throw Error("Please provide a valid clientId in constructor");
    if (!network) throw Error("Please provide a valid network in constructor");
    this.ec = new EC("secp256k1");
    this.serverTimeOffset = serverTimeOffset || 0; // ms
    this.network = network;
    this.clientId = clientId;
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

  async retrieveShares(
    endpoints: string[],
    verifier: string,
    verifierParams: VerifierParams,
    idToken: string,
    extraParams: Record<string, unknown> = {}
  ): Promise<RetrieveSharesResponse> {
    return _retrieveOrImportShare(this.ec, endpoints, verifier, verifierParams, idToken, undefined, extraParams);
  }

  generateNonceMetadataParams(operation: string, privateKey: BN, nonce?: BN): NonceMetadataParams {
    const key = this.ec.keyFromPrivate(privateKey.toString("hex", 64));
    const setData: Partial<SetNonceData> = {
      operation,
      timestamp: new BN(~~(this.serverTimeOffset + Date.now() / 1000)).toString(16),
    };

    if (nonce) {
      setData.data = nonce.toString("hex", 64);
    }
    const sig = key.sign(keccak256(stringify(setData)).slice(2));
    return {
      pub_key_X: key.getPublic().getX().toString("hex", 64),
      pub_key_Y: key.getPublic().getY().toString("hex", 64),
      set_data: setData,
      signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN("").toString(16, 2), "hex").toString("base64"),
    };
  }

  async getPublicAddress(
    endpoints: string[],
    { verifier, verifierId, extendedVerifierId }: { verifier: string; verifierId: string; extendedVerifierId?: string },
    isExtended = false
  ): Promise<string | TorusPublicKey> {
    log.debug("> torus.js/getPublicAddress", { endpoints, verifier, verifierId, isExtended });
    const keyAssignResult = await GetPubKeyOrKeyAssign(endpoints, verifier, verifierId, extendedVerifierId);
    const { errorResult, keyResult, nonceResult } = keyAssignResult;
    if (errorResult && JSON.stringify(errorResult).toLowerCase().includes("verifier not supported")) {
      // change error msg
      throw new Error(`Verifier not supported. Check if you: \n
      1. Are on the right network (Torus testnet/mainnet) \n
      2. Have setup a verifier on dashboard.web3auth.io?`);
    }
    if (errorResult) {
      throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }
    log.debug("> torus.js/getPublicAddress", { keyResult });
    if (!keyResult?.keys) {
      throw new Error(`node results do not match at final lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }

    // no need of nonce for extendedVerifierId (tss verifier id)
    if (!nonceResult && !extendedVerifierId) {
      throw new GetOrSetNonceError("metadata nonce is missing in share response");
    }
    let { pub_key_X: X, pub_key_Y: Y } = keyResult.keys[0];
    let modifiedPubKey: curve.base.BasePoint;
    let pubNonce: { x: string; y: string } | undefined;
    const nonce = new BN(nonceResult?.nonce || "0", 16);

    if (extendedVerifierId) {
      // for tss key no need to add pub nonce
      modifiedPubKey = this.ec.keyFromPublic({ x: X, y: Y }).getPublic();
    } else {
      modifiedPubKey = this.ec
        .keyFromPublic({ x: X, y: Y })
        .getPublic()
        .add(this.ec.keyFromPublic({ x: nonceResult.pubNonce.x, y: nonceResult.pubNonce.y }).getPublic());
      pubNonce = nonceResult.pubNonce;
    }

    X = modifiedPubKey.getX().toString(16, 64);
    Y = modifiedPubKey.getY().toString(16, 64);

    const address = generateAddressFromPubKey(this.ec, modifiedPubKey.getX(), modifiedPubKey.getY());
    log.debug("> torus.js/getPublicAddress", { X, Y, address, nonce: nonce?.toString(16), pubNonce });

    if (!isExtended) return address;
    return {
      address,
      X,
      Y,
      metadataNonce: nonce,
      pubNonce,
      upgraded: nonceResult.upgraded,
    };
  }

  async importPrivateKey(
    endpoints: string[],
    verifier: string,
    verifierParams: VerifierParams,
    idToken: string,
    newPrivateKey: string,
    extraParams: Record<string, unknown> = {}
  ): Promise<RetrieveSharesResponse> {
    const threshold = ~~(endpoints.length / 2) + 1;
    const degree = threshold - 1;
    const shareIndexes: BN[] = [];

    const key = this.ec.keyFromPrivate(newPrivateKey.padStart(64, "0"), "hex");
    for (let i = 0; i < endpoints.length; i++) {
      const shareIndex = new BN(i + 1, "hex");
      shareIndexes.push(shareIndex);
    }
    const privKeyBn = key.getPrivate();
    const randomNonce = new BN(generatePrivate());

    const oauthKey = privKeyBn.sub(randomNonce).umod(this.ec.curve.n);
    const oauthPubKey = this.ec.keyFromPrivate(oauthKey.toString("hex").padStart(64, "0")).getPublic();
    const poly = generateRandomPolynomial(this.ec, degree, oauthKey);
    const shares = poly.generateShares(shareIndexes);
    const nonceParams = this.generateNonceMetadataParams("getOrSetNonce", oauthKey, randomNonce);
    const sharesData: ImportedShare[] = [];
    for (let i = 0; i < shareIndexes.length; i++) {
      const shareJson = shares[shareIndexes[i].toString("hex", 64)].toJSON() as Record<string, string>;
      const nonceData = Buffer.from(stringify(nonceParams.set_data), "utf8").toString("base64");
      const shareData: ImportedShare = {
        pub_key_x: oauthPubKey.getX().toString("hex", 64),
        pub_key_y: oauthPubKey.getY().toString("hex", 64),
        share: shareJson.share,
        node_index: Number.parseInt(shareJson.shareIndex, 16),
        key_type: "secp256k1",
        nonce_data: nonceData,
        nonce_signature: nonceParams.signature,
      };
      sharesData.push(shareData);
    }

    return _retrieveOrImportShare(this.ec, endpoints, verifier, verifierParams, idToken, sharesData, extraParams);
  }
}

export default Torus;
