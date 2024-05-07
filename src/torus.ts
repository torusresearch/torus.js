import { INodePub, LEGACY_NETWORKS_ROUTE_MAP, METADATA_MAP, SIGNER_MAP, TORUS_LEGACY_NETWORK_TYPE, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
import { Ecies, encrypt, generatePrivate } from "@toruslabs/eccrypto";
import { setAPIKey, setEmbedHost } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import stringify from "json-stable-stringify";

import { config } from "./config";
import {
  encParamsBufToHex,
  generateAddressFromPubKey,
  generateRandomPolynomial,
  getMetadata,
  getOrSetNonce,
  GetOrSetNonceError,
  GetPubKeyOrKeyAssign,
  keccak256,
  retrieveOrImportShare,
} from "./helpers";
import {
  GetOrSetNonceResult,
  ImportedShare,
  LegacyVerifierLookupResponse,
  NonceMetadataParams,
  SetNonceData,
  TorusCtorOptions,
  TorusKey,
  TorusPublicKey,
  v2NonceResultType,
  VerifierParams,
} from "./interfaces";
import log from "./loglevel";

// Implement threshold logic wrappers around public APIs
// of Torus nodes to handle malicious node responses
class Torus {
  private static sessionTime: number = 86400; // 86400 = 24 hour

  public allowHost: string;

  public serverTimeOffset: number;

  public network: TORUS_NETWORK_TYPE;

  public clientId: string;

  public ec: EC;

  public enableOneKey: boolean;

  private legacyMetadataHost: string;

  constructor({ enableOneKey = false, clientId, network, serverTimeOffset = 0, allowHost, legacyMetadataHost }: TorusCtorOptions) {
    if (!clientId) throw Error("Please provide a valid clientId in constructor");
    if (!network) throw Error("Please provide a valid network in constructor");
    this.ec = new EC("secp256k1");
    this.serverTimeOffset = serverTimeOffset || 0; // ms
    this.network = network;
    this.clientId = clientId;
    this.allowHost = allowHost || `${SIGNER_MAP[network]}/api/allow`;
    this.enableOneKey = enableOneKey;
    this.legacyMetadataHost = legacyMetadataHost || METADATA_MAP[network as TORUS_LEGACY_NETWORK_TYPE];
  }

  static enableLogging(v = true): void {
    if (v) {
      log.enableAll();
      config.logRequestTracing = true;
    } else log.disableAll();
  }

  static setAPIKey(apiKey: string): void {
    setAPIKey(apiKey);
  }

  static setEmbedHost(embedHost: string): void {
    setEmbedHost(embedHost);
  }

  static setSessionTime(sessionTime: number): void {
    Torus.sessionTime = sessionTime;
  }

  static isGetOrSetNonceError(err: unknown): boolean {
    return err instanceof GetOrSetNonceError;
  }

  static getPostboxKey(torusKey: TorusKey): string {
    if (torusKey.metadata.typeOfUser === "v1") {
      return torusKey.finalKeyData.privKey || torusKey.oAuthKeyData.privKey;
    }
    return torusKey.oAuthKeyData.privKey;
  }

  async retrieveShares(
    endpoints: string[],
    indexes: number[],
    verifier: string,
    verifierParams: VerifierParams,
    idToken: string,
    extraParams: Record<string, unknown> = {}
  ): Promise<TorusKey> {
    return retrieveOrImportShare({
      legacyMetadataHost: this.legacyMetadataHost,
      serverTimeOffset: this.serverTimeOffset,
      enableOneKey: this.enableOneKey,
      ecCurve: this.ec,
      allowHost: this.allowHost,
      network: this.network,
      clientId: this.clientId,
      endpoints,
      verifier,
      verifierParams,
      idToken,
      indexes,
      importedShares: [],
      extraParams: {
        ...extraParams,
        session_token_exp_second: Torus.sessionTime,
      },
    });
  }

  async getPublicAddress(
    endpoints: string[],
    torusNodePubs: INodePub[],
    { verifier, verifierId, extendedVerifierId }: { verifier: string; verifierId: string; extendedVerifierId?: string }
  ): Promise<TorusPublicKey> {
    log.info(torusNodePubs, { verifier, verifierId, extendedVerifierId });
    return this.getNewPublicAddress(endpoints, { verifier, verifierId, extendedVerifierId }, this.enableOneKey);
  }

  async importPrivateKey(
    endpoints: string[],
    nodeIndexes: number[],
    nodePubkeys: INodePub[],
    verifier: string,
    verifierParams: VerifierParams,
    idToken: string,
    newPrivateKey: string,
    extraParams: Record<string, unknown> = {}
  ): Promise<TorusKey> {
    if (endpoints.length !== nodeIndexes.length) {
      throw new Error(`length of endpoints array must be same as length of nodeIndexes array`);
    }
    const threshold = ~~(endpoints.length / 2) + 1;
    const degree = threshold - 1;
    const nodeIndexesBn: BN[] = [];

    const key = this.ec.keyFromPrivate(newPrivateKey.padStart(64, "0"), "hex");
    for (const nodeIndex of nodeIndexes) {
      nodeIndexesBn.push(new BN(nodeIndex));
    }
    const privKeyBn = key.getPrivate();
    const randomNonce = new BN(generatePrivate());

    const oAuthKey = privKeyBn.sub(randomNonce).umod(this.ec.curve.n);
    const oAuthPubKey = this.ec.keyFromPrivate(oAuthKey.toString("hex").padStart(64, "0")).getPublic();
    const poly = generateRandomPolynomial(this.ec, degree, oAuthKey);
    const shares = poly.generateShares(nodeIndexesBn);
    const nonceParams = this.generateNonceMetadataParams("getOrSetNonce", oAuthKey, randomNonce);
    const nonceData = Buffer.from(stringify(nonceParams.set_data), "utf8").toString("base64");
    const sharesData: ImportedShare[] = [];
    const encPromises: Promise<Ecies>[] = [];
    for (let i = 0; i < nodeIndexesBn.length; i++) {
      const shareJson = shares[nodeIndexesBn[i].toString("hex", 64)].toJSON() as Record<string, string>;
      if (!nodePubkeys[i]) {
        throw new Error(`Missing node pub key for node index: ${nodeIndexesBn[i].toString("hex", 64)}`);
      }
      const nodePubKey = this.ec.keyFromPublic({ x: nodePubkeys[i].X, y: nodePubkeys[i].Y });
      encPromises.push(encrypt(Buffer.from(nodePubKey.getPublic().encodeCompressed("hex"), "hex"), Buffer.from(shareJson.share, "hex")));
    }
    const encShares = await Promise.all(encPromises);
    for (let i = 0; i < nodeIndexesBn.length; i++) {
      const shareJson = shares[nodeIndexesBn[i].toString("hex", 64)].toJSON() as Record<string, string>;
      const encParams = encShares[i];
      const encParamsMetadata = encParamsBufToHex(encParams);
      const shareData: ImportedShare = {
        pub_key_x: oAuthPubKey.getX().toString("hex", 64),
        pub_key_y: oAuthPubKey.getY().toString("hex", 64),
        encrypted_share: encParamsMetadata.ciphertext,
        encrypted_share_metadata: encParamsMetadata,
        node_index: Number.parseInt(shareJson.shareIndex, 16),
        key_type: "secp256k1",
        nonce_data: nonceData,
        nonce_signature: nonceParams.signature,
      };
      sharesData.push(shareData);
    }

    return retrieveOrImportShare({
      legacyMetadataHost: this.legacyMetadataHost,
      serverTimeOffset: this.serverTimeOffset,
      enableOneKey: this.enableOneKey,
      ecCurve: this.ec,
      allowHost: this.allowHost,
      network: this.network,
      clientId: this.clientId,
      endpoints,
      verifier,
      verifierParams,
      idToken,
      indexes: nodeIndexes,
      importedShares: sharesData,
      extraParams: {
        ...extraParams,
        session_token_exp_second: Torus.sessionTime,
      },
    });
  }

  /**
   * Note: use this function only for openlogin tkey account lookups.
   * this is a legacy function, use getPublicAddress instead for new networks
   */
  async getUserTypeAndAddress(
    endpoints: string[],
    torusNodePubs: INodePub[],
    { verifier, verifierId, extendedVerifierId }: { verifier: string; verifierId: string; extendedVerifierId?: string }
  ): Promise<TorusPublicKey> {
    log.info(torusNodePubs, { verifier, verifierId, extendedVerifierId });
    return this.getNewPublicAddress(endpoints, { verifier, verifierId, extendedVerifierId }, true) as Promise<TorusPublicKey>;
  }

  private generateNonceMetadataParams(operation: string, privateKey: BN, nonce?: BN): NonceMetadataParams {
    const key = this.ec.keyFromPrivate(privateKey.toString("hex", 64));
    const setData: Partial<SetNonceData> = {
      operation,
      timestamp: new BN(~~(this.serverTimeOffset + Date.now() / 1000)).toString(16),
    };

    if (nonce) {
      setData.data = nonce.toString("hex", 64);
    }
    const sig = key.sign(keccak256(Buffer.from(stringify(setData), "utf8")).slice(2));
    return {
      pub_key_X: key.getPublic().getX().toString("hex", 64),
      pub_key_Y: key.getPublic().getY().toString("hex", 64),
      set_data: setData,
      signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN("").toString(16, 2), "hex").toString("base64"),
    };
  }

  private async getNewPublicAddress(
    endpoints: string[],
    { verifier, verifierId, extendedVerifierId }: { verifier: string; verifierId: string; extendedVerifierId?: string },
    enableOneKey: boolean
  ): Promise<TorusPublicKey> {
    const keyAssignResult = await GetPubKeyOrKeyAssign({
      endpoints,
      network: this.network,
      verifier,
      verifierId,
      extendedVerifierId,
    });
    const { errorResult, keyResult, nodeIndexes = [], serverTimeOffset } = keyAssignResult;
    const finalServerTimeOffset = this.serverTimeOffset || serverTimeOffset;
    const { nonceResult } = keyAssignResult;
    if (errorResult && JSON.stringify(errorResult).toLowerCase().includes("verifier not supported")) {
      // change error msg
      throw new Error(`Verifier not supported. Check if you: \n
      1. Are on the right network (Torus testnet/mainnet) \n
      2. Have setup a verifier on dashboard.web3auth.io?`);
    }
    if (errorResult) {
      throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }
    if (!keyResult?.keys) {
      throw new Error(`node results do not match at final lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }

    // no need of nonce for extendedVerifierId (tss verifier id)
    if (!nonceResult && !extendedVerifierId && !LEGACY_NETWORKS_ROUTE_MAP[this.network as TORUS_LEGACY_NETWORK_TYPE]) {
      throw new GetOrSetNonceError("metadata nonce is missing in share response");
    }
    const { pub_key_X: X, pub_key_Y: Y } = keyResult.keys[0];
    let pubNonce: { X: string; Y: string } | undefined;
    const nonce = new BN(nonceResult?.nonce || "0", 16);
    let oAuthPubKey: curve.base.BasePoint;
    let finalPubKey: curve.base.BasePoint;
    if (extendedVerifierId) {
      // for tss key no need to add pub nonce
      finalPubKey = this.ec.keyFromPublic({ x: X, y: Y }).getPublic();
      oAuthPubKey = finalPubKey;
    } else if (LEGACY_NETWORKS_ROUTE_MAP[this.network as TORUS_LEGACY_NETWORK_TYPE]) {
      return this.formatLegacyPublicKeyData({
        isNewKey: keyResult.is_new_key,
        enableOneKey,
        finalKeyResult: {
          keys: keyResult.keys,
        },
        serverTimeOffset: finalServerTimeOffset,
      });
    } else {
      const v2NonceResult = nonceResult as v2NonceResultType;
      oAuthPubKey = this.ec.keyFromPublic({ x: X, y: Y }).getPublic();
      finalPubKey = this.ec
        .keyFromPublic({ x: X, y: Y })
        .getPublic()
        .add(this.ec.keyFromPublic({ x: v2NonceResult.pubNonce.x, y: v2NonceResult.pubNonce.y }).getPublic());

      pubNonce = { X: v2NonceResult.pubNonce.x, Y: v2NonceResult.pubNonce.y };
    }

    if (!oAuthPubKey) {
      throw new Error("Unable to derive oAuthPubKey");
    }
    const oAuthX = oAuthPubKey.getX().toString(16, 64);
    const oAuthY = oAuthPubKey.getY().toString(16, 64);
    const oAuthAddress = generateAddressFromPubKey(this.ec, oAuthPubKey.getX(), oAuthPubKey.getY());

    if (!finalPubKey) {
      throw new Error("Unable to derive finalPubKey");
    }
    const finalX = finalPubKey ? finalPubKey.getX().toString(16, 64) : "";
    const finalY = finalPubKey ? finalPubKey.getY().toString(16, 64) : "";
    const finalAddress = finalPubKey ? generateAddressFromPubKey(this.ec, finalPubKey.getX(), finalPubKey.getY()) : "";
    return {
      oAuthKeyData: {
        evmAddress: oAuthAddress,
        X: oAuthX,
        Y: oAuthY,
      },
      finalKeyData: {
        evmAddress: finalAddress,
        X: finalX,
        Y: finalY,
      },
      metadata: {
        pubNonce,
        nonce,
        upgraded: (nonceResult as v2NonceResultType)?.upgraded || false,
        typeOfUser: "v2",
        serverTimeOffset: finalServerTimeOffset,
      },
      nodesData: {
        nodeIndexes,
      },
    };
  }

  private async formatLegacyPublicKeyData(params: {
    finalKeyResult: LegacyVerifierLookupResponse;
    enableOneKey: boolean;
    isNewKey: boolean;
    serverTimeOffset: number;
  }): Promise<TorusPublicKey> {
    const { finalKeyResult, enableOneKey, isNewKey, serverTimeOffset } = params;
    const { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0];
    let nonceResult: GetOrSetNonceResult;
    let nonce: BN;
    let finalPubKey: curve.base.BasePoint;
    let typeOfUser: GetOrSetNonceResult["typeOfUser"];
    let pubNonce: { X: string; Y: string } | undefined;

    const oAuthPubKey = this.ec.keyFromPublic({ x: X, y: Y }).getPublic();

    const finalServerTimeOffset = this.serverTimeOffset || serverTimeOffset;
    if (enableOneKey) {
      try {
        nonceResult = await getOrSetNonce(this.legacyMetadataHost, this.ec, finalServerTimeOffset, X, Y, undefined, !isNewKey);
        nonce = new BN(nonceResult.nonce || "0", 16);
        typeOfUser = nonceResult.typeOfUser;
      } catch {
        throw new GetOrSetNonceError();
      }
      if (nonceResult.typeOfUser === "v1") {
        nonce = await getMetadata(this.legacyMetadataHost, { pub_key_X: X, pub_key_Y: Y });
        finalPubKey = this.ec
          .keyFromPublic({ x: X, y: Y })
          .getPublic()
          .add(this.ec.keyFromPrivate(nonce.toString(16, 64), "hex").getPublic());
      } else if (nonceResult.typeOfUser === "v2") {
        finalPubKey = this.ec
          .keyFromPublic({ x: X, y: Y })
          .getPublic()
          .add(this.ec.keyFromPublic({ x: nonceResult.pubNonce.x, y: nonceResult.pubNonce.y }).getPublic());
        pubNonce = { X: nonceResult.pubNonce.x, Y: nonceResult.pubNonce.y };
      } else {
        throw new Error("getOrSetNonce should always return typeOfUser.");
      }
    } else {
      typeOfUser = "v1";
      nonce = await getMetadata(this.legacyMetadataHost, { pub_key_X: X, pub_key_Y: Y });
      finalPubKey = this.ec
        .keyFromPublic({ x: X, y: Y })
        .getPublic()
        .add(this.ec.keyFromPrivate(nonce.toString(16, 64), "hex").getPublic());
    }

    if (!oAuthPubKey) {
      throw new Error("Unable to derive oAuthPubKey");
    }
    const oAuthX = oAuthPubKey.getX().toString(16, 64);
    const oAuthY = oAuthPubKey.getY().toString(16, 64);
    const oAuthAddress = generateAddressFromPubKey(this.ec, oAuthPubKey.getX(), oAuthPubKey.getY());

    if (typeOfUser === "v2" && !finalPubKey) {
      throw new Error("Unable to derive finalPubKey");
    }
    const finalX = finalPubKey ? finalPubKey.getX().toString(16, 64) : "";
    const finalY = finalPubKey ? finalPubKey.getY().toString(16, 64) : "";
    const finalAddress = finalPubKey ? generateAddressFromPubKey(this.ec, finalPubKey.getX(), finalPubKey.getY()) : "";
    return {
      oAuthKeyData: {
        evmAddress: oAuthAddress,
        X: oAuthX,
        Y: oAuthY,
      },
      finalKeyData: {
        evmAddress: finalAddress,
        X: finalX,
        Y: finalY,
      },
      metadata: {
        pubNonce,
        nonce,
        upgraded: (nonceResult as v2NonceResultType)?.upgraded || false,
        typeOfUser,
        serverTimeOffset: finalServerTimeOffset,
      },
      nodesData: {
        nodeIndexes: [],
      },
    };
  }
}

export default Torus;
