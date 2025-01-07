import {
  INodePub,
  KEY_TYPE,
  LEGACY_NETWORKS_ROUTE_MAP,
  METADATA_MAP,
  SIGNER_MAP,
  TORUS_LEGACY_NETWORK_TYPE,
  TORUS_NETWORK_TYPE,
} from "@toruslabs/constants";
import { setAPIKey, setEmbedHost } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";

import { config } from "./config";
import {
  encodeEd25519Point,
  generateAddressFromPubKey,
  generateShares,
  getEcCurve,
  getEd25519ExtendedPublicKey,
  getMetadata,
  getOrSetNonce,
  GetOrSetNonceError,
  GetPubKeyOrKeyAssign,
  retrieveOrImportShare,
} from "./helpers";
import {
  GetOrSetNonceResult,
  ImportKeyParams,
  KeyType,
  LegacyVerifierLookupResponse,
  RetrieveSharesParams,
  TorusCtorOptions,
  TorusKey,
  TorusPublicKey,
  v2NonceResultType,
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

  private keyType: KeyType = KEY_TYPE.SECP256K1;

  constructor({
    enableOneKey = false,
    clientId,
    network,
    serverTimeOffset = 0,
    allowHost,
    legacyMetadataHost,
    keyType = KEY_TYPE.SECP256K1,
  }: TorusCtorOptions) {
    if (!clientId) throw new Error("Please provide a valid clientId in constructor");
    if (!network) throw new Error("Please provide a valid network in constructor");
    if (keyType === KEY_TYPE.ED25519 && LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE]) {
      throw new Error(`keyType: ${keyType} is not supported by ${network} network`);
    }
    this.keyType = keyType;
    this.ec = new EC(this.keyType);
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
      return torusKey.finalKeyData.privKey || torusKey.postboxKeyData.privKey;
    }
    return torusKey.postboxKeyData.privKey;
  }

  async retrieveShares(params: RetrieveSharesParams): Promise<TorusKey> {
    const { verifier, verifierParams, idToken, nodePubkeys, indexes, endpoints, useDkg, extraParams = {}, checkCommitment = true } = params;
    if (nodePubkeys.length === 0) {
      throw new Error("nodePubkeys param is required");
    }

    if (nodePubkeys.length !== indexes.length) {
      throw new Error("nodePubkeys length must be same as indexes length");
    }

    if (nodePubkeys.length !== endpoints.length) {
      throw new Error("nodePubkeys length must be same as endpoints length");
    }
    // dkg is used by default only for secp256k1 keys,
    // for ed25519 keys import keys flows is the default
    let shouldUseDkg;
    if (typeof useDkg === "boolean") {
      if (useDkg === false && LEGACY_NETWORKS_ROUTE_MAP[this.network as TORUS_LEGACY_NETWORK_TYPE]) {
        throw new Error(`useDkg cannot be false for legacy network; ${this.network}`);
      }
      shouldUseDkg = this.keyType === KEY_TYPE.ED25519 ? false : useDkg;
    } else if (this.keyType === KEY_TYPE.ED25519) {
      shouldUseDkg = false;
    } else {
      shouldUseDkg = true;
    }
    if (!shouldUseDkg && nodePubkeys.length === 0) {
      throw new Error("nodePubkeys param is required");
    }

    if (!extraParams.session_token_exp_second) {
      extraParams.session_token_exp_second = Torus.sessionTime;
    }

    return retrieveOrImportShare({
      legacyMetadataHost: this.legacyMetadataHost,
      serverTimeOffset: this.serverTimeOffset,
      enableOneKey: this.enableOneKey,
      ecCurve: this.ec,
      keyType: this.keyType,
      allowHost: this.allowHost,
      network: this.network,
      clientId: this.clientId,
      endpoints,
      indexes,
      verifier,
      verifierParams,
      idToken,
      useDkg: shouldUseDkg,
      newImportedShares: [],
      overrideExistingKey: false,
      nodePubkeys,
      extraParams,
      checkCommitment,
    });
  }

  async getPublicAddress(
    endpoints: string[],
    torusNodePubs: INodePub[],
    { verifier, verifierId, extendedVerifierId, keyType }: { verifier: string; verifierId: string; extendedVerifierId?: string; keyType?: KeyType }
  ): Promise<TorusPublicKey> {
    log.info(torusNodePubs, { verifier, verifierId, extendedVerifierId });
    return this.getNewPublicAddress(endpoints, { verifier, verifierId, extendedVerifierId, keyType }, this.enableOneKey);
  }

  async importPrivateKey(params: ImportKeyParams): Promise<TorusKey> {
    const {
      nodeIndexes,
      newPrivateKey,
      verifier,
      verifierParams,
      idToken,
      nodePubkeys,
      endpoints,
      extraParams = {},
      checkCommitment = true,
    } = params;

    if (LEGACY_NETWORKS_ROUTE_MAP[this.network as TORUS_LEGACY_NETWORK_TYPE]) {
      throw new Error(`importPrivateKey is not supported by legacy network; ${this.network}`);
    }
    if (endpoints.length !== nodeIndexes.length) {
      throw new Error(`length of endpoints array must be same as length of nodeIndexes array`);
    }

    if (!extraParams.session_token_exp_second) {
      extraParams.session_token_exp_second = Torus.sessionTime;
    }

    let privKeyBuffer;

    if (this.keyType === KEY_TYPE.SECP256K1) {
      privKeyBuffer = Buffer.from(newPrivateKey.padStart(64, "0"), "hex");
      if (privKeyBuffer.length !== 32) {
        throw new Error("Invalid private key length for given secp256k1 key");
      }
    }
    if (this.keyType === KEY_TYPE.ED25519) {
      privKeyBuffer = Buffer.from(newPrivateKey.padStart(64, "0"), "hex");
      if (privKeyBuffer.length !== 32) {
        throw new Error("Invalid private key length for given ed25519 key");
      }
    }

    const sharesData = await generateShares(this.ec, this.keyType, this.serverTimeOffset, nodeIndexes, nodePubkeys, privKeyBuffer);
    if (this.keyType === KEY_TYPE.ED25519) {
      const ed25519Key = getEd25519ExtendedPublicKey(privKeyBuffer);
      const ed25519PubKey = encodeEd25519Point(ed25519Key.point);
      const encodedPubKey = encodeEd25519Point(sharesData[0].final_user_point);
      const importedPubKey = Buffer.from(ed25519PubKey).toString("hex");
      const derivedPubKey = encodedPubKey.toString("hex");
      if (importedPubKey !== derivedPubKey) {
        throw new Error("invalid shares data for ed25519 key, public key is not matching after generating shares");
      }
    }

    return retrieveOrImportShare({
      legacyMetadataHost: this.legacyMetadataHost,
      serverTimeOffset: this.serverTimeOffset,
      enableOneKey: this.enableOneKey,
      ecCurve: this.ec,
      keyType: this.keyType,
      allowHost: this.allowHost,
      network: this.network,
      clientId: this.clientId,
      endpoints,
      indexes: nodeIndexes,
      verifier,
      verifierParams,
      idToken,
      useDkg: false,
      overrideExistingKey: true,
      newImportedShares: sharesData,
      nodePubkeys,
      extraParams,
      checkCommitment,
    });
  }

  /**
   * Note: use this function only for openlogin tkey account lookups.
   * this is a legacy function, use getPublicAddress instead for new networks
   */
  async getUserTypeAndAddress(
    endpoints: string[],
    { verifier, verifierId, extendedVerifierId }: { verifier: string; verifierId: string; extendedVerifierId?: string }
  ): Promise<TorusPublicKey> {
    return this.getNewPublicAddress(endpoints, { verifier, verifierId, extendedVerifierId }, true) as Promise<TorusPublicKey>;
  }

  private async getNewPublicAddress(
    endpoints: string[],
    { verifier, verifierId, extendedVerifierId, keyType }: { verifier: string; verifierId: string; extendedVerifierId?: string; keyType?: KeyType },
    enableOneKey: boolean
  ): Promise<TorusPublicKey> {
    const localKeyType = keyType ?? this.keyType;
    const localEc = getEcCurve(localKeyType);

    const keyAssignResult = await GetPubKeyOrKeyAssign({
      endpoints,
      network: this.network,
      verifier,
      verifierId,
      keyType: localKeyType,
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
      finalPubKey = localEc.keyFromPublic({ x: X, y: Y }).getPublic();
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
      oAuthPubKey = localEc.keyFromPublic({ x: X, y: Y }).getPublic();
      finalPubKey = localEc
        .keyFromPublic({ x: X, y: Y })
        .getPublic()
        .add(localEc.keyFromPublic({ x: v2NonceResult.pubNonce.x, y: v2NonceResult.pubNonce.y }).getPublic());

      pubNonce = { X: v2NonceResult.pubNonce.x, Y: v2NonceResult.pubNonce.y };
    }

    if (!oAuthPubKey) {
      throw new Error("Unable to derive oAuthPubKey");
    }
    const oAuthX = oAuthPubKey.getX().toString(16, 64);
    const oAuthY = oAuthPubKey.getY().toString(16, 64);
    const oAuthAddress = generateAddressFromPubKey(localKeyType, oAuthPubKey.getX(), oAuthPubKey.getY());

    if (!finalPubKey) {
      throw new Error("Unable to derive finalPubKey");
    }
    const finalX = finalPubKey ? finalPubKey.getX().toString(16, 64) : "";
    const finalY = finalPubKey ? finalPubKey.getY().toString(16, 64) : "";
    const finalAddress = finalPubKey ? generateAddressFromPubKey(localKeyType, finalPubKey.getX(), finalPubKey.getY()) : "";
    return {
      oAuthKeyData: {
        walletAddress: oAuthAddress,
        X: oAuthX,
        Y: oAuthY,
      },
      finalKeyData: {
        walletAddress: finalAddress,
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
    keyType?: KeyType;
  }): Promise<TorusPublicKey> {
    const { finalKeyResult, enableOneKey, isNewKey, serverTimeOffset, keyType } = params;
    const localKeyType = keyType ?? this.keyType;
    const localEc = getEcCurve(localKeyType);

    const { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0];
    let nonceResult: GetOrSetNonceResult;
    let nonce: BN;
    let finalPubKey: curve.base.BasePoint;
    let typeOfUser: GetOrSetNonceResult["typeOfUser"];
    let pubNonce: { X: string; Y: string } | undefined;

    const oAuthPubKey = localEc.keyFromPublic({ x: X, y: Y }).getPublic();

    const finalServerTimeOffset = this.serverTimeOffset || serverTimeOffset;
    if (enableOneKey) {
      try {
        nonceResult = await getOrSetNonce(this.legacyMetadataHost, localEc, finalServerTimeOffset, X, Y, undefined, !isNewKey);
        nonce = new BN(nonceResult.nonce || "0", 16);
        typeOfUser = nonceResult.typeOfUser;
      } catch {
        throw new GetOrSetNonceError();
      }
      if (nonceResult.typeOfUser === "v1") {
        nonce = await getMetadata(this.legacyMetadataHost, { pub_key_X: X, pub_key_Y: Y });
        finalPubKey = localEc
          .keyFromPublic({ x: X, y: Y })
          .getPublic()
          .add(localEc.keyFromPrivate(nonce.toString(16, 64), "hex").getPublic());
      } else if (nonceResult.typeOfUser === "v2") {
        finalPubKey = localEc
          .keyFromPublic({ x: X, y: Y })
          .getPublic()
          .add(localEc.keyFromPublic({ x: nonceResult.pubNonce.x, y: nonceResult.pubNonce.y }).getPublic());
        pubNonce = { X: nonceResult.pubNonce.x, Y: nonceResult.pubNonce.y };
      } else {
        throw new Error("getOrSetNonce should always return typeOfUser.");
      }
    } else {
      typeOfUser = "v1";
      nonce = await getMetadata(this.legacyMetadataHost, { pub_key_X: X, pub_key_Y: Y });
      finalPubKey = localEc
        .keyFromPublic({ x: X, y: Y })
        .getPublic()
        .add(localEc.keyFromPrivate(nonce.toString(16, 64), "hex").getPublic());
    }

    if (!oAuthPubKey) {
      throw new Error("Unable to derive oAuthPubKey");
    }
    const oAuthX = oAuthPubKey.getX().toString(16, 64);
    const oAuthY = oAuthPubKey.getY().toString(16, 64);
    const oAuthAddress = generateAddressFromPubKey(localKeyType, oAuthPubKey.getX(), oAuthPubKey.getY());

    if (typeOfUser === "v2" && !finalPubKey) {
      throw new Error("Unable to derive finalPubKey");
    }
    const finalX = finalPubKey ? finalPubKey.getX().toString(16, 64) : "";
    const finalY = finalPubKey ? finalPubKey.getY().toString(16, 64) : "";
    const finalAddress = finalPubKey ? generateAddressFromPubKey(localKeyType, finalPubKey.getX(), finalPubKey.getY()) : "";
    return {
      oAuthKeyData: {
        walletAddress: oAuthAddress,
        X: oAuthX,
        Y: oAuthY,
      },
      finalKeyData: {
        walletAddress: finalAddress,
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
