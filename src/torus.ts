// import type { INodePub } from "@toruslabs/fetch-node-details";
import { INodePub, TORUS_LEGACY_NETWORK_SAPPHIRE_ALIAS, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
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
  ImportedShare,
  NonceMetadataParams,
  RetrieveSharesResponse,
  SetNonceData,
  TorusCtorOptions,
  TorusPublicKey,
  v2NonceResultType,
  VerifierParams,
} from "./interfaces";
import log from "./loglevel";

// Implement threshold logic wrappers around public APIs
// of Torus nodes to handle malicious node responses
class Torus {
  public allowHost: string;

  public serverTimeOffset: number;

  public network: TORUS_NETWORK_TYPE;

  public clientId: string;

  public ec: EC;

  public enableOneKey: boolean;

  constructor({ enableOneKey = false, clientId, network, serverTimeOffset = 0, allowHost = "https://signer.tor.us/api/allow" }: TorusCtorOptions) {
    if (!clientId) throw Error("Please provide a valid clientId in constructor");
    if (!network) throw Error("Please provide a valid network in constructor");
    this.ec = new EC("secp256k1");
    this.serverTimeOffset = serverTimeOffset || 0; // ms
    this.network = network;
    this.clientId = clientId;
    this.allowHost = allowHost;
    this.enableOneKey = enableOneKey;
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
    return retrieveOrImportShare(
      this.serverTimeOffset,
      this.enableOneKey,
      this.ec,
      this.allowHost,
      this.network,
      this.clientId,
      endpoints,
      verifier,
      verifierParams,
      idToken,
      undefined,
      extraParams
    );
  }

  async getPublicAddress(
    endpoints: string[],
    { verifier, verifierId, extendedVerifierId }: { verifier: string; verifierId: string; extendedVerifierId?: string },
    isExtended = false
  ): Promise<string | TorusPublicKey> {
    log.debug("> torus.js/getPublicAddress", { endpoints, verifier, verifierId, isExtended });
    const keyAssignResult = await GetPubKeyOrKeyAssign(endpoints, this.network, verifier, verifierId, extendedVerifierId);
    const { errorResult, keyResult, nodeIndexes = [], nonceResult } = keyAssignResult;
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
    if (!nonceResult && !extendedVerifierId && !TORUS_LEGACY_NETWORK_SAPPHIRE_ALIAS[this.network]) {
      throw new GetOrSetNonceError("metadata nonce is missing in share response");
    }
    let typeOfUser: "v1" | "v2" = "v2";
    let { pub_key_X: X, pub_key_Y: Y } = keyResult.keys[0];
    let modifiedPubKey: curve.base.BasePoint;
    let pubNonce: { x: string; y: string } | undefined;
    let nonce = new BN(nonceResult?.nonce || "0", 16);

    if (extendedVerifierId) {
      // for tss key no need to add pub nonce
      modifiedPubKey = this.ec.keyFromPublic({ x: X, y: Y }).getPublic();
    } else if (TORUS_LEGACY_NETWORK_SAPPHIRE_ALIAS[this.network]) {
      // this block is entirely for legacy verifier users which were originally created
      // on legacy networks
      if (this.enableOneKey) {
        try {
          const _nonceResult = await getOrSetNonce(this.ec, this.serverTimeOffset, X, Y, undefined, !keyResult.is_new_key);
          nonce = new BN(_nonceResult.nonce || "0", 16);
          typeOfUser = nonceResult.typeOfUser;
        } catch {
          throw new GetOrSetNonceError();
        }
        if (nonceResult.typeOfUser === "v1") {
          modifiedPubKey = this.ec
            .keyFromPublic({ x: X, y: Y })
            .getPublic()
            .add(this.ec.keyFromPrivate(nonce.toString(16)).getPublic());
        } else if (nonceResult.typeOfUser === "v2") {
          if (nonceResult.upgraded) {
            // OneKey is upgraded to 2/n, returned address is address of Torus key (postbox key), not tKey
            modifiedPubKey = this.ec.keyFromPublic({ x: X, y: Y }).getPublic();
          } else {
            modifiedPubKey = this.ec
              .keyFromPublic({ x: X, y: Y })
              .getPublic()
              .add(this.ec.keyFromPublic({ x: nonceResult.pubNonce.x, y: nonceResult.pubNonce.y }).getPublic());
            pubNonce = nonceResult.pubNonce;
          }
        } else {
          throw new Error("getOrSetNonce should always return typeOfUser.");
        }
      } else {
        typeOfUser = "v1";
        nonce = await getMetadata({ pub_key_X: X, pub_key_Y: Y });
        modifiedPubKey = this.ec
          .keyFromPublic({ x: X, y: Y })
          .getPublic()
          .add(this.ec.keyFromPrivate(nonce.toString(16)).getPublic());
      }
    } else {
      const v2NonceResult = nonceResult as v2NonceResultType;
      modifiedPubKey = this.ec
        .keyFromPublic({ x: X, y: Y })
        .getPublic()
        .add(this.ec.keyFromPublic({ x: v2NonceResult.pubNonce.x, y: v2NonceResult.pubNonce.y }).getPublic());
      pubNonce = v2NonceResult.pubNonce;
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
      upgraded: (nonceResult as v2NonceResultType)?.upgraded || false,
      nodeIndexes,
      typeOfUser,
    };
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
  ): Promise<RetrieveSharesResponse> {
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

    const oauthKey = privKeyBn.sub(randomNonce).umod(this.ec.curve.n);
    const oauthPubKey = this.ec.keyFromPrivate(oauthKey.toString("hex").padStart(64, "0")).getPublic();
    const poly = generateRandomPolynomial(this.ec, degree, oauthKey);
    const shares = poly.generateShares(nodeIndexesBn);
    const nonceParams = this.generateNonceMetadataParams("getOrSetNonce", oauthKey, randomNonce);
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
        pub_key_x: oauthPubKey.getX().toString("hex", 64),
        pub_key_y: oauthPubKey.getY().toString("hex", 64),
        encrypted_share: encParamsMetadata.ciphertext,
        encrypted_share_metadata: encParamsMetadata,
        node_index: Number.parseInt(shareJson.shareIndex, 16),
        key_type: "secp256k1",
        nonce_data: nonceData,
        nonce_signature: nonceParams.signature,
      };
      sharesData.push(shareData);
    }

    return retrieveOrImportShare(
      this.serverTimeOffset,
      this.enableOneKey,
      this.ec,
      this.allowHost,
      this.network,
      this.clientId,
      endpoints,
      verifier,
      verifierParams,
      idToken,
      sharesData,
      extraParams
    );
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
}

export default Torus;
