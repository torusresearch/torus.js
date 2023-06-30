// import type { INodePub } from "@toruslabs/fetch-node-details";
import { INodePub, JRPCResponse, LEGACY_NETWORKS_ROUTE_MAP, SIGNER_MAP, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
import { decrypt, Ecies, encrypt, generatePrivate, getPublic } from "@toruslabs/eccrypto";
import { generateJsonRPCObject, get, post, setAPIKey, setEmbedHost } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import stringify from "json-stable-stringify";

import { config } from "./config";
import {
  encParamsBufToHex,
  generateAddressFromPrivKey,
  generateAddressFromPubKey,
  generateRandomPolynomial,
  getMetadata,
  getNonce,
  getOrSetNonce,
  GetOrSetNonceError,
  GetPubKeyOrKeyAssign,
  kCombinations,
  keccak256,
  keyAssign,
  keyLookup,
  lagrangeInterpolation,
  retrieveOrImportShare,
  thresholdSame,
  waitKeyLookup,
} from "./helpers";
import {
  CommitmentRequestResult,
  GetOrSetNonceResult,
  ImportedShare,
  LegacyRetrieveSharesResponse,
  LegacyShareRequestResult,
  LegacyVerifierLookupResponse,
  NonceMetadataParams,
  RetrieveSharesResponse,
  SetNonceData,
  TorusCtorOptions,
  TorusPublicKey,
  v2NonceResultType,
  VerifierParams,
} from "./interfaces";
import log from "./loglevel";
import { Some } from "./some";

// Implement threshold logic wrappers around public APIs
// of Torus nodes to handle malicious node responses
class Torus {
  public allowHost: string;

  public serverTimeOffset: number;

  public network: TORUS_NETWORK_TYPE;

  public clientId: string;

  public ec: EC;

  public enableOneKey: boolean;

  private signerHost: string;

  constructor({ enableOneKey = false, clientId, network, serverTimeOffset = 0, allowHost = "https://signer.tor.us/api/allow" }: TorusCtorOptions) {
    if (!clientId) throw Error("Please provide a valid clientId in constructor");
    if (!network) throw Error("Please provide a valid network in constructor");
    this.ec = new EC("secp256k1");
    this.serverTimeOffset = serverTimeOffset || 0; // ms
    this.network = network;
    this.clientId = clientId;
    this.allowHost = allowHost;
    this.enableOneKey = enableOneKey;
    this.signerHost = `${SIGNER_MAP[network]}/api/sign`;
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
    const { errorResult, keyResult, nodeIndexes = [] } = keyAssignResult;
    let { nonceResult } = keyAssignResult;
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
    if (!nonceResult && !extendedVerifierId && !LEGACY_NETWORKS_ROUTE_MAP[this.network]) {
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
    } else if (LEGACY_NETWORKS_ROUTE_MAP[this.network]) {
      // this block is entirely for legacy verifier users which were originally created
      // on legacy networks
      if (this.enableOneKey) {
        try {
          nonceResult = await getOrSetNonce(this.ec, this.serverTimeOffset, X, Y, undefined, !keyResult.is_new_key);
          nonce = new BN(nonceResult.nonce || "0", 16);
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
          modifiedPubKey = this.ec
            .keyFromPublic({ x: X, y: Y })
            .getPublic()
            .add(this.ec.keyFromPublic({ x: nonceResult.pubNonce.x, y: nonceResult.pubNonce.y }).getPublic());
          pubNonce = nonceResult.pubNonce;
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

  async legacyRetrieveShares(
    endpoints: string[],
    indexes: number[],
    verifier: string,
    verifierParams: VerifierParams,
    idToken: string,
    extraParams: Record<string, unknown> = {}
  ): Promise<LegacyRetrieveSharesResponse> {
    const promiseArr = [];
    await get<void>(
      this.allowHost,
      {
        headers: {
          verifier,
          verifierId: verifierParams.verifier_id,
          network: this.network,
          clientId: this.clientId,
        },
      },
      { useAPIKey: true }
    );
    /*
      CommitmentRequestParams struct {
        MessagePrefix      string `json:"messageprefix"`
        TokenCommitment    string `json:"tokencommitment"`
        TempPubX           string `json:"temppubx"`
        TempPubY           string `json:"temppuby"`
        VerifierIdentifier string `json:"verifieridentifier"`
      } 
      */

    // generate temporary private and public key that is used to secure receive shares
    const tmpKey = generatePrivate();
    const pubKey = getPublic(tmpKey).toString("hex");
    const pubKeyX = pubKey.slice(2, 66);
    const pubKeyY = pubKey.slice(66);
    const tokenCommitment = keccak256(Buffer.from(idToken, "utf8"));

    // make commitment requests to endpoints
    for (let i = 0; i < endpoints.length; i += 1) {
      const p = post<JRPCResponse<CommitmentRequestResult>>(
        endpoints[i],
        generateJsonRPCObject("CommitmentRequest", {
          messageprefix: "mug00",
          tokencommitment: tokenCommitment.slice(2),
          temppubx: pubKeyX,
          temppuby: pubKeyY,
          verifieridentifier: verifier,
        })
      ).catch((err) => {
        log.error("commitment", err);
      });
      promiseArr.push(p);
    }
    /*
      ShareRequestParams struct {
        Item []bijson.RawMessage `json:"item"`
      }
      ShareRequestItem struct {
        IDToken            string          `json:"idtoken"`
        NodeSignatures     []NodeSignature `json:"nodesignatures"`
        VerifierIdentifier string          `json:"verifieridentifier"`
      }
      NodeSignature struct {
        Signature   string
        Data        string
        NodePubKeyX string
        NodePubKeyY string
      }
      CommitmentRequestResult struct {
        Signature string `json:"signature"`
        Data      string `json:"data"`
        NodePubX  string `json:"nodepubx"`
        NodePubY  string `json:"nodepuby"`
      }
      */
    // send share request once k + t number of commitment requests have completed
    return Some<void | JRPCResponse<CommitmentRequestResult>, (void | JRPCResponse<CommitmentRequestResult>)[]>(promiseArr, (resultArr) => {
      const completedRequests = resultArr.filter((x) => {
        if (!x || typeof x !== "object") {
          return false;
        }
        if (x.error) {
          return false;
        }
        return true;
      });
      if (completedRequests.length >= ~~(endpoints.length / 4) * 3 + 1) {
        return Promise.resolve(resultArr);
      }
      return Promise.reject(new Error(`invalid ${JSON.stringify(resultArr)}`));
    })
      .then((responses) => {
        const promiseArrRequest: Promise<void | JRPCResponse<LegacyShareRequestResult>>[] = [];
        const nodeSigs = [];
        for (let i = 0; i < responses.length; i += 1) {
          if (responses[i]) nodeSigs.push((responses[i] as JRPCResponse<CommitmentRequestResult>).result);
        }
        for (let i = 0; i < endpoints.length; i += 1) {
          const p = post<JRPCResponse<LegacyShareRequestResult>>(
            endpoints[i],
            generateJsonRPCObject("ShareRequest", {
              encrypted: "yes",
              item: [{ ...verifierParams, idtoken: idToken, nodesignatures: nodeSigs, verifieridentifier: verifier, ...extraParams }],
            })
          ).catch((err) => log.error("share req", err));
          promiseArrRequest.push(p);
        }
        return Some<void | JRPCResponse<LegacyShareRequestResult>, BN | undefined>(promiseArrRequest, async (shareResponses, sharedState) => {
          /*
              ShareRequestResult struct {
                Keys []KeyAssignment
              }
                      / KeyAssignmentPublic -
              type KeyAssignmentPublic struct {
                Index     big.Int
                PublicKey common.Point
                Threshold int
                Verifiers map[string][]string // Verifier => VerifierID
              }

              // KeyAssignment -
              type KeyAssignment struct {
                KeyAssignmentPublic
                Share big.Int // Or Si
              }
            */
          // check if threshold number of nodes have returned the same user public key
          const completedRequests = shareResponses.filter((x) => x);
          const thresholdPublicKey = thresholdSame(
            shareResponses.map((x) => x && x.result && x.result.keys[0].PublicKey),
            ~~(endpoints.length / 2) + 1
          );
          // optimistically run lagrange interpolation once threshold number of shares have been received
          // this is matched against the user public key to ensure that shares are consistent
          if (completedRequests.length >= ~~(endpoints.length / 2) + 1 && thresholdPublicKey) {
            const sharePromises: Promise<void | Buffer>[] = [];
            const nodeIndexes: BN[] = [];
            for (let i = 0; i < shareResponses.length; i += 1) {
              const currentShareResponse = shareResponses[i] as JRPCResponse<LegacyShareRequestResult>;
              if (currentShareResponse?.result?.keys?.length > 0) {
                currentShareResponse.result.keys.sort((a, b) => new BN(a.Index, 16).cmp(new BN(b.Index, 16)));
                const firstKey = currentShareResponse.result.keys[0];
                if (firstKey.Metadata) {
                  const metadata = {
                    ephemPublicKey: Buffer.from(firstKey.Metadata.ephemPublicKey, "hex"),
                    iv: Buffer.from(firstKey.Metadata.iv, "hex"),
                    mac: Buffer.from(firstKey.Metadata.mac, "hex"),
                    // mode: Buffer.from(firstKey.Metadata.mode, "hex"),
                  };
                  sharePromises.push(
                    decrypt(tmpKey, {
                      ...metadata,
                      ciphertext: Buffer.from(Buffer.from(firstKey.Share, "base64").toString("binary").padStart(64, "0"), "hex"),
                    }).catch((err) => log.debug("share decryption", err))
                  );
                } else {
                  sharePromises.push(Promise.resolve(Buffer.from(firstKey.Share.padStart(64, "0"), "hex")));
                }
              } else {
                sharePromises.push(Promise.resolve(undefined));
              }
              nodeIndexes.push(new BN(indexes[i], 16));
            }
            const sharesResolved = await Promise.all(sharePromises);
            if (sharedState.resolved) return undefined;

            const decryptedShares = sharesResolved.reduce((acc, curr, index) => {
              if (curr) acc.push({ index: nodeIndexes[index], value: new BN(curr) });
              return acc;
            }, [] as { index: BN; value: BN }[]);
            // run lagrange interpolation on all subsets, faster in the optimistic scenario than berlekamp-welch due to early exit
            const allCombis = kCombinations(decryptedShares.length, ~~(endpoints.length / 2) + 1);
            let privateKey: BN | null = null;
            for (let j = 0; j < allCombis.length; j += 1) {
              const currentCombi = allCombis[j];
              const currentCombiShares = decryptedShares.filter((v, index) => currentCombi.includes(index));
              const shares = currentCombiShares.map((x) => x.value);
              const indices = currentCombiShares.map((x) => x.index);
              const derivedPrivateKey = lagrangeInterpolation(this.ec, shares, indices);
              if (!derivedPrivateKey) continue;
              const decryptedPubKey = getPublic(Buffer.from(derivedPrivateKey.toString(16, 64), "hex")).toString("hex");
              const decryptedPubKeyX = decryptedPubKey.slice(2, 66);
              const decryptedPubKeyY = decryptedPubKey.slice(66);
              if (
                new BN(decryptedPubKeyX, 16).cmp(new BN(thresholdPublicKey.X, 16)) === 0 &&
                new BN(decryptedPubKeyY, 16).cmp(new BN(thresholdPublicKey.Y, 16)) === 0
              ) {
                privateKey = derivedPrivateKey;
                break;
              }
            }
            if (privateKey === undefined || privateKey === null) {
              throw new Error("could not derive private key");
            }
            return privateKey;
          }
          throw new Error("invalid");
        });
      })
      .then(async (returnedKey) => {
        let privateKey = returnedKey;
        if (!privateKey) throw new Error("Invalid private key returned");
        const decryptedPubKey = getPublic(Buffer.from(privateKey.toString(16, 64), "hex")).toString("hex");
        const decryptedPubKeyX = decryptedPubKey.slice(2, 66);
        const decryptedPubKeyY = decryptedPubKey.slice(66);
        let metadataNonce: BN;
        if (this.enableOneKey) {
          const { nonce } = await getNonce(this.ec, this.serverTimeOffset, decryptedPubKeyX, decryptedPubKeyY, privateKey);
          metadataNonce = new BN(nonce || "0", 16);
        } else {
          metadataNonce = await getMetadata({ pub_key_X: decryptedPubKeyX, pub_key_Y: decryptedPubKeyY });
        }
        log.debug("> torus.js/retrieveShares", { privKey: privateKey.toString(16), metadataNonce: metadataNonce.toString(16) });

        privateKey = privateKey.add(metadataNonce).umod(this.ec.curve.n);

        const ethAddress = generateAddressFromPrivKey(this.ec, privateKey);
        log.debug("> torus.js/retrieveShares", { ethAddress, privKey: privateKey.toString(16) });

        // return reconstructed private key and ethereum address
        return {
          ethAddress,
          privKey: privateKey.toString("hex", 64),
          metadataNonce,
        };
      });
  }

  async getLegacyPublicAddress(
    endpoints: string[],
    torusNodePubs: INodePub[],
    { verifier, verifierId }: { verifier: string; verifierId: string },
    isExtended = false
  ): Promise<string | TorusPublicKey> {
    log.debug("> torus.js/getPublicAddress", { endpoints, torusNodePubs, verifier, verifierId, isExtended });

    let finalKeyResult: LegacyVerifierLookupResponse | undefined;
    let isNewKey = false;

    const { keyResult, errorResult } = (await keyLookup(endpoints, verifier, verifierId)) || {};
    if (errorResult && JSON.stringify(errorResult).includes("Verifier not supported")) {
      // change error msg
      throw new Error(`Verifier not supported. Check if you: \n
      1. Are on the right network (Torus testnet/mainnet) \n
      2. Have setup a verifier on dashboard.web3auth.io?`);
    } else if (errorResult && JSON.stringify(errorResult).includes("Verifier + VerifierID has not yet been assigned")) {
      await keyAssign({
        endpoints,
        torusNodePubs,
        lastPoint: undefined,
        firstPoint: undefined,
        verifier,
        verifierId,
        signerHost: this.signerHost,
        network: this.network,
        clientId: this.clientId,
      });
      const assignResult = await waitKeyLookup(endpoints, verifier, verifierId, 1000);
      finalKeyResult = assignResult?.keyResult;
      isNewKey = true;
    } else if (keyResult) {
      finalKeyResult = keyResult;
    } else {
      throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }
    log.debug("> torus.js/getPublicAddress", { finalKeyResult, isNewKey });

    if (finalKeyResult) {
      let { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0];
      let nonceResult: GetOrSetNonceResult;
      let nonce: BN;
      let modifiedPubKey: curve.base.BasePoint;
      let typeOfUser: GetOrSetNonceResult["typeOfUser"];
      let pubNonce: { x: string; y: string } | undefined;
      if (this.enableOneKey) {
        try {
          nonceResult = await getOrSetNonce(this.ec, this.serverTimeOffset, X, Y, undefined, !isNewKey);
          nonce = new BN(nonceResult.nonce || "0", 16);
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

      X = modifiedPubKey.getX().toString(16);
      Y = modifiedPubKey.getY().toString(16);

      const address = generateAddressFromPubKey(this.ec, modifiedPubKey.getX(), modifiedPubKey.getY());
      log.debug("> torus.js/getPublicAddress", { X, Y, address, typeOfUser, nonce: nonce?.toString(16), pubNonce });

      if (!isExtended) return address;
      return {
        typeOfUser,
        address,
        X,
        Y,
        metadataNonce: nonce,
        pubNonce,
        upgraded: (nonceResult as { upgraded?: boolean })?.upgraded || undefined,
      };
    }
    throw new Error(`node results do not match at final lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
  }

  /**
   * Note: use this function only for openlogin tkey account lookups.
   */
  async getLegacyUserTypeAndAddress(
    endpoints: string[],
    torusNodePubs: INodePub[],
    { verifier, verifierId }: { verifier: string; verifierId: string },
    doesKeyAssign = false
  ): Promise<TorusPublicKey> {
    const { keyResult, errorResult } = (await keyLookup(endpoints, verifier, verifierId)) || {};
    let isNewKey = false;
    let finalKeyResult: LegacyVerifierLookupResponse;
    if (errorResult && JSON.stringify(errorResult).includes("Verifier not supported")) {
      // change error msg
      throw new Error(`Verifier not supported. Check if you: \n
      1. Are on the right network (Torus testnet/mainnet) \n
      2. Have setup a verifier on dashboard.web3auth.io?`);
    } else if (errorResult && JSON.stringify(errorResult).includes("Verifier + VerifierID has not yet been assigned")) {
      if (!doesKeyAssign) {
        throw new Error("Verifier + VerifierID has not yet been assigned");
      }
      await keyAssign({
        endpoints,
        torusNodePubs,
        lastPoint: undefined,
        firstPoint: undefined,
        verifier,
        verifierId,
        signerHost: this.signerHost,
        network: this.network,
        clientId: this.clientId,
      });
      const assignResult = await waitKeyLookup(endpoints, verifier, verifierId, 1000);
      finalKeyResult = assignResult?.keyResult;
      isNewKey = true;
    } else if (keyResult) {
      finalKeyResult = keyResult;
    } else {
      throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }
    log.debug("> torus.js/getUserTypeAndAddress", { finalKeyResult, isNewKey });

    if (finalKeyResult) {
      const { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0];
      let nonceResult: GetOrSetNonceResult;
      let nonce: BN;
      let modifiedPubKey: curve.base.BasePoint;
      let typeOfUser: GetOrSetNonceResult["typeOfUser"];
      let pubNonce: { x: string; y: string } | undefined;

      try {
        nonceResult = await getOrSetNonce(this.ec, this.serverTimeOffset, X, Y, undefined, !isNewKey);
        nonce = new BN(nonceResult.nonce || "0", 16);
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
        // pubNonce is never deleted, so we can use it to always get the tkey
        modifiedPubKey = this.ec
          .keyFromPublic({ x: X, y: Y })
          .getPublic()
          .add(this.ec.keyFromPublic({ x: nonceResult.pubNonce.x, y: nonceResult.pubNonce.y }).getPublic());
        pubNonce = nonceResult.pubNonce;
      } else {
        throw new Error("getOrSetNonce should always return typeOfUser.");
      }

      const finalX = modifiedPubKey.getX().toString(16);
      const finalY = modifiedPubKey.getY().toString(16);
      const address = generateAddressFromPubKey(this.ec, modifiedPubKey.getX(), modifiedPubKey.getY());
      log.debug("> torus.js/getUserTypeAndAddress", { X, Y, address, typeOfUser, nonce: nonce?.toString(16), pubNonce });
      return {
        typeOfUser,
        address,
        X: finalX,
        Y: finalY,
        metadataNonce: nonce,
        pubNonce,
        upgraded: (nonceResult as { upgraded?: boolean })?.upgraded || undefined,
      };
    }
    throw new Error(`node results do not match at final lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
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
