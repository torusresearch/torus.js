import {
  INodePub,
  JRPCResponse,
  LEGACY_NETWORKS_ROUTE_MAP,
  METADATA_MAP,
  SIGNER_MAP,
  TORUS_LEGACY_NETWORK_TYPE,
  TORUS_NETWORK_TYPE,
} from "@toruslabs/constants";
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
  lagrangeInterpolation,
  legacyKeyAssign,
  legacyKeyLookup,
  legacyWaitKeyLookup,
  retrieveOrImportShare,
  thresholdSame,
} from "./helpers";
import {
  CommitmentRequestResult,
  GetOrSetNonceResult,
  ImportedShare,
  LegacyShareRequestResult,
  LegacyVerifierLookupResponse,
  NonceMetadataParams,
  SetNonceData,
  TorusCtorOptions,
  TorusKey,
  TorusPublicKey,
  UserType,
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
    this.signerHost = `${SIGNER_MAP[network as TORUS_LEGACY_NETWORK_TYPE]}/api/sign`;
  }

  public get isLegacyNetwork(): boolean {
    const legacyNetwork = LEGACY_NETWORKS_ROUTE_MAP[this.network as TORUS_LEGACY_NETWORK_TYPE];
    if (legacyNetwork && !legacyNetwork.migrationCompleted) return true;
    return false;
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
    if (this.isLegacyNetwork) return this.legacyRetrieveShares(endpoints, indexes, verifier, verifierParams, idToken, extraParams);
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
      importedShares: [],
      extraParams,
    });
  }

  async getPublicAddress(
    endpoints: string[],
    torusNodePubs: INodePub[],
    { verifier, verifierId, extendedVerifierId }: { verifier: string; verifierId: string; extendedVerifierId?: string }
  ): Promise<TorusPublicKey> {
    if (this.isLegacyNetwork) return this.getLegacyPublicAddress(endpoints, torusNodePubs, { verifier, verifierId }, this.enableOneKey);
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
    if (this.isLegacyNetwork) throw new Error("This function is not supported on legacy networks");
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
      importedShares: sharesData,
      extraParams,
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
    if (!this.isLegacyNetwork)
      return this.getNewPublicAddress(endpoints, { verifier, verifierId, extendedVerifierId }, true) as Promise<TorusPublicKey>;
    return this.getLegacyPublicAddress(endpoints, torusNodePubs, { verifier, verifierId }, true);
  }

  private async legacyRetrieveShares(
    endpoints: string[],
    indexes: number[],
    verifier: string,
    verifierParams: VerifierParams,
    idToken: string,
    extraParams: Record<string, unknown> = {}
  ): Promise<TorusKey> {
    const promiseArr = [];
    await get<void>(
      this.allowHost,
      {
        headers: {
          verifier,
          verifierId: verifierParams.verifier_id,
          network: this.network,
          clientId: this.clientId,
          enableGating: "true",
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

            const decryptedShares = sharesResolved.reduce(
              (acc, curr, index) => {
                if (curr) acc.push({ index: nodeIndexes[index], value: new BN(curr) });
                return acc;
              },
              [] as { index: BN; value: BN }[]
            );
            // run lagrange interpolation on all subsets, faster in the optimistic scenario than berlekamp-welch due to early exit
            const allCombis = kCombinations(decryptedShares.length, ~~(endpoints.length / 2) + 1);
            let privateKey: BN | null = null;
            for (let j = 0; j < allCombis.length; j += 1) {
              const currentCombi = allCombis[j];
              const currentCombiShares = decryptedShares.filter((_, index) => currentCombi.includes(index));
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
        const oAuthKey = returnedKey;
        if (!oAuthKey) throw new Error("Invalid private key returned");
        const oAuthPubKey = getPublic(Buffer.from(oAuthKey.toString(16, 64), "hex")).toString("hex");
        const oAuthKeyX = oAuthPubKey.slice(2, 66);
        const oAuthKeyY = oAuthPubKey.slice(66);
        let metadataNonce: BN;
        let finalPubKey: curve.base.BasePoint;
        let typeOfUser: UserType = "v1";
        let pubKeyNonceResult: { X: string; Y: string } | undefined;
        if (this.enableOneKey) {
          const nonceResult = await getNonce(this.legacyMetadataHost, this.ec, this.serverTimeOffset, oAuthKeyX, oAuthKeyY, oAuthKey);
          metadataNonce = new BN(nonceResult.nonce || "0", 16);
          typeOfUser = nonceResult.typeOfUser;
          if (typeOfUser === "v2") {
            finalPubKey = this.ec
              .keyFromPublic({ x: oAuthKeyX, y: oAuthKeyY })
              .getPublic()
              .add(
                this.ec
                  .keyFromPublic({ x: (nonceResult as v2NonceResultType).pubNonce.x, y: (nonceResult as v2NonceResultType).pubNonce.y })
                  .getPublic()
              );
            pubKeyNonceResult = { X: (nonceResult as v2NonceResultType).pubNonce.x, Y: (nonceResult as v2NonceResultType).pubNonce.y };
          } else {
            // for imported keys in legacy networks
            metadataNonce = await getMetadata(this.legacyMetadataHost, { pub_key_X: oAuthKeyX, pub_key_Y: oAuthKeyY });
            const privateKeyWithNonce = oAuthKey.add(metadataNonce).umod(this.ec.curve.n);
            finalPubKey = this.ec.keyFromPrivate(privateKeyWithNonce.toString("hex"), "hex").getPublic();
          }
        } else {
          // for imported keys in legacy networks
          metadataNonce = await getMetadata(this.legacyMetadataHost, { pub_key_X: oAuthKeyX, pub_key_Y: oAuthKeyY });
          const privateKeyWithNonce = oAuthKey.add(metadataNonce).umod(this.ec.curve.n);
          finalPubKey = this.ec.keyFromPrivate(privateKeyWithNonce.toString("hex"), "hex").getPublic();
        }

        const oAuthKeyAddress = generateAddressFromPrivKey(this.ec, oAuthKey);

        let finalPrivKey = ""; // it is empty for v2 user upgraded to 2/n
        if (typeOfUser === "v1" || (typeOfUser === "v2" && metadataNonce.gt(new BN(0)))) {
          const privateKeyWithNonce = oAuthKey.add(metadataNonce).umod(this.ec.curve.n);
          finalPrivKey = privateKeyWithNonce.toString("hex", 64).padStart(64, "0");
        }

        let isUpgraded: boolean | null = false;
        if (typeOfUser === "v1") {
          isUpgraded = null;
        } else if (typeOfUser === "v2") {
          isUpgraded = metadataNonce.eq(new BN("0"));
        }

        // deriving address from pub key coz pubkey is always available
        // but finalPrivKey won't be available for  v2 user upgraded to 2/n
        let finalEvmAddress = "";
        if (finalPubKey) {
          finalEvmAddress = generateAddressFromPubKey(this.ec, finalPubKey.getX(), finalPubKey.getY());
          log.debug("> torus.js/retrieveShares", { finalEvmAddress });
        } else {
          throw new Error("Invalid public key, this might be a bug, please report this to web3auth team");
        }

        return {
          finalKeyData: {
            evmAddress: finalEvmAddress,
            X: finalPubKey ? finalPubKey.getX().toString(16, 64) : "", // this is final pub x user before and after updating to 2/n
            Y: finalPubKey ? finalPubKey.getY().toString(16, 64) : "", // this is final pub y user before and after updating to 2/n
            privKey: finalPrivKey,
          },
          oAuthKeyData: {
            evmAddress: oAuthKeyAddress,
            X: oAuthKeyX,
            Y: oAuthKeyY,
            privKey: oAuthKey.toString("hex", 64).padStart(64, "0"),
          },
          sessionData: {
            sessionTokenData: [],
            sessionAuthKey: "",
          },
          metadata: {
            pubNonce: pubKeyNonceResult,
            nonce: metadataNonce,
            typeOfUser: typeOfUser as UserType,
            upgraded: isUpgraded,
          },
          nodesData: {
            nodeIndexes: [],
          },
        };
      });
  }

  private async getLegacyPublicAddress(
    endpoints: string[],
    torusNodePubs: INodePub[],
    { verifier, verifierId }: { verifier: string; verifierId: string },
    enableOneKey: boolean
  ): Promise<TorusPublicKey> {
    log.debug("> torus.js/getPublicAddress", { endpoints, torusNodePubs, verifier, verifierId });

    let finalKeyResult: LegacyVerifierLookupResponse | undefined;
    let isNewKey = false;

    const { keyResult, errorResult } = (await legacyKeyLookup(endpoints, verifier, verifierId)) || {};
    if (errorResult && JSON.stringify(errorResult).includes("Verifier not supported")) {
      // change error msg
      throw new Error(`Verifier not supported. Check if you: \n
      1. Are on the right network (Torus testnet/mainnet) \n
      2. Have setup a verifier on dashboard.web3auth.io?`);
    } else if (errorResult && JSON.stringify(errorResult).includes("Verifier + VerifierID has not yet been assigned")) {
      await legacyKeyAssign({
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
      const assignResult = await legacyWaitKeyLookup(endpoints, verifier, verifierId, 1000);
      finalKeyResult = assignResult?.keyResult;
      isNewKey = true;
    } else if (keyResult) {
      finalKeyResult = keyResult;
    } else {
      throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }
    log.debug("> torus.js/getPublicAddress", { finalKeyResult, isNewKey });

    if (finalKeyResult) {
      return this.formatLegacyPublicKeyData({
        finalKeyResult,
        isNewKey,
        enableOneKey,
      });
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

  private async getNewPublicAddress(
    endpoints: string[],
    { verifier, verifierId, extendedVerifierId }: { verifier: string; verifierId: string; extendedVerifierId?: string },
    enableOneKey: boolean
  ): Promise<TorusPublicKey> {
    log.debug("> torus.js/getPublicAddress", { endpoints, verifier, verifierId });
    const keyAssignResult = await GetPubKeyOrKeyAssign({
      endpoints,
      network: this.network,
      verifier,
      verifierId,
      extendedVerifierId,
    });
    const { errorResult, keyResult, nodeIndexes = [] } = keyAssignResult;
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
    log.debug("> torus.js/getPublicAddress", { keyResult });
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
    log.debug("> torus.js/getPublicAddress, oAuthKeyData", { X: oAuthX, Y: oAuthY, oAuthAddress, nonce: nonce?.toString(16), pubNonce });

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
  }): Promise<TorusPublicKey> {
    const { finalKeyResult, enableOneKey, isNewKey } = params;
    const { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0];
    let nonceResult: GetOrSetNonceResult;
    let nonce: BN;
    let finalPubKey: curve.base.BasePoint;
    let typeOfUser: GetOrSetNonceResult["typeOfUser"];
    let pubNonce: { X: string; Y: string } | undefined;

    const oAuthPubKey = this.ec.keyFromPublic({ x: X, y: Y }).getPublic();

    if (enableOneKey) {
      try {
        nonceResult = await getOrSetNonce(this.legacyMetadataHost, this.ec, this.serverTimeOffset, X, Y, undefined, !isNewKey);
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
    log.debug("> torus.js/getPublicAddress, oAuthKeyData", { X: oAuthX, Y: oAuthY, oAuthAddress, nonce: nonce?.toString(16), pubNonce });

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
      },
      nodesData: {
        nodeIndexes: [],
      },
    };
  }
}

export default Torus;
