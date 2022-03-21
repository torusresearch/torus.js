import { decrypt, generatePrivate, getPublic } from "@toruslabs/eccrypto";
import type { INodePub as TorusNodePub } from "@toruslabs/fetch-node-details";
import { generateJsonRPCObject, get, post, setAPIKey, setEmbedHost } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import stringify from "json-stable-stringify";
import { keccak256, toChecksumAddress } from "web3-utils";

import {
  MetadataParams,
  MetadataResponse,
  SetCustomKeyOptions,
  ShareResponse,
  TorusCtorOptions,
  V1UserTypeAndAddress,
  V2UserTypeAndAddress,
} from "./interfaces";
import log from "./loglevel";
import { Some } from "./some";
import { GetOrSetNonceError, kCombinations, keyAssign, keyLookup, thresholdSame, waitKeyLookup } from "./utils";

// Implement threshold logic wrappers around public APIs
// of Torus nodes to handle malicious node responses
class Torus {
  public metadataHost: string;

  public allowHost: string;

  public serverTimeOffset: number;

  public enableOneKey: boolean;

  public signerHost: string;

  protected ec: EC;

  constructor({
    enableOneKey = false,
    metadataHost = "https://metadata.tor.us",
    allowHost = "https://signer.tor.us/api/allow",
    signerHost = "https://signer.tor.us/api/sign",
    serverTimeOffset = 0,
  }: TorusCtorOptions = {}) {
    this.ec = new EC("secp256k1");
    this.metadataHost = metadataHost;
    this.allowHost = allowHost;
    this.enableOneKey = enableOneKey;
    this.serverTimeOffset = serverTimeOffset || 0; // ms
    this.signerHost = signerHost;
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

  /**
   * Note: use this function only for openlogin tkey account lookups.
   */
  async getUserTypeAndAddress(
    endpoints: string[],
    torusNodePubs: TorusNodePub[],
    { verifier, verifierId }: { verifier: string; verifierId: string },
    doesKeyAssign = false
  ): Promise<V1UserTypeAndAddress | V2UserTypeAndAddress> {
    const { keyResult, errorResult } = (await keyLookup(endpoints, verifier, verifierId)) || {};
    let isNewKey = false;
    let finalKeyResult;
    if (errorResult && JSON.stringify(errorResult).includes("Verifier + VerifierID has not yet been assigned")) {
      if (!doesKeyAssign) {
        throw new Error("Verifier + VerifierID has not yet been assigned");
      }
      await keyAssign({ endpoints, torusNodePubs, lastPoint: undefined, firstPoint: undefined, verifier, verifierId, signerHost: this.signerHost });
      const assignResult = (await waitKeyLookup(endpoints, verifier, verifierId, 1000)) || {};
      finalKeyResult = assignResult.keyResult;
      isNewKey = true;
    } else if (keyResult) {
      finalKeyResult = keyResult;
    } else {
      throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }
    if (finalKeyResult) {
      const { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0];
      let typeOfUser;
      let nonce;
      let pubNonce;
      let modifiedPubKey;
      let upgraded;

      try {
        ({ typeOfUser, nonce, pubNonce, upgraded } = await this.getOrSetNonce(X, Y, undefined, !isNewKey));
        nonce = new BN(nonce || "0", 16);
      } catch {
        throw new GetOrSetNonceError();
      }
      if (typeOfUser === "v1") {
        modifiedPubKey = this.ec
          .keyFromPublic({ x: X.toString(16), y: Y.toString(16) })
          .getPublic()
          .add(this.ec.keyFromPrivate(nonce.toString(16)).getPublic());
      } else if (typeOfUser === "v2") {
        modifiedPubKey = this.ec
          .keyFromPublic({ x: X.toString(16), y: Y.toString(16) })
          .getPublic()
          .add(this.ec.keyFromPublic({ x: pubNonce.x, y: pubNonce.y }).getPublic());
      } else {
        throw new Error("getOrSetNonce should always return typeOfUser.");
      }
      const finalX = modifiedPubKey.getX().toString(16);
      const finalY = modifiedPubKey.getY().toString(16);
      const address = this.generateAddressFromPubKey(modifiedPubKey.getX(), modifiedPubKey.getY());
      return { typeOfUser, nonce, pubNonce, upgraded, X: finalX, Y: finalY, address };
    }
    throw new Error(`node results do not match at final lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
  }

  async setCustomKey({ privKeyHex, metadataNonce, torusKeyHex, customKeyHex }: SetCustomKeyOptions): Promise<void> {
    let torusKey: BN | undefined;
    if (torusKeyHex) {
      torusKey = new BN(torusKeyHex, 16);
    } else {
      const privKey = new BN(privKeyHex, 16);
      torusKey = privKey.sub(metadataNonce).umod(this.ec.curve.n);
    }
    const customKey = new BN(customKeyHex, 16);
    const newMetadataNonce = customKey.sub(torusKey).umod(this.ec.curve.n);
    const data = this.generateMetadataParams(newMetadataNonce.toString(16), torusKey.toString(16));
    await this.setMetadata(data);
  }

  async retrieveShares(
    endpoints: string[],
    indexes: number[],
    verifier: string,
    verifierParams: { verifier_id: string },
    idToken: string,
    extraParams: Record<string, unknown> = {}
  ): Promise<ShareResponse> {
    const promiseArr = [];
    await get(
      this.allowHost,
      {
        headers: {
          verifier,
          verifier_id: verifierParams.verifier_id,
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
    const tokenCommitment = keccak256(idToken);

    // make commitment requests to endpoints
    for (let i = 0; i < endpoints.length; i += 1) {
      const p = post(
        endpoints[i],
        generateJsonRPCObject("CommitmentRequest", {
          messageprefix: "mug00",
          tokencommitment: tokenCommitment.slice(2),
          temppubx: pubKeyX,
          temppuby: pubKeyY,
          verifieridentifier: verifier,
        })
      ).catch((err) => log.error("commitment", err));
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
    return Some(promiseArr, (resultArr) => {
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
        const promiseArrRequest = [];
        const nodeSigs = [];
        for (let i = 0; i < responses.length; i += 1) {
          if (responses[i]) nodeSigs.push(responses[i].result);
        }
        for (let i = 0; i < endpoints.length; i += 1) {
          // eslint-disable-next-line promise/no-nesting
          const p = post(
            endpoints[i],
            generateJsonRPCObject("ShareRequest", {
              encrypted: "yes",
              item: [{ ...verifierParams, idtoken: idToken, nodesignatures: nodeSigs, verifieridentifier: verifier, ...extraParams }],
            })
          ).catch((err) => log.error("share req", err));
          promiseArrRequest.push(p);
        }
        return Some(promiseArrRequest, async (shareResponses, sharedState) => {
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
            const sharePromises = [];
            const nodeIndex = [];
            for (let i = 0; i < shareResponses.length; i += 1) {
              if (shareResponses[i] && shareResponses[i].result && shareResponses[i].result.keys && shareResponses[i].result.keys.length > 0) {
                shareResponses[i].result.keys.sort((a, b) => new BN(a.Index, 16).cmp(new BN(b.Index, 16)));
                if (shareResponses[i].result.keys[0].Metadata) {
                  const metadata = {
                    ephemPublicKey: Buffer.from(shareResponses[i].result.keys[0].Metadata.ephemPublicKey, "hex"),
                    iv: Buffer.from(shareResponses[i].result.keys[0].Metadata.iv, "hex"),
                    mac: Buffer.from(shareResponses[i].result.keys[0].Metadata.mac, "hex"),
                    mode: Buffer.from(shareResponses[i].result.keys[0].Metadata.mode, "hex"),
                  };
                  sharePromises.push(
                    // eslint-disable-next-line promise/no-nesting
                    decrypt(tmpKey, {
                      ...metadata,
                      ciphertext: Buffer.from(atob(shareResponses[i].result.keys[0].Share).padStart(64, "0"), "hex"),
                    }).catch((err) => log.debug("share decryption", err))
                  );
                } else {
                  sharePromises.push(Promise.resolve(Buffer.from(shareResponses[i].result.keys[0].Share.padStart(64, "0"), "hex")));
                }
              } else {
                sharePromises.push(Promise.resolve(undefined));
              }
              nodeIndex.push(new BN(indexes[i], 16));
            }
            const sharesResolved = await Promise.all(sharePromises);
            if (sharedState.resolved) return undefined;

            const decryptedShares = sharesResolved.reduce((acc, curr, index) => {
              if (curr) acc.push({ index: nodeIndex[index], value: new BN(curr) });
              return acc;
            }, []);
            // run lagrange interpolation on all subsets, faster in the optimistic scenario than berlekamp-welch due to early exit
            const allCombis = kCombinations(decryptedShares.length, ~~(endpoints.length / 2) + 1);
            let privateKey;
            for (let j = 0; j < allCombis.length; j += 1) {
              const currentCombi = allCombis[j];
              const currentCombiShares = decryptedShares.filter((v, index) => currentCombi.includes(index));
              const shares = currentCombiShares.map((x) => x.value);
              const indices = currentCombiShares.map((x) => x.index);
              const derivedPrivateKey = this.lagrangeInterpolation(shares, indices);
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
            if (privateKey === undefined) {
              throw new Error("could not derive private key");
            }
            return privateKey;
          }
          throw new Error("invalid");
        });
      })
      .then(async (returnedKey) => {
        let privateKey = returnedKey;
        const decryptedPubKey = getPublic(Buffer.from(privateKey.toString(16, 64), "hex")).toString("hex");
        const decryptedPubKeyX = decryptedPubKey.slice(2, 66);
        const decryptedPubKeyY = decryptedPubKey.slice(66);
        let metadataNonce: BN;

        if (this.enableOneKey) {
          const { nonce } = await this.getNonce(decryptedPubKeyX, decryptedPubKeyY, privateKey);
          metadataNonce = new BN(nonce || "0", 16);
        } else {
          metadataNonce = await this.getMetadata({ pub_key_X: decryptedPubKeyX, pub_key_Y: decryptedPubKeyY });
        }
        log.debug("> torus.js/retrieveShares", { privKey: privateKey.toString(16), metadataNonce: metadataNonce.toString(16) });

        privateKey = privateKey.add(metadataNonce).umod(this.ec.curve.n);

        const ethAddress = this.generateAddressFromPrivKey(privateKey);
        log.debug("> torus.js/retrieveShares", { ethAddress, privKey: privateKey.toString(16) });

        // return reconstructed private key and ethereum address
        return {
          ethAddress,
          privKey: privateKey.toString("hex", 64),
          metadataNonce,
        };
      });
  }

  async getMetadata(data: MetadataParams, options = {}): Promise<BN> {
    try {
      const metadataResponse: MetaDataResponse = await post(`${this.metadataHost}/get`, data, options, { useAPIKey: true });
      if (!metadataResponse || !metadataResponse.message) {
        return new BN(0);
      }
      return new BN(metadataResponse.message, 16); // nonce
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
      signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN(sig.v).toString(16, 2), "hex").toString("base64"),
    };
  }

  async setMetadata(data, options = {}): Promise<string> {
    try {
      const metadataResponse: MetadataResponse = await post(`${this.metadataHost}/set`, data, options, { useAPIKey: true });
      return metadataResponse.message; // IPFS hash
    } catch (error) {
      log.error("set metadata error", error);
      return "";
    }
  }

  lagrangeInterpolation(shares: BN[], nodeIndex: BN[]): BN {
    if (shares.length !== nodeIndex.length) {
      return null;
    }
    let secret = new BN(0);
    for (let i = 0; i < shares.length; i += 1) {
      let upper = new BN(1);
      let lower = new BN(1);
      for (let j = 0; j < shares.length; j += 1) {
        if (i !== j) {
          upper = upper.mul(nodeIndex[j].neg());
          upper = upper.umod(this.ec.curve.n);
          let temp = nodeIndex[i].sub(nodeIndex[j]);
          temp = temp.umod(this.ec.curve.n);
          lower = lower.mul(temp).umod(this.ec.curve.n);
        }
      }
      let delta = upper.mul(lower.invm(this.ec.curve.n)).umod(this.ec.curve.n);
      delta = delta.mul(shares[i]).umod(this.ec.curve.n);
      secret = secret.add(delta);
    }
    return secret.umod(this.ec.curve.n);
  }

  generateAddressFromPrivKey(privateKey: BN): string {
    const key = this.ec.keyFromPrivate(privateKey.toString("hex", 64), "hex");
    const publicKey = key.getPublic().encode("hex").slice(2);
    const ethAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
    return toChecksumAddress(ethAddressLower);
  }

  generateAddressFromPubKey(publicKeyX: BN, publicKeyY: BN): string {
    const key = this.ec.keyFromPublic({ x: publicKeyX.toString("hex", 64), y: publicKeyY.toString("hex", 64) });
    const publicKey = key.getPublic().encode("hex").slice(2);
    const ethAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
    return toChecksumAddress(ethAddressLower);
  }

  /**
   * Note: use this function only with custom auth, don't use to lookup openlogin accounts.
   */
  async getPublicAddress(
    endpoints: string[],
    torusNodePubs: TorusNodePub[],
    { verifier, verifierId }: { verifier: string; verifierId: string },
    isExtended = false
  ): Promise<string | TorusPublicKey> {
    log.debug("> torus.js/getPublicAddress", { endpoints, torusNodePubs, verifier, verifierId, isExtended });

    let finalKeyResult: KeyLookupResult["keyResult"] | undefined;
    let isNewKey = false;

    const { keyResult, errorResult } = (await keyLookup(endpoints, verifier, verifierId)) || {};
    if (errorResult && JSON.stringify(errorResult).includes("Verifier not supported")) {
      // change error msg
      throw new Error(`Verifier not supported. Check if you: \n
      1. Are on the right network (Torus testnet/mainnet) \n
      2. Have setup a verifier on dashboard.web3auth.io?`);
    } else if (errorResult && JSON.stringify(errorResult).includes("Verifier + VerifierID has not yet been assigned")) {
      await keyAssign({ endpoints, torusNodePubs, lastPoint: undefined, firstPoint: undefined, verifier, verifierId, signerHost: this.signerHost });
      const assignResult = (await waitKeyLookup(endpoints, verifier, verifierId, 1000)) || {};
      finalKeyResult = assignResult.keyResult;
      isNewKey = true;
    } else if (keyResult) {
      finalKeyResult = keyResult;
    } else {
      throw new Error(`node results do not match at first lookup ${JSON.stringify(keyResult || {})}, ${JSON.stringify(errorResult || {})}`);
    }
    log.debug("> torus.js/getPublicAddress", { finalKeyResult, isNewKey });

    if (finalKeyResult) {
      let { pub_key_X: X, pub_key_Y: Y } = finalKeyResult.keys[0];
      let typeOfUser: "v1" | "v2";
      let nonce: string;
      let pubNonce: { x: string; y: string };
      let modifiedPubKey: curve.base.BasePoint;
      if (this.enableOneKey) {
        let upgraded;
        try {
          ({ typeOfUser, nonce, pubNonce, upgraded } = await this.getOrSetNonce(X, Y, undefined, !isNewKey));
          nonce = new BN(nonce || "0", 16);
        } catch {
          throw new GetOrSetNonceError();
        }
        if (typeOfUser === "v1") {
          modifiedPubKey = this.ec
            .keyFromPublic({ x: X.toString(16), y: Y.toString(16) })
            .getPublic()
            .add(this.ec.keyFromPrivate(nonce.toString(16)).getPublic());
        } else if (typeOfUser === "v2") {
          if (upgraded) {
            // OneKey is upgraded to 2/n, returned address is address of Torus key (postbox key), not tKey
            modifiedPubKey = this.ec.keyFromPublic({ x: X.toString(16), y: Y.toString(16) }).getPublic();
          } else {
            modifiedPubKey = this.ec
              .keyFromPublic({ x: X.toString(16), y: Y.toString(16) })
              .getPublic()
              .add(this.ec.keyFromPublic({ x: pubNonce.x, y: pubNonce.y }).getPublic());
          }
        } else {
          throw new Error("getOrSetNonce should always return typeOfUser.");
        }
      } else {
        typeOfUser = "v1";
        nonce = await this.getMetadata({ pub_key_X: X, pub_key_Y: Y });
        modifiedPubKey = this.ec
          .keyFromPublic({ x: X.toString(16), y: Y.toString(16) })
          .getPublic()
          .add(this.ec.keyFromPrivate(nonce.toString(16)).getPublic());
      }

      X = modifiedPubKey.getX().toString(16);
      Y = modifiedPubKey.getY().toString(16);

      const address = this.generateAddressFromPubKey(modifiedPubKey.getX(), modifiedPubKey.getY());
      log.debug("> torus.js/getPublicAddress", { X, Y, address, typeOfUser, nonce: nonce?.toString(16), pubNonce });

      if (!isExtended) return address;
      return {
        typeOfUser,
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

  static isGetOrSetNonceError(err: unknown): boolean {
    return err instanceof GetOrSetNonceError;
  }

  async getOrSetNonce(
    X?: string,
    Y?: string,
    privKey?: BN,
    getOnly = false
  ): Promise<
    { typeOfUser: "v1"; nonce?: string } | { typeOfUser: "v2"; nonce?: string; pubNonce: { x: string; y: string }; ipfs?: string; upgraded?: boolean }
  > {
    let data;
    const msg = getOnly ? "getNonce" : "getOrSetNonce";
    if (privKey) {
      data = this.generateMetadataParams(msg, privKey);
    } else {
      data = {
        pub_key_X: X,
        pub_key_Y: Y,
        set_data: { data: msg },
      };
    }
    return post(`${this.metadataHost}/get_or_set_nonce`, data, {}, { useAPIKey: true });
  }

  async getNonce(X: string, Y: string, privKey?: BN): Promise<ReturnType<Torus["getOrSetNonce"]>> {
    return this.getOrSetNonce(X, Y, privKey, true);
  }

  getPostboxKeyFrom1OutOf1(privKey: string, nonce: string): string {
    const privKeyBN = new BN(privKey, 16);
    const nonceBN = new BN(nonce, 16);
    return privKeyBN.sub(nonceBN).umod(this.ec.curve.n).toString("hex");
  }
}

export default Torus;
