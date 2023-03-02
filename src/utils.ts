import { decrypt, generatePrivate, getPublic } from "@toruslabs/eccrypto";
import { generateJsonRPCObject, post } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { ec } from "elliptic";
import JsonStringify from "json-stable-stringify";
import createKeccakHash from "keccak";
import { toChecksumAddress } from "web3-utils";

// import type { INodePub } from "@toruslabs/fetch-node-details";
import {
  CommitmentRequestResult,
  ImportedShare,
  ImportShareRequestResult,
  JRPCResponse,
  KeyLookupResult,
  SessionToken,
  ShareRequestResult,
  VerifierLookupResponse,
  VerifierParams,
} from "./interfaces";
import { lagrangeInterpolation } from "./langrangeInterpolatePoly";
import log from "./loglevel";
import { Some } from "./some";

export class GetOrSetNonceError extends Error {}

export function keccak256(a: string | Buffer): string {
  const hash = createKeccakHash("keccak256").update(a).digest().toString("hex");
  return `0x${hash}`;
}

export function generateAddressFromPrivKey(ecCurve: ec, privateKey: BN): string {
  const key = ecCurve.keyFromPrivate(privateKey.toString("hex", 64), "hex");
  const publicKey = key.getPublic().encode("hex", false).slice(2);
  log.info(publicKey, "public key");
  const ethAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
  return toChecksumAddress(ethAddressLower);
}

export function generateAddressFromPubKey(ecCurve: ec, publicKeyX: BN, publicKeyY: BN): string {
  const key = ecCurve.keyFromPublic({ x: publicKeyX.toString("hex", 64), y: publicKeyY.toString("hex", 64) });
  const publicKey = key.getPublic().encode("hex", false).slice(2);
  log.info(key.getPublic().encode("hex", false), "public key");
  const ethAddressLower = `0x${keccak256(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
  return toChecksumAddress(ethAddressLower);
}

export function convertMetadataToNonce(params: { message?: string }) {
  if (!params || !params.message) {
    return new BN(0);
  }
  return new BN(params.message, 16);
}

export const kCombinations = (s: number | number[], k: number): number[][] => {
  let set = s;
  if (typeof set === "number") {
    set = Array.from({ length: set }, (_, i) => i);
  }
  if (k > set.length || k <= 0) {
    return [];
  }

  if (k === set.length) {
    return [set];
  }

  if (k === 1) {
    return set.reduce((acc, cur) => [...acc, [cur]], [] as number[][]);
  }

  const combs: number[][] = [];
  let tailCombs: number[][] = [];

  for (let i = 0; i <= set.length - k + 1; i += 1) {
    tailCombs = kCombinations(set.slice(i + 1), k - 1);
    for (let j = 0; j < tailCombs.length; j += 1) {
      combs.push([set[i], ...tailCombs[j]]);
    }
  }

  return combs;
};

export const thresholdSame = <T>(arr: T[], t: number): T | undefined => {
  const hashMap: Record<string, number> = {};
  for (let i = 0; i < arr.length; i += 1) {
    const str = JsonStringify(arr[i]);
    hashMap[str] = hashMap[str] ? hashMap[str] + 1 : 1;
    if (hashMap[str] === t) {
      return arr[i];
    }
  }
  return undefined;
};

export const keyLookup = async (endpoints: string[], verifier: string, verifierId: string): Promise<KeyLookupResult> => {
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<VerifierLookupResponse>>(
      x,
      generateJsonRPCObject("VerifierLookupRequest", {
        verifier,
        verifier_id: verifierId.toString(),
      })
    ).catch((err) => log.error("lookup request failed", err))
  );
  return Some<void | JRPCResponse<VerifierLookupResponse>, KeyLookupResult>(lookupPromises, (lookupResults) => {
    const lookupShares = lookupResults.filter((x1) => x1);
    const errorResult = thresholdSame(
      lookupShares.map((x2) => x2 && x2.error),
      ~~(endpoints.length / 2) + 1
    );
    const keyResult = thresholdSame(
      lookupShares.map((x3) => x3 && x3.result),
      ~~(endpoints.length / 2) + 1
    );
    if (keyResult || errorResult) {
      return Promise.resolve({ keyResult, errorResult });
    }
    return Promise.reject(new Error(`invalid results ${JSON.stringify(lookupResults)}`));
  });
};

export const GetPubKeyOrKeyAssign = async (
  endpoints: string[],
  verifier: string,
  verifierId: string,
  extendedVerifierId?: string
): Promise<KeyLookupResult> => {
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<VerifierLookupResponse>>(
      x,
      generateJsonRPCObject("GetPubKeyOrKeyAssign", {
        verifier,
        verifier_id: verifierId.toString(),
        extended_verifier_id: extendedVerifierId,
        one_key_flow: true,
      })
    ).catch((err) => log.error("lookup request failed", err))
  );
  let nonceResult;
  const result = await Some<void | JRPCResponse<VerifierLookupResponse>, KeyLookupResult>(lookupPromises, (lookupResults) => {
    const lookupShares = lookupResults.filter((x1) => {
      if (x1) {
        // currently only one node returns metadata nonce
        // other nodes returns empty object
        const pubNonceX = x1.result?.keys[0].nonce_data?.pubNonce?.x;
        if (!nonceResult && pubNonceX) {
          nonceResult = x1.result.keys[0].nonce_data;
        }

        return x1;
      }
      return false;
    });
    const errorResult = thresholdSame(
      lookupShares.map((x2) => x2 && x2.error),
      ~~(endpoints.length / 2) + 1
    );
    const keyResult = thresholdSame(
      lookupShares.map((x3) => x3 && x3.result),
      ~~(endpoints.length / 2) + 1
    );
    if ((keyResult && (nonceResult || extendedVerifierId)) || errorResult) {
      return Promise.resolve({ keyResult, errorResult, nonceResult });
    }
    return Promise.reject(new Error(`invalid results ${JSON.stringify(lookupResults)}`));
  });

  return result;
};

export const waitKeyLookup = (endpoints: string[], verifier: string, verifierId: string, timeout: number): Promise<KeyLookupResult> =>
  new Promise((resolve, reject) => {
    setTimeout(() => {
      keyLookup(endpoints, verifier, verifierId).then(resolve).catch(reject);
    }, timeout);
  });

export function _retrieveOrImportShare(
  ecCurve: ec,
  endpoints: string[],
  verifier: string,
  verifierParams: VerifierParams,
  idToken: string,
  importedShares?: ImportedShare[],
  extraParams: Record<string, unknown> = {}
) {
  const promiseArr = [];
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
  let isImportShareReq = false;
  if (importedShares && importedShares.length > 0) {
    if (importedShares.length !== endpoints.length) {
      throw new Error("Invalid imported shares length");
    }
    isImportShareReq = true;
  }

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
      log.error("commitment error", err);
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

    if (completedRequests.length >= ~~((endpoints.length * 3) / 4) + 1) {
      return Promise.resolve(resultArr);
    }

    return Promise.reject(new Error(`invalid ${JSON.stringify(resultArr)}`));
  })
    .then((responses) => {
      const promiseArrRequest: Promise<void | JRPCResponse<ShareRequestResult>>[] = [];
      const nodeSigs = [];
      for (let i = 0; i < responses.length; i += 1) {
        if (responses[i]) nodeSigs.push((responses[i] as JRPCResponse<CommitmentRequestResult>).result);
      }

      for (let i = 0; i < endpoints.length; i += 1) {
        if (isImportShareReq) {
          const importedShare = importedShares[i];
          const p = post<JRPCResponse<ImportShareRequestResult>>(
            endpoints[i],
            generateJsonRPCObject("ImportShare", {
              encrypted: "yes",
              item: [
                {
                  ...verifierParams,
                  idtoken: idToken,
                  nodesignatures: nodeSigs,
                  verifieridentifier: verifier,
                  pub_key_x: importedShare.pub_key_x,
                  pub_key_y: importedShare.pub_key_y,
                  share: importedShare.share,
                  node_index: importedShare.node_index,
                  key_type: importedShare.key_type,
                  nonce_data: importedShare.nonce_data,
                  nonce_signature: importedShare.nonce_signature,
                  ...extraParams,
                },
              ],
              one_key_flow: true,
            })
          ).catch((err) => log.error("share req", err));
          promiseArrRequest.push(p);
        } else {
          const p = post<JRPCResponse<ShareRequestResult>>(
            endpoints[i],
            generateJsonRPCObject("GetShareOrKeyAssign", {
              encrypted: "yes",
              item: [
                {
                  ...verifierParams,
                  idtoken: idToken,
                  nodesignatures: nodeSigs,
                  verifieridentifier: verifier,
                  ...extraParams,
                },
              ],
              one_key_flow: true,
            })
          ).catch((err) => log.error("share req", err));
          promiseArrRequest.push(p);
        }
      }
      let thresholdMetadataNonce: BN;
      return Some<void | JRPCResponse<ShareRequestResult>, { privateKey: BN; sessionTokenData: SessionToken[]; metadataNonce: BN } | undefined>(
        promiseArrRequest,
        async (shareResponses, sharedState) => {
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
          const pubkeys = shareResponses.map((x) => {
            if (x && x.result && x.result.keys[0].public_key) {
              const pubNonce = x.result.keys[0].nonce_data?.pubNonce?.x;
              if (!thresholdMetadataNonce && pubNonce) {
                thresholdMetadataNonce = new BN(x.result.keys[0].nonce_data.nonce || "0", 16);
              }
              return x.result.keys[0].public_key;
            }
            return undefined;
          });

          const thresholdPublicKey = thresholdSame(pubkeys, ~~(endpoints.length / 2) + 1);

          // optimistically run lagrange interpolation once threshold number of shares have been received
          // this is matched against the user public key to ensure that shares are consistent
          // Note: no need of thresholdMetadataNonce for extended_verifier_id key
          if (
            completedRequests.length >= ~~(endpoints.length / 2) + 1 &&
            thresholdPublicKey &&
            (thresholdMetadataNonce || verifierParams.extended_verifier_id)
          ) {
            const sharePromises: Promise<void | Buffer>[] = [];
            const nodeIndexes: BN[] = [];
            const sessionTokenData: SessionToken[] = [];

            for (let i = 0; i < shareResponses.length; i += 1) {
              const currentShareResponse = shareResponses[i] as JRPCResponse<ShareRequestResult>;

              if (currentShareResponse?.result?.keys?.length > 0) {
                // currentShareResponse.result.keys.sort((a, b) => new BN(a.index.index, 16).cmp(new BN(b.index.index, 16)));
                const firstKey = currentShareResponse.result.keys[0];

                nodeIndexes.push(new BN(firstKey.node_index, 16));

                if (currentShareResponse.result.session_tokens) {
                  sessionTokenData.push({
                    token: currentShareResponse.result.session_tokens[0],
                    signature: currentShareResponse.result.session_token_sigs[0],
                    node_pubx: currentShareResponse.result.node_pubx[0],
                    node_puby: currentShareResponse.result.node_puby[0],
                  });
                } else {
                  sessionTokenData.push(undefined);
                }

                if (firstKey.metadata) {
                  const metadata = {
                    ephemPublicKey: Buffer.from(firstKey.metadata.ephemPublicKey, "hex"),
                    iv: Buffer.from(firstKey.metadata.iv, "hex"),
                    mac: Buffer.from(firstKey.metadata.mac, "hex"),
                    // mode: Buffer.from(firstKey.Metadata.mode, "hex"),
                  };

                  sharePromises.push(
                    decrypt(tmpKey, {
                      ...metadata,
                      ciphertext: Buffer.from(Buffer.from(firstKey.share, "base64").toString("binary").padStart(64, "0"), "hex"),
                    }).catch((err) => log.debug("share decryption", err))
                  );
                } else {
                  sharePromises.push(Promise.resolve(Buffer.from(firstKey.share.padStart(64, "0"), "hex")));
                }
              } else {
                sessionTokenData.push(undefined);
                nodeIndexes.push(undefined);
                sharePromises.push(Promise.resolve(undefined));
              }
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
              const derivedPrivateKey = lagrangeInterpolation(ecCurve, shares, indices);
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

            return { privateKey, sessionTokenData, metadataNonce: thresholdMetadataNonce };
          }
          throw new Error("invalid");
        }
      );
    })
    .then(async (res) => {
      let { privateKey, sessionTokenData, metadataNonce } = res;
      if (!privateKey) throw new Error("Invalid private key returned");
      const decryptedPubKey = getPublic(Buffer.from(privateKey.toString(16, 64), "hex")).toString("hex");
      const decryptedPubKeyX = decryptedPubKey.slice(2, 66);
      const decryptedPubKeyY = decryptedPubKey.slice(66);
      if (verifierParams.extended_verifier_id) {
        metadataNonce = new BN(0);
      }
      log.debug("> torus.js/retrieveShares", { privKey: privateKey.toString(16), metadataNonce: metadataNonce.toString(16) });

      privateKey = privateKey.add(metadataNonce).umod(ecCurve.curve.n);

      const ethAddress = generateAddressFromPrivKey(ecCurve, privateKey);
      log.debug("> torus.js/retrieveShares", { ethAddress, privKey: privateKey.toString(16) });

      // return reconstructed private key and ethereum address
      return {
        ethAddress,
        privKey: privateKey.toString("hex", 64),
        metadataNonce,
        sessionTokensData: sessionTokenData,
        X: decryptedPubKeyX,
        Y: decryptedPubKeyY,
      };
    });
}
