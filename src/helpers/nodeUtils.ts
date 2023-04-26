import { decrypt, generatePrivate, getPublic } from "@toruslabs/eccrypto";
import { generateJsonRPCObject, post } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec } from "elliptic";

import { JRPC_METHODS } from "../constants";
import {
  CommitmentRequestResult,
  GetOrSetNonceResult,
  ImportedShare,
  ImportShareRequestResult,
  JRPCResponse,
  KeyLookupResult,
  SessionToken,
  ShareRequestResult,
  VerifierLookupResponse,
  VerifierParams,
} from "../interfaces";
import log from "../loglevel";
import { Some } from "../some";
import { kCombinations, normalizeKeysResult, thresholdSame } from "./common";
import { generateAddressFromPubKey, keccak256 } from "./keyUtils";
import { lagrangeInterpolation } from "./langrangeInterpolatePoly";

export const GetPubKeyOrKeyAssign = async (
  endpoints: string[],
  verifier: string,
  verifierId: string,
  extendedVerifierId?: string
): Promise<KeyLookupResult> => {
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<VerifierLookupResponse>>(
      x,
      generateJsonRPCObject(JRPC_METHODS.GET_OR_SET_KEY, {
        verifier,
        verifier_id: verifierId.toString(),
        extended_verifier_id: extendedVerifierId,
        one_key_flow: true,
      })
    ).catch((err) => log.error(`${JRPC_METHODS.GET_OR_SET_KEY} request failed`, err))
  );

  let nonceResult: GetOrSetNonceResult | undefined;
  const result = await Some<void | JRPCResponse<VerifierLookupResponse>, KeyLookupResult>(lookupPromises, (lookupResults) => {
    const lookupPubKeys = lookupResults.filter((x1) => {
      if (x1) {
        if (!nonceResult) {
          // currently only one node returns metadata nonce
          // other nodes returns empty object
          // pubNonce must be available to derive the public key
          const pubNonceX = x1.result?.keys[0].nonce_data?.pubNonce?.x;
          if (pubNonceX) {
            nonceResult = x1.result.keys[0].nonce_data;
          }
        }
        return x1;
      }
      return false;
    });
    const errorResult = thresholdSame(
      lookupPubKeys.map((x2) => x2 && x2.error),
      ~~(endpoints.length / 2) + 1
    );
    const keyResult = thresholdSame(
      lookupPubKeys.map((x3) => x3 && normalizeKeysResult(x3.result)),
      ~~(endpoints.length / 2) + 1
    );

    // nonceResult must exist except for extendedVerifierId along with keyResult
    if ((keyResult && (nonceResult || extendedVerifierId)) || errorResult) {
      return Promise.resolve({ keyResult, errorResult, nonceResult });
    }
    return Promise.reject(
      new Error(
        `invalid public key result: ${JSON.stringify(lookupResults)} and nonce result:${JSON.stringify(
          nonceResult || {}
        )} for verifier: ${verifier}, verifierId: ${verifierId} and extendedVerifierId: ${extendedVerifierId} `
      )
    );
  });

  return result;
};

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
    /*
      CommitmentRequestParams struct {
        MessagePrefix      string `json:"messageprefix"`
        TokenCommitment    string `json:"tokencommitment"`
        TempPubX           string `json:"temppubx"`
        TempPubY           string `json:"temppuby"`
        VerifierIdentifier string `json:"verifieridentifier"`
      } 
      */
    const p = post<JRPCResponse<CommitmentRequestResult>>(
      endpoints[i],
      generateJsonRPCObject(JRPC_METHODS.COMMITMENT_REQUEST, {
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
      const nodeSigs: CommitmentRequestResult[] = [];
      for (let i = 0; i < responses.length; i += 1) {
        if (responses[i]) nodeSigs.push((responses[i] as JRPCResponse<CommitmentRequestResult>).result);
      }
      for (let i = 0; i < endpoints.length; i += 1) {
        if (isImportShareReq) {
          const importedShare = importedShares[i];
          const p = post<JRPCResponse<ImportShareRequestResult>>(
            endpoints[i],
            generateJsonRPCObject(JRPC_METHODS.IMPORT_SHARE, {
              encrypted: "yes",
              //   use_temp: true,
              // todo: this is a bit insecure cause shares are not encrypted
              // todo: the other way would be to encrypt each share using node pubkey that and then send it
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
            generateJsonRPCObject(JRPC_METHODS.GET_SHARE_OR_KEY_ASSIGN, {
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
      let thresholdNonceData: GetOrSetNonceResult;
      return Some<
        void | JRPCResponse<ShareRequestResult>,
        { privateKey: BN; sessionTokenData: SessionToken[]; thresholdNonceData: GetOrSetNonceResult } | undefined
      >(promiseArrRequest, async (shareResponses, sharedState) => {
        // check if threshold number of nodes have returned the same user public key
        const completedRequests = shareResponses.filter((x) => x);
        const pubkeys = shareResponses.map((x) => {
          if (x && x.result && x.result.keys[0].public_key) {
            if (!thresholdNonceData && !verifierParams.extended_verifier_id) {
              const pubNonce = x.result.keys[0].nonce_data?.pubNonce?.x;
              if (pubNonce) {
                thresholdNonceData = x.result.keys[0].nonce_data;
              }
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
          (thresholdNonceData || verifierParams.extended_verifier_id)
        ) {
          const sharePromises: Promise<void | Buffer>[] = [];
          const nodeIndexes: BN[] = [];
          const sessionTokenData: SessionToken[] = [];

          for (let i = 0; i < shareResponses.length; i += 1) {
            const currentShareResponse = shareResponses[i] as JRPCResponse<ShareRequestResult>;

            if (currentShareResponse?.result?.keys?.length > 0) {
              const latestKey = currentShareResponse.result.keys[0];
              nodeIndexes.push(new BN(latestKey.node_index, 16));
              const { session_tokens: sessionTokens, session_token_sigs: sessionSigs } = currentShareResponse.result;
              if (sessionTokens && sessionSigs) {
                let sessionSig = sessionSigs[0];

                // decrypt sessionSig if enc metadata is sent
                if (latestKey.sig_metadata?.ephemPublicKey) {
                  const metadata = {
                    ephemPublicKey: Buffer.from(latestKey.sig_metadata.ephemPublicKey, "hex"),
                    iv: Buffer.from(latestKey.sig_metadata.iv, "hex"),
                    mac: Buffer.from(latestKey.sig_metadata.mac, "hex"),
                    // mode: Buffer.from(latestKey.Metadata.mode, "hex"),
                  };
                  const decryptedSigBuffer = await decrypt(tmpKey, {
                    ...metadata,
                    ciphertext: Buffer.from(sessionSig, "hex"),
                  });
                  sessionSig = decryptedSigBuffer.toString("hex");
                }

                let sessionToken = sessionTokens[0];

                // decrypt session token if enc metadata is sent
                if (latestKey.session_token_metadata?.ephemPublicKey) {
                  const metadata = {
                    ephemPublicKey: Buffer.from(latestKey.session_token_metadata.ephemPublicKey, "hex"),
                    iv: Buffer.from(latestKey.session_token_metadata.iv, "hex"),
                    mac: Buffer.from(latestKey.session_token_metadata.mac, "hex"),
                    // mode: Buffer.from(latestKey.Metadata.mode, "hex"),
                  };
                  const decryptedSigBuffer = await decrypt(tmpKey, {
                    ...metadata,
                    ciphertext: Buffer.from(sessionToken, "hex"),
                  });
                  sessionToken = decryptedSigBuffer.toString("hex");
                }
                sessionTokenData.push({
                  token: sessionToken,
                  signature: sessionSig,
                  node_pubx: currentShareResponse.result.node_pubx,
                  node_puby: currentShareResponse.result.node_puby,
                });
              } else {
                sessionTokenData.push(undefined);
              }

              if (latestKey.metadata) {
                const metadata = {
                  ephemPublicKey: Buffer.from(latestKey.metadata.ephemPublicKey, "hex"),
                  iv: Buffer.from(latestKey.metadata.iv, "hex"),
                  mac: Buffer.from(latestKey.metadata.mac, "hex"),
                  // mode: Buffer.from(latestKey.Metadata.mode, "hex"),
                };

                sharePromises.push(
                  decrypt(tmpKey, {
                    ...metadata,
                    ciphertext: Buffer.from(Buffer.from(latestKey.share, "base64").toString("binary").padStart(64, "0"), "hex"),
                  }).catch((err) => log.debug("share decryption", err))
                );
              } else {
                sharePromises.push(Promise.resolve(Buffer.from(latestKey.share.padStart(64, "0"), "hex")));
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

          return { privateKey, sessionTokenData, thresholdNonceData };
        }
        if (!thresholdPublicKey) {
          throw new Error("invalid result from nodes, threshold number of public key results are not matching");
        }
        // if both thresholdNonceData and extended_verifier_id are not available
        // then we need to throw other wise address would be incorrect.
        if (!thresholdNonceData && !verifierParams.extended_verifier_id) {
          throw new Error(
            `invalid metadata result from nodes, nonce metadata is empty for verifier: ${verifier} and verifierId: ${verifierParams.verifier_id}`
          );
        }
      });
    })
    .then(async (res) => {
      const { privateKey, sessionTokenData, thresholdNonceData } = res;
      if (!privateKey) throw new Error("Invalid private key returned");
      const oauthKey = privateKey;
      const decryptedPubKey = getPublic(Buffer.from(oauthKey.toString(16, 64), "hex")).toString("hex");
      const decryptedPubKeyX = decryptedPubKey.slice(2, 66);
      const decryptedPubKeyY = decryptedPubKey.slice(66);
      const metadataNonce = new BN(thresholdNonceData?.nonce ? thresholdNonceData.nonce.padStart(64, "0") : "0", "hex");
      const privateKeyWithNonce = oauthKey.add(metadataNonce).umod(ecCurve.curve.n);

      let modifiedPubKey: curve.base.BasePoint;

      if (verifierParams.extended_verifier_id) {
        // for tss key no need to add pub nonce
        modifiedPubKey = ecCurve.keyFromPublic({ x: decryptedPubKeyX, y: decryptedPubKeyY }).getPublic();
      } else {
        modifiedPubKey = ecCurve
          .keyFromPublic({ x: decryptedPubKeyX, y: decryptedPubKeyY })
          .getPublic()
          .add(ecCurve.keyFromPublic({ x: thresholdNonceData.pubNonce.x, y: thresholdNonceData.pubNonce.y }).getPublic());
      }

      const ethAddress = generateAddressFromPubKey(ecCurve, modifiedPubKey.getX(), modifiedPubKey.getY());
      log.debug("> torus.js/retrieveShares", { ethAddress });

      // return reconstructed private key and ethereum address
      return {
        ethAddress, // this address should be used only if user hasn't updated to 2/n
        privKey: privateKeyWithNonce.toString("hex", 64).padStart(64, "0"), // Caution: final x and y wont be derivable from this key once user upgrades to 2/n
        metadataNonce,
        sessionTokensData: sessionTokenData,
        X: modifiedPubKey.getX().toString(), // this is final pub x of user before and after updating to 2/n
        Y: modifiedPubKey.getY().toString(), // this is final pub y of user before and after updating to 2/n
        postboxPubKeyX: decryptedPubKeyX,
        postboxPubKeyY: decryptedPubKeyY,
      };
    });
}
