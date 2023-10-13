import { LEGACY_NETWORKS_ROUTE_MAP, TORUS_LEGACY_NETWORK_TYPE, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
import { generatePrivate, getPublic } from "@toruslabs/eccrypto";
import { generateJsonRPCObject, get, post } from "@toruslabs/http-helpers";
import BN from "bn.js";
import { curve, ec } from "elliptic";

import { config } from "../config";
import { JRPC_METHODS } from "../constants";
import {
  CommitmentRequestResult,
  GetOrSetNonceResult,
  ImportedShare,
  ImportShareRequestResult,
  JRPCResponse,
  KeyAssignInput,
  KeyLookupResult,
  LegacyKeyLookupResult,
  LegacyVerifierLookupResponse,
  SessionToken,
  ShareRequestResult,
  SignerResponse,
  TorusKey,
  UserType,
  v2NonceResultType,
  VerifierLookupResponse,
  VerifierParams,
} from "../interfaces";
import log from "../loglevel";
import { Some } from "../some";
import { kCombinations, normalizeKeysResult, thresholdSame } from "./common";
import { generateAddressFromPrivKey, generateAddressFromPubKey, keccak256 } from "./keyUtils";
import { lagrangeInterpolation } from "./langrangeInterpolatePoly";
import { decryptNodeData, getMetadata, getOrSetNonce } from "./metadataUtils";

export const GetPubKeyOrKeyAssign = async (params: {
  endpoints: string[];
  network: TORUS_NETWORK_TYPE;
  verifier: string;
  verifierId: string;
  extendedVerifierId?: string;
}): Promise<KeyLookupResult> => {
  const { endpoints, network, verifier, verifierId, extendedVerifierId } = params;
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<VerifierLookupResponse>>(
      x,
      generateJsonRPCObject(JRPC_METHODS.GET_OR_SET_KEY, {
        verifier,
        verifier_id: verifierId.toString(),
        extended_verifier_id: extendedVerifierId,
        one_key_flow: true,
        fetch_node_index: true,
      }),
      null,
      { logTracingHeader: config.logRequestTracing }
    ).catch((err) => log.error(`${JRPC_METHODS.GET_OR_SET_KEY} request failed`, err))
  );

  let nonceResult: GetOrSetNonceResult | undefined;
  const nodeIndexes: number[] = [];
  const result = await Some<void | JRPCResponse<VerifierLookupResponse>, KeyLookupResult>(lookupPromises, (lookupResults) => {
    const lookupPubKeys = lookupResults.filter((x1) => {
      if (x1 && !x1.error) {
        if (!nonceResult) {
          // currently only one node returns metadata nonce
          // other nodes returns empty object
          // pubNonce must be available to derive the public key
          const pubNonceX = (x1.result?.keys[0].nonce_data as v2NonceResultType)?.pubNonce?.x;
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

    // nonceResult must exist except for extendedVerifierId and legacy networks along with keyResult
    if ((keyResult && (nonceResult || extendedVerifierId || LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE])) || errorResult) {
      if (keyResult) {
        lookupResults.forEach((x1) => {
          if (x1 && x1.result) {
            const currentNodePubKey = x1.result.keys[0].pub_key_X.toLowerCase();
            const thresholdPubKey = keyResult.keys[0].pub_key_X.toLowerCase();
            // push only those indexes for nodes who are returning pub key matching with threshold pub key.
            // this check is important when different nodes have different keys assigned to a user.
            if (currentNodePubKey === thresholdPubKey) {
              const nodeIndex = parseInt(x1.result.node_index);
              if (nodeIndex) nodeIndexes.push(nodeIndex);
            }
          }
        });
      }
      return Promise.resolve({ keyResult, nodeIndexes, errorResult, nonceResult });
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

export async function retrieveOrImportShare(params: {
  legacyMetadataHost: string;
  serverTimeOffset: number;
  enableOneKey: boolean;
  ecCurve: ec;
  allowHost: string;
  network: string;
  clientId: string;
  endpoints: string[];
  verifier: string;
  verifierParams: VerifierParams;
  idToken: string;
  importedShares?: ImportedShare[];
  extraParams: Record<string, unknown>;
}): Promise<TorusKey> {
  const {
    legacyMetadataHost,
    serverTimeOffset,
    enableOneKey,
    ecCurve,
    allowHost,
    network,
    clientId,
    endpoints,
    verifier,
    verifierParams,
    idToken,
    importedShares,
    extraParams,
  } = params;
  await get<void>(
    allowHost,
    {
      headers: {
        verifier,
        verifierId: verifierParams.verifier_id,
        network,
        clientId,
        enableGating: "true",
      },
    },
    { useAPIKey: true }
  );
  const promiseArr = [];

  // generate temporary private and public key that is used to secure receive shares
  const sessionAuthKey = generatePrivate();
  const pubKey = getPublic(sessionAuthKey).toString("hex");
  const pubKeyX = pubKey.slice(2, 66);
  const pubKeyY = pubKey.slice(66);
  const tokenCommitment = keccak256(Buffer.from(idToken, "utf8"));
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
      }),
      null,
      { logTracingHeader: config.logRequestTracing }
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

    // we need to get commitments from all endpoints for importing share
    if (importedShares.length > 0 && completedRequests.length === endpoints.length) {
      return Promise.resolve(resultArr);
    } else if (importedShares.length === 0 && completedRequests.length >= ~~((endpoints.length * 3) / 4) + 1) {
      const requiredNodeResult = completedRequests.find((resp: void | JRPCResponse<CommitmentRequestResult>) => {
        if (resp && resp.result?.nodeindex === "1") {
          return true;
        }
        return false;
      });

      if (requiredNodeResult) {
        return Promise.resolve(resultArr);
      }
    }

    return Promise.reject(new Error(`invalid ${JSON.stringify(resultArr)}`));
  })
    .then((responses) => {
      const promiseArrRequest: Promise<void | JRPCResponse<ShareRequestResult>>[] = [];
      const nodeSigs: CommitmentRequestResult[] = [];
      for (let i = 0; i < responses.length; i += 1) {
        const x = responses[i];
        if (!x || typeof x !== "object") {
          continue;
        }
        if (x.error) {
          continue;
        }
        if (x) nodeSigs.push((x as JRPCResponse<CommitmentRequestResult>).result);
      }
      for (let i = 0; i < endpoints.length; i += 1) {
        const x = responses[i];
        if (!x || typeof x !== "object") {
          continue;
        }
        if (x.error) {
          continue;
        }
        if (isImportShareReq) {
          const importedShare = importedShares[i];
          const p = post<JRPCResponse<ImportShareRequestResult>>(
            endpoints[i],
            generateJsonRPCObject(JRPC_METHODS.IMPORT_SHARE, {
              encrypted: "yes",
              use_temp: true,
              item: [
                {
                  ...verifierParams,
                  idtoken: idToken,
                  nodesignatures: nodeSigs,
                  verifieridentifier: verifier,
                  pub_key_x: importedShare.pub_key_x,
                  pub_key_y: importedShare.pub_key_y,
                  encrypted_share: importedShare.encrypted_share,
                  encrypted_share_metadata: importedShare.encrypted_share_metadata,
                  node_index: importedShare.node_index,
                  key_type: importedShare.key_type,
                  nonce_data: importedShare.nonce_data,
                  nonce_signature: importedShare.nonce_signature,
                  ...extraParams,
                },
              ],
              one_key_flow: true,
            }),
            null,
            { logTracingHeader: config.logRequestTracing }
          ).catch((err) => log.error("share req", err));
          promiseArrRequest.push(p);
        } else {
          const p = post<JRPCResponse<ShareRequestResult>>(
            endpoints[i],
            generateJsonRPCObject(JRPC_METHODS.GET_SHARE_OR_KEY_ASSIGN, {
              encrypted: "yes",
              use_temp: true,
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
            }),
            null,
            { logTracingHeader: config.logRequestTracing }
          ).catch((err) => log.error("share req", err));
          promiseArrRequest.push(p);
        }
      }
      let thresholdNonceData: GetOrSetNonceResult;
      return Some<
        void | JRPCResponse<ShareRequestResult>,
        | { privateKey: BN; sessionTokenData: SessionToken[]; thresholdNonceData: GetOrSetNonceResult; nodeIndexes: BN[]; isNewKey: boolean }
        | undefined
      >(promiseArrRequest, async (shareResponses, sharedState) => {
        // check if threshold number of nodes have returned the same user public key
        const completedRequests = shareResponses.filter((x) => {
          if (!x || typeof x !== "object") {
            return false;
          }
          if (x.error) {
            return false;
          }
          return true;
        });
        const pubkeys = shareResponses.map((x) => {
          if (x && x.result && x.result.keys[0].public_key) {
            if (!thresholdNonceData && !verifierParams.extended_verifier_id) {
              const pubNonce = (x.result.keys[0].nonce_data as v2NonceResultType)?.pubNonce?.x;
              if (pubNonce) {
                thresholdNonceData = x.result.keys[0].nonce_data;
              }
            }
            return x.result.keys[0].public_key;
          }
          return undefined;
        });

        const thresholdPublicKey = thresholdSame(pubkeys, ~~(endpoints.length / 2) + 1);

        if (!thresholdPublicKey) {
          throw new Error("invalid result from nodes, threshold number of public key results are not matching");
        }

        // if both thresholdNonceData and extended_verifier_id are not available
        // then we need to throw other wise address would be incorrect.
        if (!thresholdNonceData && !verifierParams.extended_verifier_id && !LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE]) {
          throw new Error(
            `invalid metadata result from nodes, nonce metadata is empty for verifier: ${verifier} and verifierId: ${verifierParams.verifier_id}`
          );
        }

        const thresholdReqCount = importedShares.length > 0 ? endpoints.length : ~~(endpoints.length / 2) + 1;
        // optimistically run lagrange interpolation once threshold number of shares have been received
        // this is matched against the user public key to ensure that shares are consistent
        // Note: no need of thresholdMetadataNonce for extended_verifier_id key
        if (
          completedRequests.length >= thresholdReqCount &&
          thresholdPublicKey &&
          (thresholdNonceData || verifierParams.extended_verifier_id || LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE])
        ) {
          const sharePromises: Promise<void | Buffer>[] = [];
          const sessionTokenSigPromises: Promise<void | Buffer>[] = [];
          const sessionTokenPromises: Promise<void | Buffer>[] = [];
          const nodeIndexes: BN[] = [];
          const sessionTokenData: SessionToken[] = [];
          const isNewKeyResponses: string[] = [];

          for (let i = 0; i < completedRequests.length; i += 1) {
            const currentShareResponse = completedRequests[i] as JRPCResponse<ShareRequestResult>;
            const {
              session_tokens: sessionTokens,
              session_token_metadata: sessionTokenMetadata,
              session_token_sigs: sessionTokenSigs,
              session_token_sig_metadata: sessionTokenSigMetadata,
              keys,
              is_new_key: isNewKey,
            } = currentShareResponse.result;

            isNewKeyResponses.push(isNewKey);

            if (sessionTokenSigs?.length > 0) {
              // decrypt sessionSig if enc metadata is sent
              if (sessionTokenSigMetadata && sessionTokenSigMetadata[0]?.ephemPublicKey) {
                sessionTokenSigPromises.push(
                  decryptNodeData(sessionTokenSigMetadata[0], sessionTokenSigs[0], sessionAuthKey).catch((err) =>
                    log.debug("session sig decryption", err)
                  )
                );
              } else {
                sessionTokenSigPromises.push(Promise.resolve(Buffer.from(sessionTokenSigs[0], "hex")));
              }
            } else {
              sessionTokenSigPromises.push(Promise.resolve(undefined));
            }

            if (sessionTokens?.length > 0) {
              // decrypt session token if enc metadata is sent
              if (sessionTokenMetadata && sessionTokenMetadata[0]?.ephemPublicKey) {
                sessionTokenPromises.push(
                  decryptNodeData(sessionTokenMetadata[0], sessionTokens[0], sessionAuthKey).catch((err) =>
                    log.debug("session token sig decryption", err)
                  )
                );
              } else {
                sessionTokenPromises.push(Promise.resolve(Buffer.from(sessionTokens[0], "base64")));
              }
            } else {
              sessionTokenPromises.push(Promise.resolve(undefined));
            }

            if (keys?.length > 0) {
              const latestKey = currentShareResponse.result.keys[0];
              nodeIndexes.push(new BN(latestKey.node_index));

              if (latestKey.share_metadata) {
                sharePromises.push(
                  decryptNodeData(
                    latestKey.share_metadata,
                    Buffer.from(latestKey.share, "base64").toString("binary").padStart(64, "0"),
                    sessionAuthKey
                  ).catch((err) => log.debug("share decryption", err))
                );
              }
            } else {
              nodeIndexes.push(undefined);
              sharePromises.push(Promise.resolve(undefined));
            }
          }
          const allPromises = await Promise.all(sharePromises.concat(sessionTokenSigPromises).concat(sessionTokenPromises));
          const sharesResolved = allPromises.slice(0, sharePromises.length);
          const sessionSigsResolved = allPromises.slice(sharePromises.length, sharePromises.length + sessionTokenSigPromises.length);
          const sessionTokensResolved = allPromises.slice(sharePromises.length + sessionTokenSigPromises.length, allPromises.length);
          const validSigs = sessionSigsResolved.filter((sig) => {
            if (sig) {
              return true;
            }
            return false;
          });

          const minThresholdRequired = ~~(endpoints.length / 2) + 1;
          if (!verifierParams.extended_verifier_id && validSigs.length < minThresholdRequired) {
            throw new Error(`Insufficient number of signatures from nodes, required: ${minThresholdRequired}, found: ${validSigs.length}`);
          }

          const validTokens = sessionTokensResolved.filter((token) => {
            if (token) {
              return true;
            }
            return false;
          });

          if (!verifierParams.extended_verifier_id && validTokens.length < minThresholdRequired) {
            throw new Error(`Insufficient number of session tokens from nodes, required: ${minThresholdRequired}, found: ${validTokens.length}`);
          }
          sessionTokensResolved.forEach((x, index) => {
            if (!x) sessionTokenData.push(undefined);
            else
              sessionTokenData.push({
                token: x.toString("base64"),
                signature: (sessionSigsResolved[index] as Buffer).toString("hex"),
                node_pubx: (completedRequests[index] as JRPCResponse<ShareRequestResult>).result.node_pubx,
                node_puby: (completedRequests[index] as JRPCResponse<ShareRequestResult>).result.node_puby,
              });
          });

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
          const thresholdIsNewKey = thresholdSame(isNewKeyResponses, ~~(endpoints.length / 2) + 1);

          return { privateKey, sessionTokenData, thresholdNonceData, nodeIndexes, isNewKey: thresholdIsNewKey === "true" };
        }
        throw new Error("Invalid");
      });
    })
    .then(async (res) => {
      const { privateKey, sessionTokenData, thresholdNonceData, nodeIndexes, isNewKey } = res;
      let nonceResult = thresholdNonceData;
      if (!privateKey) throw new Error("Invalid private key returned");
      const oAuthKey = privateKey;
      const oAuthPubKey = getPublic(Buffer.from(oAuthKey.toString(16, 64), "hex")).toString("hex");
      const oAuthPubkeyX = oAuthPubKey.slice(2, 66);
      const oAuthPubkeyY = oAuthPubKey.slice(66);
      let metadataNonce = new BN(nonceResult?.nonce ? nonceResult.nonce.padStart(64, "0") : "0", "hex");
      let finalPubKey: curve.base.BasePoint;
      let pubNonce: { X: string; Y: string } | undefined;
      let typeOfUser: UserType = "v1";
      // extended_verifier_id is only exception for torus-test-health verifier
      // otherwise extended verifier id should not even return shares.
      if (verifierParams.extended_verifier_id) {
        typeOfUser = "v2";
        // for tss key no need to add pub nonce
        finalPubKey = ecCurve.keyFromPublic({ x: oAuthPubkeyX, y: oAuthPubkeyY }).getPublic();
      } else if (LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE]) {
        if (enableOneKey) {
          nonceResult = await getOrSetNonce(legacyMetadataHost, ecCurve, serverTimeOffset, oAuthPubkeyX, oAuthPubkeyY, oAuthKey, !isNewKey);
          metadataNonce = new BN(nonceResult.nonce || "0", 16);
          typeOfUser = nonceResult.typeOfUser;
          if (typeOfUser === "v2") {
            pubNonce = { X: (nonceResult as v2NonceResultType).pubNonce.x, Y: (nonceResult as v2NonceResultType).pubNonce.y };
            finalPubKey = ecCurve
              .keyFromPublic({ x: oAuthPubkeyX, y: oAuthPubkeyY })
              .getPublic()
              .add(
                ecCurve
                  .keyFromPublic({ x: (nonceResult as v2NonceResultType).pubNonce.x, y: (nonceResult as v2NonceResultType).pubNonce.y })
                  .getPublic()
              );
          } else {
            typeOfUser = "v1";
            // for imported keys in legacy networks
            metadataNonce = await getMetadata(legacyMetadataHost, { pub_key_X: oAuthPubkeyX, pub_key_Y: oAuthPubkeyY });
            const privateKeyWithNonce = oAuthKey.add(metadataNonce).umod(ecCurve.curve.n);
            finalPubKey = ecCurve.keyFromPrivate(privateKeyWithNonce.toString(16, 64), "hex").getPublic();
          }
        } else {
          typeOfUser = "v1";
          // for imported keys in legacy networks
          metadataNonce = await getMetadata(legacyMetadataHost, { pub_key_X: oAuthPubkeyX, pub_key_Y: oAuthPubkeyY });
          const privateKeyWithNonce = oAuthKey.add(metadataNonce).umod(ecCurve.curve.n);
          finalPubKey = ecCurve.keyFromPrivate(privateKeyWithNonce.toString(16, 64), "hex").getPublic();
        }
      } else {
        typeOfUser = "v2";
        finalPubKey = ecCurve
          .keyFromPublic({ x: oAuthPubkeyX, y: oAuthPubkeyY })
          .getPublic()
          .add(
            ecCurve.keyFromPublic({ x: (nonceResult as v2NonceResultType).pubNonce.x, y: (nonceResult as v2NonceResultType).pubNonce.y }).getPublic()
          );
        pubNonce = { X: (nonceResult as v2NonceResultType).pubNonce.x, Y: (nonceResult as v2NonceResultType).pubNonce.y };
      }

      if (!finalPubKey) {
        throw new Error("Invalid public key, this might be a bug, please report this to web3auth team");
      }

      const oAuthKeyAddress = generateAddressFromPrivKey(ecCurve, oAuthKey);

      // deriving address from pub key coz pubkey is always available
      // but finalPrivKey won't be available for  v2 user upgraded to 2/n
      const finalEvmAddress = generateAddressFromPubKey(ecCurve, finalPubKey.getX(), finalPubKey.getY());
      log.debug("> torus.js/retrieveShares", { finalEvmAddress });
      let finalPrivKey = ""; // it is empty for v2 user upgraded to 2/n
      if (typeOfUser === "v1" || (typeOfUser === "v2" && metadataNonce.gt(new BN(0)))) {
        const privateKeyWithNonce = oAuthKey.add(metadataNonce).umod(ecCurve.curve.n);
        finalPrivKey = privateKeyWithNonce.toString("hex", 64);
      }

      let isUpgraded: boolean | null = false;
      if (typeOfUser === "v1") {
        isUpgraded = null;
      } else if (typeOfUser === "v2") {
        isUpgraded = metadataNonce.eq(new BN("0"));
      }
      // return reconstructed private key and ethereum address
      return {
        finalKeyData: {
          evmAddress: finalEvmAddress,
          X: finalPubKey.getX().toString(16, 64), // this is final pub x user before and after updating to 2/n
          Y: finalPubKey.getY().toString(16, 64), // this is final pub y user before and after updating to 2/n
          privKey: finalPrivKey,
        },
        oAuthKeyData: {
          evmAddress: oAuthKeyAddress,
          X: oAuthPubkeyX,
          Y: oAuthPubkeyY,
          privKey: oAuthKey.toString("hex", 64).padStart(64, "0"),
        },
        sessionData: {
          sessionTokenData,
          sessionAuthKey: sessionAuthKey.toString("hex").padStart(64, "0"),
        },
        metadata: {
          pubNonce,
          nonce: metadataNonce,
          typeOfUser,
          upgraded: isUpgraded,
        },
        nodesData: {
          nodeIndexes: nodeIndexes.map((x) => x.toNumber()),
        },
      } as TorusKey;
    });
}

export const legacyKeyLookup = async (endpoints: string[], verifier: string, verifierId: string): Promise<LegacyKeyLookupResult> => {
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<LegacyVerifierLookupResponse>>(
      x,
      generateJsonRPCObject("VerifierLookupRequest", {
        verifier,
        verifier_id: verifierId.toString(),
      })
    ).catch((err) => log.error("lookup request failed", err))
  );
  return Some<void | JRPCResponse<LegacyVerifierLookupResponse>, LegacyKeyLookupResult>(lookupPromises, (lookupResults) => {
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

export const legacyKeyAssign = async ({
  endpoints,
  torusNodePubs,
  lastPoint,
  firstPoint,
  verifier,
  verifierId,
  signerHost,
  network,
  clientId,
}: KeyAssignInput): Promise<void> => {
  let nodeNum: number;
  let initialPoint: number | undefined;
  if (lastPoint === undefined) {
    nodeNum = Math.floor(Math.random() * endpoints.length);
    // nodeNum = endpoints.indexOf("https://torus-node.binancex.dev/jrpc");
    log.info("keyassign", nodeNum, endpoints[nodeNum]);
    initialPoint = nodeNum;
  } else {
    nodeNum = lastPoint % endpoints.length;
  }
  if (nodeNum === firstPoint) throw new Error("Looped through all");
  if (firstPoint !== undefined) initialPoint = firstPoint;

  const data = generateJsonRPCObject("KeyAssign", {
    verifier,
    verifier_id: verifierId.toString(),
  });
  try {
    const signedData = await post<SignerResponse>(
      signerHost,
      data,
      {
        headers: {
          pubKeyX: torusNodePubs[nodeNum].X,
          pubKeyY: torusNodePubs[nodeNum].Y,
          network,
          clientId,
        },
      },
      { useAPIKey: true }
    );
    return await post<void>(
      endpoints[nodeNum],
      { ...data, ...signedData },
      {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
        },
      }
    );
  } catch (error2: unknown) {
    const error = error2 as { status: number; message: string };
    log.error(error.status, error.message, error, "key assign error");
    const acceptedErrorMsgs = [
      // Slow node
      "Timed out",
      "Failed to fetch",
      "cancelled",
      "NetworkError when attempting to fetch resource.",
      // Happens when the node is not reachable (dns issue etc)
      "TypeError: Failed to fetch", // All except iOS and Firefox
      "TypeError: cancelled", // iOS
      "TypeError: NetworkError when attempting to fetch resource.", // Firefox
    ];
    if (
      error?.status === 502 ||
      error?.status === 504 ||
      error?.status === 401 ||
      acceptedErrorMsgs.includes(error.message) ||
      acceptedErrorMsgs.some((x) => error.message?.includes(x)) ||
      (error.message && error.message.includes("reason: getaddrinfo EAI_AGAIN"))
    )
      return legacyKeyAssign({
        endpoints,
        torusNodePubs,
        lastPoint: nodeNum + 1,
        firstPoint: initialPoint,
        verifier,
        verifierId,
        signerHost,
        network,
        clientId,
      });
    throw new Error(
      `Sorry, the Torus Network that powers Web3Auth is currently very busy.
    We will generate your key in time. Pls try again later. \n
    ${error.message || ""}`
    );
  }
};

export const legacyWaitKeyLookup = (endpoints: string[], verifier: string, verifierId: string, timeout: number): Promise<LegacyKeyLookupResult> =>
  new Promise((resolve, reject) => {
    setTimeout(() => {
      legacyKeyLookup(endpoints, verifier, verifierId).then(resolve).catch(reject);
    }, timeout);
  });
