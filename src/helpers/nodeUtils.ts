import { INodePub, LEGACY_NETWORKS_ROUTE_MAP, TORUS_LEGACY_NETWORK_TYPE, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
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
  KeyType,
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
import {
  calculateMedian,
  getProxyCoordinatorEndpointIndex,
  kCombinations,
  normalizeKeysResult,
  normalizeLegacyKeysResult,
  thresholdSame,
} from "./common";
import { derivePubKey, generateAddressFromPrivKey, generateAddressFromPubKey, generatePrivateKey, generateShares, keccak256 } from "./keyUtils";
import { lagrangeInterpolation } from "./langrangeInterpolatePoly";
import { decryptNodeData, getMetadata, getOrSetNonce } from "./metadataUtils";

export const GetPubKeyOrKeyAssign = async (params: {
  endpoints: string[];
  network: TORUS_NETWORK_TYPE;
  verifier: string;
  verifierId: string;
  keyType: KeyType;
  extendedVerifierId?: string;
}): Promise<KeyLookupResult> => {
  const { endpoints, network, verifier, verifierId, extendedVerifierId, keyType } = params;
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<VerifierLookupResponse>>(
      x,
      generateJsonRPCObject(JRPC_METHODS.GET_OR_SET_KEY, {
        distributed_metadata: true,
        verifier,
        verifier_id: verifierId.toString(),
        extended_verifier_id: extendedVerifierId,
        one_key_flow: true,
        key_type: keyType,
        fetch_node_index: true,
        client_time: Math.floor(Date.now() / 1000).toString(),
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

    // check for nonce result in response if not a extendedVerifierId and not a legacy network
    if (keyResult && !nonceResult && !extendedVerifierId && !LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE]) {
      for (let i = 0; i < lookupResults.length; i++) {
        const x1 = lookupResults[i];
        if (x1 && !x1.error) {
          const currentNodePubKey = x1.result.keys[0].pub_key_X.toLowerCase();
          const thresholdPubKey = keyResult.keys[0].pub_key_X.toLowerCase();
          const pubNonceX = (x1.result?.keys[0].nonce_data as v2NonceResultType)?.pubNonce?.x;
          if (pubNonceX && currentNodePubKey === thresholdPubKey) {
            nonceResult = x1.result.keys[0].nonce_data;
            break;
          }
        }
      }
    }

    const serverTimeOffsets: number[] = [];
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
              const nodeIndex = Number.parseInt(x1.result.node_index);
              if (nodeIndex) nodeIndexes.push(nodeIndex);
            }
            const serverTimeOffset = x1.result.server_time_offset ? Number.parseInt(x1.result.server_time_offset, 10) : 0;
            serverTimeOffsets.push(serverTimeOffset);
          }
        });
      }

      const serverTimeOffset = keyResult ? calculateMedian(serverTimeOffsets) : 0;
      return Promise.resolve({ keyResult, serverTimeOffset, nodeIndexes, errorResult, nonceResult });
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
  keyType: KeyType;
  allowHost: string;
  network: string;
  clientId: string;
  endpoints: string[];
  indexes: number[];
  verifier: string;
  verifierParams: VerifierParams;
  idToken: string;
  useDkg: boolean;
  overrideExistingKey: boolean;
  nodePubkeys: INodePub[];
  newImportedShares?: ImportedShare[];
  extraParams: Record<string, unknown>;
}): Promise<TorusKey> {
  const {
    legacyMetadataHost,
    enableOneKey,
    ecCurve,
    keyType,
    allowHost,
    network,
    clientId,
    endpoints,
    nodePubkeys,
    indexes,
    verifier,
    verifierParams,
    idToken,
    overrideExistingKey,
    newImportedShares,
    extraParams,
    useDkg = true,
    serverTimeOffset,
  } = params;
  await get<void>(
    allowHost,
    {
      headers: {
        verifier,
        verifierid: verifierParams.verifier_id,
        network,
        clientid: clientId,
        enablegating: "true",
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
  let finalImportedShares: ImportedShare[] = [];

  if (newImportedShares.length > 0) {
    if (newImportedShares.length !== endpoints.length) {
      throw new Error("Invalid imported shares length");
    }
    finalImportedShares = newImportedShares;
  } else if (!useDkg) {
    const importedKey = new BN(generatePrivateKey(ecCurve, Buffer));
    const generatedShares = await generateShares(ecCurve, keyType, serverTimeOffset, indexes, nodePubkeys, importedKey.toString(16, 64));
    finalImportedShares = [...finalImportedShares, ...generatedShares];
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
        keytype: keyType,
        tokencommitment: tokenCommitment.slice(2),
        temppubx: pubKeyX,
        temppuby: pubKeyY,
        verifieridentifier: verifier,
        verifier_id: verifierParams.verifier_id,
        is_import_key_flow: true,
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

    if (finalImportedShares.length > 0) {
      // this case is for imported keys
      // for imported keys registration we need to wait for all nodes to agree on commitment
      // for existing imported keys we can rely on threshold nodes commitment
      if (overrideExistingKey && completedRequests.length === endpoints.length) {
        const requiredNodeResult = completedRequests.find((resp: void | JRPCResponse<CommitmentRequestResult>) => {
          if (resp && resp.result?.nodeindex === "1") {
            return true;
          }
          return false;
        });
        if (requiredNodeResult) {
          return Promise.resolve(resultArr);
        }
      } else if (!overrideExistingKey && completedRequests.length >= ~~((endpoints.length * 3) / 4) + 1) {
        // for import shares, proxy node response is required.
        // proxy node returns metadata unlike dkg keys where node 1 is checked for metadata.
        // if user's account already
        const nodeSigs: CommitmentRequestResult[] = [];
        for (let i = 0; i < completedRequests.length; i += 1) {
          const x = completedRequests[i];
          if (!x || typeof x !== "object" || x.error) {
            continue;
          }
          if (x) nodeSigs.push((x as JRPCResponse<CommitmentRequestResult>).result);
        }
        const existingPubKey = thresholdSame(
          nodeSigs.map((x) => x && x.pub_key_x),
          ~~(endpoints.length / 2) + 1
        );
        const proxyEndpointNum = getProxyCoordinatorEndpointIndex(endpoints, verifier, verifierParams.verifier_id);
        const requiredNodeIndex = indexes[proxyEndpointNum].toString(10);

        // if not a existing key we need to wait for nodes to agree on commitment
        if (existingPubKey || (!existingPubKey && completedRequests.length === endpoints.length)) {
          const requiredNodeResult = completedRequests.find((resp: void | JRPCResponse<CommitmentRequestResult>) => {
            if (resp && resp.result?.nodeindex === requiredNodeIndex) {
              return true;
            }
            return false;
          });
          if (requiredNodeResult) {
            return Promise.resolve(resultArr);
          }
        }
      }
    } else if (completedRequests.length >= ~~((endpoints.length * 3) / 4) + 1) {
      // this case is for dkg keys
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
      const promiseArrRequest: Promise<void | JRPCResponse<ShareRequestResult> | JRPCResponse<ShareRequestResult[]>>[] = [];
      const nodeSigs: CommitmentRequestResult[] = [];
      for (let i = 0; i < responses.length; i += 1) {
        const x = responses[i];
        if (!x || typeof x !== "object" || x.error) {
          continue;
        }
        if (x) nodeSigs.push((x as JRPCResponse<CommitmentRequestResult>).result);
      }

      // if user's account already
      const existingPubKey = thresholdSame(
        nodeSigs.map((x) => x && x.pub_key_x),
        ~~(endpoints.length / 2) + 1
      );

      // can only import shares if override existing key is allowed or for new non dkg registration
      const canImportedShares = overrideExistingKey || (!useDkg && !existingPubKey);
      if (canImportedShares) {
        const proxyEndpointNum = getProxyCoordinatorEndpointIndex(endpoints, verifier, verifierParams.verifier_id);
        const items: Record<string, unknown>[] = [];
        for (let i = 0; i < endpoints.length; i += 1) {
          const x = responses[i];
          if (!x || typeof x !== "object" || x.error) {
            continue;
          }
          const importedShare = finalImportedShares[i];
          items.push({
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
            sss_endpoint: endpoints[i],
            ...extraParams,
          });
        }
        const p = post<JRPCResponse<ImportShareRequestResult[]>>(
          endpoints[proxyEndpointNum],
          generateJsonRPCObject(JRPC_METHODS.IMPORT_SHARES, {
            encrypted: "yes",
            use_temp: true,
            item: items,
            key_type: keyType,
            one_key_flow: true,
          }),
          null,
          { logTracingHeader: config.logRequestTracing }
        ).catch((err) => log.error("share req", err));
        promiseArrRequest.push(p);
      } else {
        for (let i = 0; i < endpoints.length; i += 1) {
          const x = responses[i];
          if (!x || typeof x !== "object" || x.error) {
            continue;
          }
          const p = post<JRPCResponse<ShareRequestResult>>(
            endpoints[i],
            generateJsonRPCObject(JRPC_METHODS.GET_SHARE_OR_KEY_ASSIGN, {
              encrypted: "yes",
              use_temp: true,
              key_type: keyType,
              distributed_metadata: true,
              item: [
                {
                  ...verifierParams,
                  idtoken: idToken,
                  key_type: keyType,
                  nodesignatures: nodeSigs,
                  verifieridentifier: verifier,
                  ...extraParams,
                },
              ],
              client_time: Math.floor(Date.now() / 1000).toString(),
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
        void | JRPCResponse<ShareRequestResult> | JRPCResponse<ShareRequestResult[]>,
        | {
            privateKey: BN;
            sessionTokenData: SessionToken[];
            thresholdNonceData: GetOrSetNonceResult;
            nodeIndexes: BN[];
            isNewKey: boolean;
            serverTimeOffsetResponse?: number;
          }
        | undefined
      >(promiseArrRequest, async (shareResponseResult, sharedState) => {
        let shareResponses: (void | JRPCResponse<ShareRequestResult>)[] = [];
        // for import shares case, where result is an array
        if (shareResponseResult.length === 1 && shareResponseResult[0] && Array.isArray(shareResponseResult[0].result)) {
          // this is for import shares
          const importedSharesResult = shareResponseResult[0];
          shareResponseResult[0].result.forEach((res) => {
            shareResponses.push({
              id: importedSharesResult.id,
              jsonrpc: "2.0",
              result: res,
              error: importedSharesResult.error,
            });
          });
        } else {
          shareResponses = shareResponseResult as (void | JRPCResponse<ShareRequestResult>)[];
        }
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
            return x.result.keys[0].public_key;
          }
          return undefined;
        });

        const thresholdPublicKey = thresholdSame(pubkeys, ~~(endpoints.length / 2) + 1);

        if (!thresholdPublicKey) {
          throw new Error("invalid result from nodes, threshold number of public key results are not matching");
        }

        shareResponses.forEach((x) => {
          const requiredShareResponse = x && x.result && x.result.keys[0].public_key && x.result.keys[0];
          if (requiredShareResponse && !thresholdNonceData && !verifierParams.extended_verifier_id) {
            const currentPubKey = requiredShareResponse.public_key;
            const pubNonce = (requiredShareResponse.nonce_data as v2NonceResultType)?.pubNonce?.x;
            if (pubNonce && currentPubKey.X === thresholdPublicKey.X) {
              thresholdNonceData = requiredShareResponse.nonce_data;
            }
          }
        });

        // if both thresholdNonceData and extended_verifier_id are not available
        // then we need to throw other wise address would be incorrect.
        if (!thresholdNonceData && !verifierParams.extended_verifier_id && !LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE]) {
          throw new Error(
            `invalid metadata result from nodes, nonce metadata is empty for verifier: ${verifier} and verifierId: ${verifierParams.verifier_id}`
          );
        }

        const thresholdReqCount = ~~(endpoints.length / 2) + 1;
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
          const serverTimeOffsetResponses: string[] = [];

          for (let i = 0; i < completedRequests.length; i += 1) {
            const currentShareResponse = completedRequests[i] as JRPCResponse<ShareRequestResult>;
            const {
              session_tokens: sessionTokens,
              session_token_metadata: sessionTokenMetadata,
              session_token_sigs: sessionTokenSigs,
              session_token_sig_metadata: sessionTokenSigMetadata,
              keys,
              is_new_key: isNewKey,
              server_time_offset: serverTimeOffsetResponse,
            } = currentShareResponse.result;

            isNewKeyResponses.push(isNewKey);
            serverTimeOffsetResponses.push(serverTimeOffsetResponse || "0");

            if (sessionTokenSigs?.length > 0) {
              // decrypt sessionSig if enc metadata is sent
              if (sessionTokenSigMetadata && sessionTokenSigMetadata[0]?.ephemPublicKey) {
                sessionTokenSigPromises.push(
                  decryptNodeData(sessionTokenSigMetadata[0], sessionTokenSigs[0], sessionAuthKey).catch((err) =>
                    log.error("session sig decryption", err)
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
                    log.error("session token sig decryption", err)
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
                  ).catch((err) => log.error("share decryption", err))
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
              if (curr) {
                acc.push({ index: nodeIndexes[index], value: new BN(curr) });
              }
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
            const decryptedPubKey = derivePubKey(ecCurve, derivedPrivateKey);
            const decryptedPubKeyX = decryptedPubKey.getX();
            const decryptedPubKeyY = decryptedPubKey.getY();

            if (decryptedPubKeyX.cmp(new BN(thresholdPublicKey.X, 16)) === 0 && decryptedPubKeyY.cmp(new BN(thresholdPublicKey.Y, 16)) === 0) {
              privateKey = derivedPrivateKey;
              break;
            }
          }

          if (privateKey === undefined || privateKey === null) {
            throw new Error("could not derive private key");
          }

          const thresholdIsNewKey = thresholdSame(isNewKeyResponses, ~~(endpoints.length / 2) + 1);

          // Convert each string timestamp to a number
          const serverOffsetTimes = serverTimeOffsetResponses.map((timestamp) => Number.parseInt(timestamp, 10));

          return {
            privateKey,
            sessionTokenData,
            thresholdNonceData,
            nodeIndexes,
            isNewKey: thresholdIsNewKey === "true",
            serverTimeOffsetResponse: serverTimeOffset || calculateMedian(serverOffsetTimes),
          };
        }
        throw new Error("Invalid");
      });
    })
    .then(async (res) => {
      const { privateKey, sessionTokenData, thresholdNonceData, nodeIndexes, isNewKey, serverTimeOffsetResponse } = res;
      let nonceResult = thresholdNonceData;
      if (!privateKey) throw new Error("Invalid private key returned");
      const oAuthKey = privateKey;
      const oAuthPubKey = derivePubKey(ecCurve, oAuthKey);
      const oAuthPubkeyX = oAuthPubKey.getX().toString("hex", 64);
      const oAuthPubkeyY = oAuthPubKey.getY().toString("hex", 64);

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
          nonceResult = await getOrSetNonce(
            legacyMetadataHost,
            ecCurve,
            keyType,
            serverTimeOffsetResponse,
            oAuthPubkeyX,
            oAuthPubkeyY,
            oAuthKey,
            !isNewKey
          );
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
          serverTimeOffset: serverTimeOffsetResponse,
        },
        nodesData: {
          nodeIndexes: nodeIndexes.map((x) => x.toNumber()),
        },
      } as TorusKey;
    });
}

export const legacyKeyLookup = async (
  endpoints: string[],
  verifier: string,
  verifierId: string,
  keyType: KeyType
): Promise<LegacyKeyLookupResult> => {
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<LegacyVerifierLookupResponse>>(
      x,
      generateJsonRPCObject("VerifierLookupRequest", {
        verifier,
        verifier_id: verifierId.toString(),
        key_type: keyType,
        client_time: Math.floor(Date.now() / 1000).toString(),
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
      lookupShares.map((x3) => x3 && normalizeLegacyKeysResult(x3.result)),
      ~~(endpoints.length / 2) + 1
    );

    const serverTimeOffsets: number[] = [];
    // nonceResult must exist except for extendedVerifierId and legacy networks along with keyResult
    if (keyResult) {
      lookupResults.forEach((x1) => {
        if (x1 && x1.result) {
          const timeOffSet = x1.result.server_time_offset;
          const serverTimeOffset = timeOffSet ? Number.parseInt(timeOffSet, 10) : 0;
          serverTimeOffsets.push(serverTimeOffset);
        }
      });
    }

    if (keyResult || errorResult) {
      const serverTimeOffset = keyResult ? calculateMedian(serverTimeOffsets) : 0;
      return Promise.resolve({ keyResult, errorResult, serverTimeOffset });
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
  keyType,
}: KeyAssignInput): Promise<void> => {
  let nodeNum: number;
  let initialPoint: number | undefined;
  if (lastPoint === undefined) {
    nodeNum = Math.floor(Math.random() * endpoints.length);
    // nodeNum = endpoints.indexOf("https://torus-node.binancex.dev/jrpc");
    initialPoint = nodeNum;
  } else {
    nodeNum = lastPoint % endpoints.length;
  }
  if (nodeNum === firstPoint) throw new Error("Looped through all");
  if (firstPoint !== undefined) initialPoint = firstPoint;

  const data = generateJsonRPCObject("KeyAssign", {
    verifier,
    verifier_id: verifierId.toString(),
    // key_type: keyType,  // NOTE: key type doesnt work for legacy networks and doesnt have to , so skipping it here.
  });
  try {
    const signedData = await post<SignerResponse>(
      signerHost,
      data,
      {
        headers: {
          pubkeyx: torusNodePubs[nodeNum].X,
          pubkeyy: torusNodePubs[nodeNum].Y,
          network,
          clientid: clientId,
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
        keyType,
      });
    throw new Error(
      `Sorry, the Torus Network that powers Web3Auth is currently very busy.
    We will generate your key in time. Pls try again later. \n
    ${error.message || ""}`
    );
  }
};

export const legacyWaitKeyLookup = (
  endpoints: string[],
  verifier: string,
  verifierId: string,
  keyType: KeyType,
  timeout: number
): Promise<LegacyKeyLookupResult> =>
  new Promise((resolve, reject) => {
    setTimeout(() => {
      legacyKeyLookup(endpoints, verifier, verifierId, keyType).then(resolve).catch(reject);
    }, timeout);
  });
