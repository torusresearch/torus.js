import { INodePub, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
import { generatePrivate, getPublic } from "@toruslabs/eccrypto";
import { generateJsonRPCObject, post } from "@toruslabs/http-helpers";
import { ec } from "elliptic";

import { config } from "../config";
import { JRPC_METHODS } from "../constants";
import { JRPCResponse, KeyType, ShareRequestResult } from "../interfaces";
import {
  AuthMessageData,
  AuthMessageRequestJRPCResult,
  GetAuthMessageFromNodesParams,
  LinkPasskeyParams,
  ListLinkedPasskeysParams,
  ListLinkedPasskeysResponse,
  PasskeyListItem,
  UnLinkPasskeyParams,
} from "../passkeyConnectorInterfaces";
import { Some } from "../some";
import { TorusUtilsPasskeyExtraParams } from "../TorusUtilsExtraParams";
import { processShareResponse } from "./nodeUtils";
export const getAuthMessageFromNodes = (params: GetAuthMessageFromNodesParams) => {
  const { verifier, verifierId, passkeyPubKey, endpoints, requiredNodeIndexes } = params;
  const threeFourthsThreshold = ~~((endpoints.length * 3) / 4) + 1;

  if (!verifierId && !passkeyPubKey) {
    throw new Error("Verifier ID or passkey pub key is required");
  }
  const promiseArr: Promise<JRPCResponse<AuthMessageRequestJRPCResult>>[] = [];
  for (let i = 0; i < endpoints.length; i++) {
    const p = post<JRPCResponse<AuthMessageRequestJRPCResult>>(
      endpoints[i],
      generateJsonRPCObject(JRPC_METHODS.GENERATE_AUTH_MESSAGE, {
        verifier,
        verifier_id: verifierId,
        passkey_pub_key: passkeyPubKey,
      }),
      {},
      { logTracingHeader: config.logRequestTracing }
    );
    promiseArr.push(p);
  }

  return new Promise<AuthMessageData[]>((resolve, reject) => {
    Some<null | JRPCResponse<AuthMessageRequestJRPCResult>, (null | JRPCResponse<AuthMessageRequestJRPCResult>)[]>(promiseArr, (resultArr) => {
      const completedRequests = resultArr.filter((x) => {
        if (!x || typeof x !== "object") {
          return false;
        }
        if (x.error) {
          return false;
        }
        return true;
      });
      if (completedRequests.length >= threeFourthsThreshold) {
        // wait for all required node indexes to be resolved
        if (requiredNodeIndexes.length > 0) {
          const retrievedNodeIndexes: Record<number, boolean> = {};
          completedRequests.forEach((x) => {
            retrievedNodeIndexes[x.result.node_index] = true;
          });
          const pendingNodeIndexes = requiredNodeIndexes.filter((x) => {
            if (!retrievedNodeIndexes[x]) return x;
            return false;
          });
          if (pendingNodeIndexes.length === 0) {
            return Promise.resolve(completedRequests);
          }
        } else {
          return Promise.resolve(completedRequests);
        }
      }
      return Promise.reject(new Error("Failed to get auth message from threshold number of nodes"));
    })
      .then((resultArr: JRPCResponse<AuthMessageRequestJRPCResult>[]) => {
        const authMessageData: AuthMessageData[] = resultArr.map((x) => ({
          message: x.result.message,
          nodeIndex: x.result.node_index,
        }));
        return resolve(authMessageData);
      })
      .catch(reject);
  });
};

export const linkPasskey = async (params: LinkPasskeyParams) => {
  const { endpoints, messages, label, passkeyPubKey, oAuthKeySignatures, keyType, sessionData, passkeyAuthData } = params;
  const halfThreshold = ~~(endpoints.length / 2) + 1;

  if (!endpoints || endpoints.length < halfThreshold) {
    throw new Error(`minimum ${halfThreshold} endpoints are required`);
  }

  const promiseArr: Promise<JRPCResponse<Record<string, never>>>[] = [];
  for (let i = 0; i < endpoints.length; i++) {
    const p = post<JRPCResponse<Record<string, never>>>(
      endpoints[i],
      generateJsonRPCObject(JRPC_METHODS.LINK_PASSKEY, {
        message: messages[i],
        label,
        passkey_pub_key: passkeyPubKey,
        verifier_account_signature: oAuthKeySignatures[i],
        key_type: keyType,
        passkey_auth_data: passkeyAuthData,
        session_data: sessionData,
      }),
      {},
      { logTracingHeader: config.logRequestTracing }
    );
    promiseArr.push(p);
  }

  return new Promise<JRPCResponse<Record<string, never>>[]>((resolve, reject) => {
    Some<null | JRPCResponse<Record<string, never>>, (null | JRPCResponse<Record<string, never>>)[]>(promiseArr, (resultArr) => {
      const completedRequests = resultArr.filter((x) => {
        if (!x || typeof x !== "object") {
          return false;
        }
        if (x.error) {
          return false;
        }
        return true;
      });
      if (completedRequests.length >= halfThreshold) {
        return Promise.resolve(completedRequests);
      }
      return Promise.reject(new Error("Failed to get auth message from threshold number of nodes"));
    })
      .then((resultArr: JRPCResponse<Record<string, never>>[]) => {
        return resolve(resultArr);
      })
      .catch(reject);
  });
};

export const unlinkPasskey = async (params: UnLinkPasskeyParams) => {
  const { endpoints, messages, passkeyPubKey, oAuthKeySignatures, sessionData, keyType } = params;
  const halfThreshold = ~~(endpoints.length / 2) + 1;

  if (!endpoints || endpoints.length < halfThreshold) {
    throw new Error(`minimum ${halfThreshold} endpoints are required`);
  }

  const promiseArr: Promise<JRPCResponse<Record<string, never>>>[] = [];
  for (let i = 0; i < endpoints.length; i++) {
    const p = post<JRPCResponse<Record<string, never>>>(
      endpoints[i],
      generateJsonRPCObject(JRPC_METHODS.UNLINK_PASSKEY, {
        message: messages[i],
        passkey_pub_key: passkeyPubKey,
        verifier_account_signature: oAuthKeySignatures[i],
        key_type: keyType,
        session_data: sessionData,
      }),
      {},
      { logTracingHeader: config.logRequestTracing }
    );
    promiseArr.push(p);
  }

  return new Promise<JRPCResponse<Record<string, never>>[]>((resolve, reject) => {
    Some<null | JRPCResponse<Record<string, never>>, (null | JRPCResponse<Record<string, never>>)[]>(promiseArr, (resultArr) => {
      const completedRequests = resultArr.filter((x) => {
        if (!x || typeof x !== "object") {
          return false;
        }
        if (x.error) {
          return false;
        }
        return true;
      });
      if (completedRequests.length >= halfThreshold) {
        return Promise.resolve(completedRequests);
      }
      return Promise.reject(new Error("Failed to get auth message from threshold number of nodes"));
    })
      .then((resultArr: JRPCResponse<Record<string, never>>[]) => {
        return resolve(resultArr);
      })
      .catch(reject);
  });
};

export const listLinkedPasskey = async (params: ListLinkedPasskeysParams) => {
  const { endpoints, messages, oAuthKeySignatures, keyType } = params;
  const halfThreshold = ~~(endpoints.length / 2) + 1;

  if (!endpoints || endpoints.length < halfThreshold) {
    throw new Error(`minimum ${halfThreshold} endpoints are required`);
  }

  const promiseArr: Promise<JRPCResponse<ListLinkedPasskeysResponse>>[] = [];
  for (let i = 0; i < endpoints.length; i++) {
    const p = post<JRPCResponse<ListLinkedPasskeysResponse>>(
      endpoints[i],
      generateJsonRPCObject(JRPC_METHODS.GET_LINKED_PASSKEYS, {
        message: messages[i],
        verifier_account_signature: oAuthKeySignatures[i],
        key_type: keyType,
      }),
      {},
      { logTracingHeader: config.logRequestTracing }
    );
    promiseArr.push(p);
  }

  return new Promise<PasskeyListItem[]>((resolve, reject) => {
    Some<null | JRPCResponse<ListLinkedPasskeysResponse>, PasskeyListItem[]>(promiseArr, (resultArr) => {
      const completedRequests = resultArr.filter((x) => {
        if (!x || typeof x !== "object") {
          return false;
        }
        if (x.error) {
          return false;
        }
        return true;
      });
      if (completedRequests.length >= halfThreshold) {
        // find all passkeys object which have same passkey_pub_key inside each complated request passkeys array object
        // Find passkeys that appear in at least halfThreshold number of responses
        const passkeyMap = new Map<string, { count: number; passkey: PasskeyListItem }>();

        // Count occurrences of each passkey by pub_key
        completedRequests.forEach((request) => {
          const passkeys = request.result.passkeys || [];
          passkeys.forEach((passkey) => {
            const existing = passkeyMap.get(passkey.passkey_pub_key);
            if (existing) {
              existing.count++;
            } else {
              passkeyMap.set(passkey.passkey_pub_key, { count: 1, passkey });
            }
          });
        });

        // Filter passkeys that meet threshold requirement
        const result = Array.from(passkeyMap.values())
          .filter((item) => item.count >= halfThreshold)
          .map((item) => item.passkey);

        return Promise.resolve(result);
      }
    })
      .then((resultArr: PasskeyListItem[]) => {
        return resolve(resultArr);
      })
      .catch(reject);
  });
};

export async function _linkedPasskeyRetrieveShares(params: {
  serverTimeOffset: number;
  ecCurve: ec;
  keyType: KeyType;
  allowHost: string;
  network: TORUS_NETWORK_TYPE;
  clientId: string;
  endpoints: string[];
  nodePubkeys: INodePub[];
  indexes: number[];
  passkeyPublicKey: string;
  passkeyVerifierID: string;
  idToken: string;
  sessionExpSecond: number;
  extraParams: TorusUtilsPasskeyExtraParams;
}) {
  const { endpoints, passkeyPublicKey, passkeyVerifierID, idToken, keyType, sessionExpSecond, extraParams, serverTimeOffset, ecCurve, network } =
    params;

  // generate temporary private and public key that is used to secure receive shares
  const sessionAuthKey = generatePrivate();
  const pubKey = getPublic(sessionAuthKey).toString("hex");
  const sessionPubX = pubKey.slice(2, 66);
  const sessionPubY = pubKey.slice(66);
  const promiseArrRequest: Promise<void | JRPCResponse<ShareRequestResult>>[] = [];

  const passkeyExtraParams = { ...extraParams } as TorusUtilsPasskeyExtraParams;
  for (let i = 0; i < endpoints.length; i += 1) {
    const p = post<JRPCResponse<ShareRequestResult>>(
      endpoints[i],
      generateJsonRPCObject(JRPC_METHODS.RETRIEVE_SHARES_WITH_LINKED_PASSKEY, {
        encrypted: "yes",
        key_type: keyType,
        passkey_pub_key: passkeyPublicKey,
        temp_pub_x: sessionPubX,
        temp_pub_y: sessionPubY,
        passkey_auth_data: {
          verifier_id: passkeyVerifierID,
          idtoken: idToken,
          key_type: keyType,
          session_token_exp_second: sessionExpSecond,
          ...passkeyExtraParams,
        },
        client_time: Math.floor(Date.now() / 1000).toString(),
      }),
      {},
      { logTracingHeader: config.logRequestTracing }
    );
    promiseArrRequest.push(p);
  }
  return processShareResponse(
    {
      legacyMetadataHost: "", // this method only works for sapphire
      serverTimeOffset,
      sessionAuthKey,
      enableOneKey: true,
      ecCurve,
      keyType,
      network,
      verifierParams: { verifier_id: passkeyPublicKey },
      endpoints,
      isImportedShares: false,
    },
    promiseArrRequest
  );
}
