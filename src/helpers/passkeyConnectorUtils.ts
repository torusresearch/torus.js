import { generateJsonRPCObject, post } from "@toruslabs/http-helpers";

import { config } from "../config";
import { JRPC_METHODS } from "../constants";
import { JRPCResponse } from "../interfaces";
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
export const getAuthMessageFromNodes = (params: GetAuthMessageFromNodesParams) => {
  const { verifier, verifierId, passkeyPubKey, endpoints } = params;
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
        return Promise.resolve(completedRequests);
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
  const { endpoints, messages, label, passkeyPubKey, oAuthKeySignatures, keyType, passkeyAuthData } = params;
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
  const { endpoints, messages, passkeyPubKey, oAuthKeySignatures, keyType } = params;
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
