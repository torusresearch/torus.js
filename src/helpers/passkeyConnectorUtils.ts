import { generateJsonRPCObject, post } from "@toruslabs/http-helpers";

import { config } from "../config";
import { JRPC_METHODS } from "../constants";
import { AuthMessageRequestResult, JRPCResponse } from "../interfaces";
import {
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
  const promiseArr: Promise<JRPCResponse<AuthMessageRequestResult>>[] = [];
  for (let i = 0; i < endpoints.length; i++) {
    const p = post<JRPCResponse<AuthMessageRequestResult>>(
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

  return new Promise<JRPCResponse<AuthMessageRequestResult>[]>((resolve, reject) => {
    Some<null | JRPCResponse<AuthMessageRequestResult>, (null | JRPCResponse<AuthMessageRequestResult>)[]>(promiseArr, (resultArr) => {
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
      .then((resultArr: JRPCResponse<AuthMessageRequestResult>[]) => {
        return resolve(resultArr);
      })
      .catch(reject);
  });
};

export const linkPasskey = async (params: LinkPasskeyParams) => {
  const { endpoints, message, label, passkeyPubKey, oAuthKeySignature, keyType, passkeyAuthData } = params;
  const halfThreshold = ~~(endpoints.length / 2) + 1;

  if (!endpoints || endpoints.length === 0) {
    throw new Error("Endpoints are required");
  }

  const promiseArr: Promise<JRPCResponse<Record<string, never>>>[] = [];
  for (let i = 0; i < endpoints.length; i++) {
    const p = post<JRPCResponse<Record<string, never>>>(
      endpoints[i],
      generateJsonRPCObject(JRPC_METHODS.LINK_PASSKEY, {
        message,
        label,
        passkey_pub_key: passkeyPubKey,
        verifier_account_signature: oAuthKeySignature,
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

export const UnlinkPasskey = async (params: UnLinkPasskeyParams) => {
  const { endpoints, message, passkeyPubKey, oAuthKeySignature, keyType } = params;
  const halfThreshold = ~~(endpoints.length / 2) + 1;

  if (!endpoints || endpoints.length === 0) {
    throw new Error("Endpoints are required");
  }

  const promiseArr: Promise<JRPCResponse<Record<string, never>>>[] = [];
  for (let i = 0; i < endpoints.length; i++) {
    const p = post<JRPCResponse<Record<string, never>>>(
      endpoints[i],
      generateJsonRPCObject(JRPC_METHODS.UNLINK_PASSKEY, {
        message,
        passkey_pub_key: passkeyPubKey,
        verifier_account_signature: oAuthKeySignature,
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

export const ListLinkedPasskey = async (params: ListLinkedPasskeysParams) => {
  const { endpoints, message, oAuthKeySignature, keyType } = params;
  const halfThreshold = ~~(endpoints.length / 2) + 1;

  if (!endpoints || endpoints.length === 0) {
    throw new Error("Endpoints are required");
  }

  const promiseArr: Promise<JRPCResponse<ListLinkedPasskeysResponse>>[] = [];
  for (let i = 0; i < endpoints.length; i++) {
    const p = post<JRPCResponse<ListLinkedPasskeysResponse>>(
      endpoints[i],
      generateJsonRPCObject(JRPC_METHODS.GET_LINKED_PASSKEYS, {
        message,
        verifier_account_signature: oAuthKeySignature,
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
          request.result.passkeys.forEach((passkey) => {
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
      return Promise.reject(new Error("Failed to get auth message from threshold number of nodes"));
    })
      .then((resultArr: PasskeyListItem[]) => {
        return resolve(resultArr);
      })
      .catch(reject);
  });
};
