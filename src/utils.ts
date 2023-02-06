import { generateJsonRPCObject, get, post } from "@toruslabs/http-helpers";
import { SafeEventEmitter } from "@toruslabs/openlogin-jrpc";
import JsonStringify from "json-stable-stringify";
import createKeccakHash from "keccak";

import {
  JRPCResponse,
  KeyAssignInput,
  KeyAssignInputWithQueue,
  KeyAssignQueueResponse,
  KeyAssignStatus,
  KeyLookupResult,
  SignerResponse,
  VerifierLookupResponse,
} from "./interfaces";
import log from "./loglevel";
import { Some } from "./some";

export class GetOrSetNonceError extends Error {}

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

export const waitKeyLookup = (endpoints: string[], verifier: string, verifierId: string, timeout: number): Promise<KeyLookupResult> =>
  new Promise((resolve, reject) => {
    setTimeout(() => {
      keyLookup(endpoints, verifier, verifierId).then(resolve).catch(reject);
    }, timeout);
  });

export const keyAssign = async ({
  endpoints,
  torusNodePubs,
  lastPoint,
  firstPoint,
  verifier,
  verifierId,
  signerHost,
  network,
}: KeyAssignInput): Promise<void> => {
  let nodeNum: number;
  let initialPoint: number | undefined;
  if (lastPoint === undefined) {
    nodeNum = Math.floor(Math.random() * endpoints.length);
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
  } catch (error) {
    log.error(error);
    const acceptedErrorMsgs = [
      // Slow node
      "Timed out",
      // Happens when the node is not reachable (dns issue etc)
      "TypeError: Failed to fetch", // All except iOS and Firefox
      "TypeError: cancelled", // iOS
      "TypeError: NetworkError when attempting to fetch resource.", // Firefox
    ];
    if (
      error?.status === 502 ||
      acceptedErrorMsgs.includes(error.message) ||
      (error.message && error.message.includes("reason: getaddrinfo EAI_AGAIN"))
    )
      return keyAssign({ endpoints, torusNodePubs, lastPoint: nodeNum + 1, firstPoint: initialPoint, verifier, verifierId, signerHost, network });
    throw new Error(
      `Sorry, the Torus Network that powers Web3Auth is currently very busy.
    We will generate your key in time. Pls try again later. \n
    ${error.message || ""}`
    );
  }
};

export const getKeyAssignEventKey = (instanceId: string) => {
  return `ks:${instanceId}`;
};

const sleep = async (seconds: number) => {
  return new Promise((resolve) => {
    setTimeout(async () => {
      return resolve(true);
    }, seconds * 1000);
  });
};

const emitKeyAssignEvent = (key: string, data: KeyAssignQueueResponse, emitter: SafeEventEmitter) => {
  if (emitter?.emit) {
    const finalData: KeyAssignStatus = {
      processingTime: data.processingTime,
      status: data.status,
    };
    emitter.emit(key, finalData);
  }
};

const checkKeyAssignStatus = async (params: {
  keyAssignQueueHost: string;
  verifier: string;
  verifierId: string;
  network: string;
  retryInterval: number; // in seconds
  retries: number;
  instanceId: string;
  keyAssignListener: SafeEventEmitter;
}) => {
  const { verifier, verifierId, network, retries, retryInterval, keyAssignQueueHost, keyAssignListener, instanceId } = params;
  const eventKey = getKeyAssignEventKey(instanceId);

  let pendingRetries = retries;
  // eslint-disable-next-line no-console
  console.log("checking key assign status", pendingRetries);
  try {
    if (pendingRetries === 0) {
      throw new Error("Failed to do key assign, please try again");
    }
    if (pendingRetries > 0) {
      pendingRetries -= 1;
    }

    const url = new URL(`${keyAssignQueueHost}/api/keyAssignStatus`);
    url.searchParams.append("verifier", verifier);
    url.searchParams.append("verifierId", verifierId);
    url.searchParams.append("network", network);

    const keyAssignResponse = await get<KeyAssignQueueResponse>(url.href, {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
      },
    });
    // eslint-disable-next-line no-console
    console.log("keyAssignResponse", keyAssignResponse);
    if (keyAssignResponse.status === "success") {
      emitKeyAssignEvent(eventKey, keyAssignResponse, keyAssignListener);
      return;
    }
    if (keyAssignResponse.status === "failed") {
      // no need to retry if status is failed
      // hack to bypass eslint warning
      // basically setting finalRetries = 0
      pendingRetries = pendingRetries - pendingRetries;
      emitKeyAssignEvent(eventKey, { ...keyAssignResponse, processingTime: 0 }, keyAssignListener);
      throw new Error("Failed to do key assign");
    }

    // emit event if request is processing but also retry if possible in catch block
    if (keyAssignResponse.status === "processing") {
      emitKeyAssignEvent(eventKey, keyAssignResponse, keyAssignListener);
    }
    // retry till pendingRetries in case of `waiting` in catch block
    throw new Error("Failed to process your request within estimated time, please try again");
  } catch (error) {
    if (pendingRetries > 0) {
      // check key assign status after retryInterval.
      await sleep(retryInterval);
      return checkKeyAssignStatus({
        keyAssignQueueHost,
        verifier,
        verifierId,
        network,
        instanceId,
        keyAssignListener,
        retryInterval,
        retries: pendingRetries,
      });
    }
    // emit failed if request fails after all attempts
    emitKeyAssignEvent(eventKey, { status: "failed", processingTime: 0, success: false }, keyAssignListener);
    log.error("Failed to check key assign status after all retries", error);
    throw error;
  }
};

/**
 *
 * This function will emit event and returns in case of success key assign
 * and it will throw and emit event in case of failure after retries
 */
export const keyAssignWithQueue = async ({
  verifier,
  verifierId,
  keyAssignQueueHost,
  network,
  instanceId,
  keyAssignListener,
}: KeyAssignInputWithQueue): Promise<void> => {
  try {
    const keyAssignResponse = await post<KeyAssignQueueResponse>(
      `${keyAssignQueueHost}/api/keyAssign`,
      { verifier, verifierId, network },
      {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
        },
      }
    );

    const eventKey = getKeyAssignEventKey(instanceId);
    if (keyAssignResponse.status === "waiting") {
      // since shares can be fetched up to 60 seconds
      // we can wait here up to 55 seconds and give 5 second buffer for retrieveShares and keylookup apis
      // So if `processingTime` is more than 55 seconds, key assign will throw and user will have to retry login.
      if (keyAssignResponse.processingTime > 55) {
        emitKeyAssignEvent(eventKey, keyAssignResponse, keyAssignListener);
        const errMessage = `Your request is in queue, Please try after ${keyAssignResponse.processingTime} seconds`;
        throw new Error(errMessage);
      }

      const retries = 3;
      const retryInterval = 2; // 2s
      const maxWaitingTime = keyAssignResponse.processingTime + retries * retryInterval;
      emitKeyAssignEvent(
        eventKey,
        {
          ...keyAssignResponse,
          processingTime: maxWaitingTime,
        },
        keyAssignListener
      );

      const keyAssignStatusCheckTime = keyAssignResponse.processingTime * 1000;
      return await new Promise((resolve, reject) => {
        setTimeout(async () => {
          try {
            // check key assign status
            await checkKeyAssignStatus({
              keyAssignQueueHost,
              verifier,
              verifierId,
              network,
              instanceId,
              keyAssignListener,
              retries,
              retryInterval,
            });
            return resolve();
          } catch (error) {
            return reject(error);
          }
        }, keyAssignStatusCheckTime);
      });
    } else if (keyAssignResponse.status === "success") {
      emitKeyAssignEvent(eventKey, keyAssignResponse, keyAssignListener);
      return;
    } else if (keyAssignResponse.status === "failed") {
      emitKeyAssignEvent(eventKey, keyAssignResponse, keyAssignListener);
      throw new Error("Failed to do key assign");
    } else {
      throw new Error(`Unknown error, unknown keyAssign status: ${keyAssignResponse.status}`);
    }
  } catch (error) {
    log.error(error);
    throw new Error(
      `Sorry, the Torus Network that powers Web3Auth is currently very busy.
    We will generate your key in time. Pls try again later. \n
    ${error.message || ""}`
    );
  }
};

export function keccak256(a: string | Buffer): string {
  const hash = createKeccakHash("keccak256").update(a).digest().toString("hex");
  return `0x${hash}`;
}
