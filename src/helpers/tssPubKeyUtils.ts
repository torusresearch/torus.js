// Note: Endpoints should be the sss node endpoints along with path
import { JRPCResponse, KEY_TYPE } from "@toruslabs/constants";
import { generateJsonRPCObject, post } from "@toruslabs/http-helpers";
import log from "loglevel";

import { JRPC_METHODS } from "../constants";
import { GetORSetKeyResponse, KeyType } from "../interfaces";
import { Some } from "../some";
import { normalizeKeysResult, thresholdSame } from "./common";

// for ex: [https://node-1.node.web3auth.io/sss/jrpc, https://node-2.node.web3auth.io/sss/jrpc ....]
export const GetOrSetTssDKGPubKey = async (params: {
  endpoints: string[];
  verifier: string;
  verifierId: string;
  tssVerifierId: string;
  keyType?: KeyType;
}): Promise<{
  key: {
    pubKeyX: string;
    pubKeyY: string;
    address: string;
    createdAt?: number;
  };
  isNewKey: boolean;
  nodeIndexes: number[];
}> => {
  const { endpoints, verifier, verifierId, tssVerifierId, keyType = KEY_TYPE.SECP256K1 } = params;
  const minThreshold = ~~(endpoints.length / 2) + 1;
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<GetORSetKeyResponse>>(
      x,
      generateJsonRPCObject(JRPC_METHODS.GET_OR_SET_KEY, {
        distributed_metadata: true,
        verifier,
        verifier_id: verifierId,
        extended_verifier_id: tssVerifierId,
        one_key_flow: true,
        key_type: keyType,
        fetch_node_index: true,
        client_time: Math.floor(Date.now() / 1000).toString(),
      }),
      {},
      {
        logTracingHeader: false,
      }
    ).catch((err) => log.error(`${JRPC_METHODS.GET_OR_SET_KEY} request failed`, err))
  );

  const nodeIndexes: number[] = [];
  const result = await Some<
    void | JRPCResponse<GetORSetKeyResponse>,
    {
      keyResult: Pick<GetORSetKeyResponse, "keys" | "is_new_key">;
      nodeIndexes: number[];
      errorResult: JRPCResponse<GetORSetKeyResponse>["error"];
    }
  >(lookupPromises, async (lookupResults) => {
    const lookupPubKeys = lookupResults.filter((x1) => {
      if (x1 && !x1.error) {
        return x1;
      }
      return false;
    });

    const errorResult = thresholdSame(
      lookupResults.map((x2) => x2 && x2.error),
      minThreshold
    );

    const keyResult = thresholdSame(
      lookupPubKeys.map((x3) => x3 && normalizeKeysResult(x3.result)),
      minThreshold
    );

    if (keyResult || errorResult) {
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
          }
        });
      }

      return Promise.resolve({ keyResult, nodeIndexes, errorResult });
    }
    return Promise.reject(new Error(`invalid public key result: ${JSON.stringify(lookupResults)} for tssVerifierId: ${tssVerifierId} `));
  });

  if (result.errorResult) {
    throw new Error(`invalid public key result,errorResult: ${JSON.stringify(result.errorResult)}`);
  }

  const key = result.keyResult.keys[0];
  return {
    key: {
      pubKeyX: key.pub_key_X,
      pubKeyY: key.pub_key_Y,
      address: key.address,
      createdAt: key.created_at,
    },
    nodeIndexes: result.nodeIndexes,
    isNewKey: result.keyResult.is_new_key,
  };
};
