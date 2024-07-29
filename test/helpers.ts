import { INodePub } from "@toruslabs/constants";
import { generateJsonRPCObject, post } from "@toruslabs/http-helpers";
import dotenv from "dotenv";
import jwt, { Algorithm } from "jsonwebtoken";

import { ImportKeyParams, JRPCResponse, RetrieveSharesParams, VerifierParams } from "../src";
import { config } from "../src/config";
import { TorusUtilsExtraParams } from "../src/TorusUtilsExtraParams";

dotenv.config({ path: `.env.${process.env.NODE_ENV}` });
const jwtPrivateKey = `-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCD7oLrcKae+jVZPGx52Cb/lKhdKxpXjl9eGNa1MlY57A==\n-----END PRIVATE KEY-----`;
export const generateIdToken = (email: string, alg: Algorithm) => {
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "torus-key-test",
    aud: "torus-key-test",
    name: email,
    email,
    scope: "email",
    iat,
    eat: iat + 120,
  };

  const algo = {
    expiresIn: 120,
    algorithm: alg,
  };

  return jwt.sign(payload, jwtPrivateKey, algo);
};

interface KeyLookupResponse {
  verifiers: Record<string, string[]>;
}

export const lookupVerifier = (endpoint: string, pubKeyX: string, pubKeyY: string) => {
  return post<JRPCResponse<KeyLookupResponse>>(
    endpoint,
    generateJsonRPCObject("KeyLookupRequest", {
      pub_key_x: pubKeyX,
      pub_key_y: pubKeyY,
    }),
    {},
    { logTracingHeader: config.logRequestTracing }
  );
};

export const getRetrieveSharesParams = (
  endpoints: string[],
  indexes: number[],
  verifier: string,
  verifierParams: VerifierParams,
  idToken: string,
  nodePubkeys: INodePub[],
  extraParams: TorusUtilsExtraParams = {},
  useDkg?: boolean
): RetrieveSharesParams => {
  return {
    endpoints,
    indexes,
    verifier,
    verifierParams,
    idToken,
    nodePubkeys,
    extraParams,
    useDkg,
  };
};

export const getImportKeyParams = (
  endpoints: string[],
  nodeIndexes: number[],
  nodePubkeys: INodePub[],
  verifier: string,
  verifierParams: VerifierParams,
  idToken: string,
  newPrivateKey: string,
  extraParams: TorusUtilsExtraParams = {}
): ImportKeyParams => {
  return {
    endpoints,
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierParams,
    idToken,
    newPrivateKey,
    extraParams,
  };
};
