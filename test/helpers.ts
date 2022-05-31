import dotenv from "dotenv";
import jwt, { Algorithm } from "jsonwebtoken";
import { keccak256 } from "web3-utils";

dotenv.config({ path: `.env.${process.env.NODE_ENV}` });

const jwtPrivateKey =   `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDfRoQkC62DPWgqUocA
ZdtVkrhpoFEwTCD3f94hZPc/LA==
-----END PRIVATE KEY-----`;

export function randomEmail() {
  return keccak256(Math.random().toString()).slice(2, 20) + "@tor.us";
}

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