import dotenv from "dotenv";
import jwt, { Algorithm } from "jsonwebtoken";
import { keccak256 } from "web3-utils";

dotenv.config({ path: `.env.${process.env.NODE_ENV}` });

const jwtPrivateKey =   `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAUkXYLzqygitCTW0o5T8l4S/PFOjYx4wGGoBn62E2r6Q==
-----END PRIVATE KEY-----`;

export function randomEmail() {
  return keccak256(Math.random().toString()).slice(2, 20) + "@tor.us";
}

export const generateIdToken = (email: string, alg: Algorithm) => {
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "https://lentan.auth0.com/",
    aud: "LPDUGgSqNP5mSxllGP0TEgJwRrNU0lVH",
    name: email,
    email,
    scope: "email",
    iat,
    eat: iat + 120,
    sub: "email|5ea6a520580a1d9af4183048"
  };

  const algo = {
    expiresIn: 120,
    algorithm: alg,
  };

  return jwt.sign(payload, jwtPrivateKey, algo);
};